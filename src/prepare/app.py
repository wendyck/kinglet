"""Prepare Lambda (SPEC.md §5.2).

Turns a PR into two artifacts:

- `bundles/<exec>.tar.gz` — what the reviewer may read. Repo tree at the pinned
  SHA, untrusted PR-derived text, and a task list. It carries **no floor and no
  guardrail flags**, so a compromised reviewer cannot see what score it is
  expected to beat.
- `meta/<exec>.json` — Tier 1 only. The floor, its reasons, the file index used
  to validate evidence, and the guardrail findings. The reviewer's task role has
  no access to this prefix.

Prepare holds a GitHub token. The reviewer never does. Everything after this
Lambda runs against files.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tarfile
import tempfile
import urllib.request
from pathlib import Path

import boto3

from common import github_app as gh
from common import release_notes
from common.dependabot import normalize, parse_pr
from common.risk_floor import overall_floor, package_floor
from common.safe_tar import UnsafeArchive, safe_extract

log = logging.getLogger()
log.setLevel(logging.INFO)

BUCKET = os.environ.get("KINGLET_BUCKET", "")
GUARDRAIL_ID = os.environ.get("KINGLET_GUARDRAIL_ID", "")
GUARDRAIL_VERSION = os.environ.get("KINGLET_GUARDRAIL_VERSION", "1")
CONFIG_PATH = os.environ.get("KINGLET_CONFIG", "config/repos.yml")

# §5.2 step 3. Anything outside this set means the PR is doing more than a
# dependency bump, which is UNEXPECTED_CHANGE and a high floor.
MANIFEST_ALLOWLIST = [
    re.compile(r"(^|/)requirements[^/]*\.txt$"),
    re.compile(r"(^|/)pyproject\.toml$"),
    re.compile(r"(^|/)poetry\.lock$"),
    re.compile(r"(^|/)[^/]*\.lock$"),
    re.compile(r"^\.github/workflows/[^/]+\.ya?ml$"),
    re.compile(r"(^|/)Dockerfile[^/]*$"),
]

MAX_LINE_INDEX_FILES = 20_000
MAX_PR_BODY_BYTES = 100_000


def allowed_change(filename: str) -> bool:
    return any(p.search(filename) for p in MANIFEST_ALLOWLIST)


def load_config(path: str | None = None) -> dict:
    import yaml
    with open(path or CONFIG_PATH) as fh:
        return yaml.safe_load(fh) or {}


# ── guardrail (§5.2 step 7) ──────────────────────────────────────────────────


def apply_guardrail(text: str, source: str = "INPUT") -> tuple[bool, list[str]]:
    """Returns (intervened, matched check names).

    A hit does **not** withhold the file. §5.2 is explicit: the reviewer should
    still see the text as data, because judging hostile release notes is part of
    the job. The hit raises the floor instead.
    """
    if not GUARDRAIL_ID or not text.strip():
        return False, []
    try:
        client = boto3.client("bedrock-runtime")
        resp = client.apply_guardrail(
            guardrailIdentifier=GUARDRAIL_ID,
            guardrailVersion=GUARDRAIL_VERSION,
            source=source,
            content=[{"text": {"text": text[:100_000]}}],
        )
    except Exception as e:
        # A guardrail outage must not silently downgrade the floor.
        log.error("ApplyGuardrail failed: %s", e)
        return True, ["GUARDRAIL_UNAVAILABLE"]

    if resp.get("action") != "GUARDRAIL_INTERVENED":
        return False, []
    matched: list[str] = []
    for assessment in resp.get("assessments", []):
        matched += [t["name"] for t in assessment.get("topicPolicy", {}).get("topics", [])]
        matched += [f["type"] for f in assessment.get("contentPolicy", {}).get("filters", [])]
    return True, sorted(set(matched))


# ── the bundle ───────────────────────────────────────────────────────────────


def build_file_index(root: Path) -> dict[str, int]:
    """path -> line count, for Finalize's evidence validation (§7.2).

    Finalize rejects an `evidence` entry whose path is not here or whose line
    exceeds the count, which is how a hallucinated citation gets dropped.
    """
    index: dict[str, int] = {}
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        rel = str(p.relative_to(root))
        if rel.startswith(".git/"):
            continue
        if len(index) >= MAX_LINE_INDEX_FILES:
            break
        try:
            with p.open("rb") as fh:
                head = fh.read(2048)
                if b"\0" in head:
                    continue
                fh.seek(0)
                index[rel] = sum(1 for _ in fh)
        except OSError:
            continue
    return index


def write_bundle(work: Path, out_path: Path) -> None:
    with tarfile.open(out_path, "w:gz") as tf:
        for p in sorted(work.rglob("*")):
            tf.add(p, arcname=str(p.relative_to(work)), recursive=False)


# ── the handler ──────────────────────────────────────────────────────────────


def handler(event, context):  # noqa: ARG001
    repo = event["repo"]
    number = int(event["pr"])
    pinned_sha = event["head_sha"]
    review_key = event["review_key"]
    installation_id = int(event["installation_id"])
    exec_id = event.get("execution_name") or f"{repo.replace('/', '-')}-{number}-{review_key[:12]}"

    cfg = load_config()
    repo_cfg = (cfg.get("repos") or {}).get(repo, {})

    app = gh.GitHubApp()
    token = app.installation_token(
        installation_id,
        repositories=[repo.split("/")[-1]],
        permissions={"contents": "read", "pull_requests": "read",
                     "vulnerability_alerts": "read"})

    global_reasons: list[str] = []

    # 2. Re-fetch at the pinned SHA. If it moved, the next poll picks it up.
    pr, _ = gh.request(f"/repos/{repo}/pulls/{number}", token=token)
    if pr["head"]["sha"] != pinned_sha:
        log.info("head moved %s -> %s; aborting", pinned_sha, pr["head"]["sha"])
        return {"status": "sha_moved", "repo": repo, "pr": number}

    # 3. Authenticity, again, plus per-commit authorship and the file allowlist.
    commits = gh.list_pull_commits(repo, number, token=token)
    if not commits or any((c.get("author") or {}).get("login") != "dependabot[bot]"
                          for c in commits):
        global_reasons.append("UNEXPECTED_CHANGE")

    files = gh.list_pull_files(repo, number, token=token)
    unexpected = [f["filename"] for f in files if not allowed_change(f["filename"])]
    if unexpected:
        log.warning("unexpected files in %s#%s: %s", repo, number, unexpected[:10])
        if "UNEXPECTED_CHANGE" not in global_reasons:
            global_reasons.append("UNEXPECTED_CHANGE")

    # 5. Package list, from the trailer plus the patches.
    parsed = parse_pr(commits[0]["commit"]["message"] if commits else "", files)
    global_reasons += [r for r in parsed.reasons if r not in global_reasons]

    with tempfile.TemporaryDirectory() as td:
        work = Path(td) / "bundle"
        repo_dir = work / "repo"
        untrusted = work / "untrusted" / "release_notes"
        untrusted.mkdir(parents=True)

        # 4. Tarball at the pinned SHA, safe-extracted.
        tar_url = gh.repo_tarball(repo, pinned_sha, token=token)
        tar_path = Path(td) / "repo.tar.gz"
        with urllib.request.urlopen(tar_url, timeout=120) as r, open(tar_path, "wb") as out:
            while chunk := r.read(1 << 20):
                out.write(chunk)
        try:
            extracted = safe_extract(tar_path, repo_dir)
            log.info("extracted %s files, %s bytes", extracted.files, extracted.total_bytes)
        except UnsafeArchive as e:
            log.error("unsafe archive for %s@%s: %s", repo, pinned_sha, e)
            if "UNEXPECTED_CHANGE" not in global_reasons:
                global_reasons.append("UNEXPECTED_CHANGE")
            repo_dir.mkdir(parents=True, exist_ok=True)

        # 6. Untrusted text: the PR body and per-package release notes.
        guardrail_flags: dict[str, list[str]] = {}

        body = pr.get("body") or ""
        (work / "untrusted" / "pr_body.md").write_text(body[:MAX_PR_BODY_BYTES])
        hit, matched = apply_guardrail(body)
        if hit:
            guardrail_flags["untrusted/pr_body.md"] = matched

        for u in parsed.updates:
            notes = release_notes.fetch(u.name, u.ecosystem, u.from_version, u.to_version)
            if not notes:
                continue
            fname = f"{normalize(u.name, u.ecosystem).replace('/', '__')}.md"
            (untrusted / fname).write_text(notes)
            hit, matched = apply_guardrail(notes)
            if hit:
                guardrail_flags[f"untrusted/release_notes/{fname}"] = matched

        if guardrail_flags:
            global_reasons.append("PROMPT_ATTACK_SUSPECTED")

        # 7. Security alerts (§5.7) — the only source for the banner.
        alerts = []
        try:
            alerts = gh.open_dependabot_alerts(repo, token=token)
        except gh.GitHubError as e:
            log.warning("alerts unavailable for %s: %s", repo, e)
        security = match_alerts(alerts, parsed.updates)

        # 8. The floor.
        floors = {u.key(): package_floor(u, repo_cfg) for u in parsed.updates}
        overall = overall_floor(floors, global_reasons)

        # 9. task.json — no floor, no guardrail flags (§5.2 step 9).
        task = {
            "repo": repo,
            "pr": number,
            "head_sha": pinned_sha,
            "security_fix": bool(security),
            "security_advisories": [a["ghsa_id"] for a in security],
            "packages": [
                {"name": u.name, "ecosystem": u.ecosystem, "directory": u.directory,
                 "manifest": u.manifest, "from": u.from_spec, "to": u.to_spec,
                 "from_version": u.from_version, "to_version": u.to_version,
                 "is_range": u.is_range, "group": u.group}
                for u in parsed.updates
            ],
        }
        (work / "task.json").write_text(json.dumps(task, indent=2))

        file_index = build_file_index(repo_dir)

        bundle_path = Path(td) / "bundle.tar.gz"
        write_bundle(work, bundle_path)

        s3 = boto3.client("s3")
        bundle_key = f"bundles/{exec_id}.tar.gz"
        s3.upload_file(str(bundle_path), BUCKET, bundle_key)

    # 10. meta — Tier 1 only.
    meta = {
        "repo": repo, "pr": number, "head_sha": pinned_sha, "review_key": review_key,
        "packages": [
            {"name": u.name, "ecosystem": u.ecosystem, "directory": u.directory,
             "manifest": u.manifest, "from": u.from_spec, "to": u.to_spec,
             "floor": floors[u.key()].level, "floor_reasons": floors[u.key()].reasons}
            for u in parsed.updates
        ],
        "overall_floor": overall.level,
        "global_reasons": global_reasons,
        "changed_files": [f["filename"] for f in files],
        "unexpected_files": unexpected,
        "file_index": file_index,
        "guardrail_flags": guardrail_flags,
        "security": security,
    }
    meta_key = f"meta/{exec_id}.json"
    boto3.client("s3").put_object(
        Bucket=BUCKET, Key=meta_key,
        Body=json.dumps(meta).encode(), ContentType="application/json")

    log.info("prepared %s#%s: floor=%s packages=%d", repo, number,
             overall.level, len(parsed.updates))
    return {
        "status": "ok", "repo": repo, "pr": number, "head_sha": pinned_sha,
        "review_key": review_key, "execution_name": exec_id,
        "bundle_key": bundle_key, "meta_key": meta_key,
        "result_key": f"results/{exec_id}.json",
        "installation_id": installation_id,
        "overall_floor": overall.level,
    }


def match_alerts(alerts: list[dict], updates) -> list[dict]:
    """§5.7 match rule. Never inferred from PR text.

    An alert counts when the ecosystem, normalized package name and manifest
    directory all line up, and the PR's target version reaches the first patched
    version.
    """
    from packaging.version import InvalidVersion, Version

    by_key = {}
    for u in updates:
        by_key.setdefault((u.ecosystem, normalize(u.name, u.ecosystem)), []).append(u)

    out = []
    for alert in alerts:
        dep = alert.get("dependency") or {}
        pkg = (dep.get("package") or {})
        eco = {"pip": "pip", "actions": "actions", "github-actions": "actions"}.get(
            (pkg.get("ecosystem") or "").lower())
        name = pkg.get("name") or ""
        if not eco or not name:
            continue
        candidates = by_key.get((eco, normalize(name, eco)), [])
        manifest_path = dep.get("manifest_path") or ""
        for u in candidates:
            if manifest_path and not manifest_path.startswith(u.directory.lstrip("/")) \
                    and u.directory != "/":
                continue
            vuln = alert.get("security_vulnerability") or {}
            patched = ((vuln.get("first_patched_version") or {}).get("identifier"))
            if patched and u.to_version:
                try:
                    if Version(u.to_version) < Version(patched):
                        continue
                except InvalidVersion:
                    pass
            advisory = alert.get("security_advisory") or {}
            out.append({
                "ghsa_id": advisory.get("ghsa_id", ""),
                "severity": advisory.get("severity", "unknown"),
                "summary": advisory.get("summary", ""),
                "package": u.name,
                "directory": u.directory,
            })
            break
    return out
