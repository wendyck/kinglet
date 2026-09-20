#!/usr/bin/env python3
"""Replay a real PR through the reviewer locally (SPEC.md §12, Phase 2).

Builds a bundle from a snapshotted fixture, runs the reviewer container against
it, and puts the result through the same §7.2 validation Finalize uses — then
renders the comment that would have been posted.

Nothing is written to GitHub and nothing touches the deployed stack. This is the
loop for iterating on the skill and the prompt: a full round trip costs one
Bedrock call and about a minute, instead of a deploy plus a Step Functions run.

    AWS_PROFILE=kinglet python3 scripts/replay.py csa-wrangler-pr29
    AWS_PROFILE=kinglet python3 scripts/replay.py --all --no-model

`--no-model` skips the container and echoes the floor, which exercises
everything except the model itself and needs no Bedrock access at all.

**Where `repo/` comes from.** The same place Prepare gets it: the GitHub
tarball at the PR's pinned `head_sha`, safe-extracted through `safe_tar`. That
is what makes a replay's verdict mean something — the model can grep the real
source for imports, so `usage` and `verdict` are answerable rather than
`UNKNOWN`. Tarballs are cached under `tests/fixtures/real/.tarballs/`, so the
first replay of a fixture hits the network and the rest do not.

Two overrides, in priority order: a directory at
`tests/fixtures/real/<fixture>-tree/` is used as the tree if it exists, and
`--no-tree` falls back to reconstructing just the changed manifests from the
snapshot's patches. Under `--no-tree` the model has no source to grep, so
verdicts come back `UNKNOWN` or a spurious `DEAD` and only the *plumbing* is
proven: the package set matches, the schema holds, evidence validation and
`max(floor, model)` behave, the comment renders.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import yaml  # noqa: E402

from common.dependabot import normalize, parse_pr  # noqa: E402
from common.render import Advisory, Row, render_comment  # noqa: E402
from common.risk_floor import overall_floor, package_floor  # noqa: E402
from common.safe_tar import UnsafeArchive, safe_extract  # noqa: E402
from common.validate import (  # noqa: E402
    ResultRejected, cross_check, floor_reason_summary, validate_schema,
)
from prepare.app import build_file_index  # noqa: E402

# The reviewer's own extractor, not a second copy of it. Both earlier copies
# drifted: this harness used a greedy `\{.*\}` span, which starts at the first
# brace in the reply — often one quoted inside the release notes — and so failed
# to parse a perfectly good result object. One tested implementation, the same
# reasoning as safe_tar.
sys.path.insert(0, str(ROOT / "src" / "common"))  # entrypoint imports it flat
sys.path.insert(0, str(ROOT / "reviewer"))
from entrypoint import agent_reply_text, extract_json  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "real"
TARBALLS = FIXTURES / ".tarballs"
IMAGE = "kinglet-reviewer:dev"
MODEL = "amazon-bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0"


def _token() -> str | None:
    """A GitHub token, if one is lying around.

    The enrolled repos are public, so anonymous works — it just spends the
    60/hour anonymous rate limit, and a cache miss on every fixture is eight
    requests. A token is used when available and never required.
    """
    if os.environ.get("GITHUB_TOKEN"):
        return os.environ["GITHUB_TOKEN"]
    p = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
    return p.stdout.strip() or None if p.returncode == 0 else None


def fetch_tarball(repo: str, sha: str) -> Path | None:
    """The repo tarball at `sha`, cached. None if it cannot be fetched.

    Cached by SHA, which is immutable, so the cache never needs invalidating.
    """
    TARBALLS.mkdir(parents=True, exist_ok=True)
    cached = TARBALLS / f"{repo.replace('/', '-')}-{sha}.tar.gz"
    if cached.is_file():
        return cached

    headers = {"User-Agent": "kinglet-replay",
               "X-GitHub-Api-Version": "2022-11-28"}
    token = _token()
    if token:
        headers["Authorization"] = f"token {token}"
    url = f"https://api.github.com/repos/{repo}/tarball/{sha}"
    tmp = cached.with_suffix(".partial")

    # A token scoped to a different repository is rejected outright, which is
    # worse than sending none at all: these repos are public. CI hits exactly
    # this — its GITHUB_TOKEN belongs to kinglet, and the fixtures live in
    # csa-wrangler and calendar-digest.
    attempts = [headers] + ([{k: v for k, v in headers.items()
                              if k != "Authorization"}] if token else [])
    for n, hdrs in enumerate(attempts):
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(url, headers=hdrs), timeout=120) as r, \
                    open(tmp, "wb") as out:
                while chunk := r.read(1 << 20):
                    out.write(chunk)
            break
        except (urllib.error.URLError, OSError) as e:
            tmp.unlink(missing_ok=True)
            if n + 1 < len(attempts):
                print(f"  tarball fetch with a token failed ({e}); retrying anonymously")
                continue
            print(f"  tarball fetch failed for {repo}@{sha[:8]}: {e}")
            return None
    tmp.rename(cached)
    print(f"  fetched tarball {repo}@{sha[:8]} ({cached.stat().st_size // 1024} KiB)")
    return cached


def populate_repo(fixture: dict, repo_dir: Path, *, use_tree: bool) -> str:
    """Fill `repo/`. Returns which source was used, for the log line.

    Priority: a recorded tree beside the fixture, then the real tarball at
    `head_sha`, then the snapshot's patches. The last is a fallback, not a
    peer — see the module docstring.
    """
    repo_dir.mkdir(parents=True, exist_ok=True)

    recorded = FIXTURES / f"{Path(fixture['_name']).stem}-tree"
    if recorded.is_dir():
        shutil.copytree(recorded, repo_dir, dirs_exist_ok=True)
        return f"recorded tree ({recorded.name})"

    if use_tree:
        tar = fetch_tarball(fixture["repo"], fixture["head"]["sha"])
        if tar is not None:
            try:
                extracted = safe_extract(tar, repo_dir)
                return f"tarball at {fixture['head']['sha'][:8]} ({extracted.files} files)"
            except UnsafeArchive as e:
                print(f"  unsafe archive, falling back to patches: {e}")

    for f in fixture["changed_files"]:
        path = repo_dir / f["filename"]
        path.parent.mkdir(parents=True, exist_ok=True)
        added = [l[1:] for l in (f.get("patch") or "").splitlines()
                 if l.startswith("+") and not l.startswith("+++")]
        path.write_text("\n".join(added) + "\n")
    return "patches only — verdicts are not meaningful"


def build_bundle(fixture: dict, work: Path, *, use_tree: bool = True) -> tuple[dict, dict]:
    """Recreate what Prepare would have written, from the snapshot.

    Release notes are not fetched — a replay should be reproducible and offline
    where possible. If a fixture has recorded notes beside it they are used.
    """
    cfg = yaml.safe_load((ROOT / "config" / "repos.yml").read_text())
    repo_cfg = (cfg.get("repos") or {}).get(fixture["repo"], {})

    parsed = parse_pr(fixture["commits"][0]["message"], fixture["changed_files"])
    floors = {u.key(): package_floor(u, repo_cfg) for u in parsed.updates}
    overall = overall_floor(floors, parsed.reasons)

    (work / "untrusted" / "release_notes").mkdir(parents=True, exist_ok=True)
    (work / "untrusted" / "pr_body.md").write_text(fixture["pr"].get("body") or "")

    source = populate_repo(fixture, work / "repo", use_tree=use_tree)
    print(f"  repo:     {source}")

    # The same index Prepare builds, because it is what bounds evidence (§7.2).
    file_index = build_file_index(work / "repo")

    for u in parsed.updates:
        notes = FIXTURES / f"notes-{normalize(u.name, u.ecosystem).replace('/', '__')}.md"
        if notes.is_file():
            (work / "untrusted" / "release_notes" /
             f"{normalize(u.name, u.ecosystem).replace('/', '__')}.md").write_text(notes.read_text())

    task = {
        "repo": fixture["repo"], "pr": fixture["pr"]["number"],
        "head_sha": fixture["head"]["sha"], "security_fix": False,
        "security_advisories": [],
        "packages": [
            {"name": u.name, "ecosystem": u.ecosystem, "directory": u.directory,
             "manifest": u.manifest, "from": u.from_spec, "to": u.to_spec,
             "from_version": u.from_version, "to_version": u.to_version,
             "is_range": u.is_range, "group": u.group}
            for u in parsed.updates],
    }
    (work / "task.json").write_text(json.dumps(task, indent=2))

    meta = {
        "repo": fixture["repo"], "pr": fixture["pr"]["number"],
        "head_sha": fixture["head"]["sha"], "review_key": "replay",
        "packages": [
            {"name": u.name, "ecosystem": u.ecosystem, "directory": u.directory,
             "manifest": u.manifest, "from": u.from_spec, "to": u.to_spec,
             "floor": floors[u.key()].level,
             "floor_reasons": floors[u.key()].reasons}
            for u in parsed.updates],
        "overall_floor": overall.level,
        "global_reasons": parsed.reasons,
        "changed_files": [f["filename"] for f in fixture["changed_files"]],
        "unexpected_files": [], "file_index": file_index,
        "guardrail_flags": {}, "security": [],
    }
    return task, meta


class NoCredentials(Exception):
    """The container would have run without Bedrock access."""


def aws_env() -> list[str]:
    """The credentials the container needs, as `-e KEY=VALUE` pairs.

    Raises rather than returning nothing. Without these the container starts,
    the agent burns its retries on "Could not load credentials from any
    providers", and the failure surfaces as an empty reply — a run that did not
    happen, reported as a run that failed.
    """
    p = subprocess.run(["aws", "configure", "export-credentials",
                        "--format", "env-no-export"],
                       capture_output=True, text=True)
    pairs = [l.strip() for l in p.stdout.splitlines()
             if "=" in l and l.split("=", 1)[1].strip()]
    if not pairs:
        profile = os.environ.get("AWS_PROFILE", "kinglet")
        raise NoCredentials(
            f"no AWS credentials for profile {profile!r}"
            + (f": {p.stderr.strip()}" if p.stderr.strip() else "")
            + f"\n  try: aws sso login --profile {profile}")
    return [arg for pair in pairs for arg in ("-e", pair)]


def run_container(work: Path, config: Path) -> dict | None:
    cmd = [
        "docker", "run", "--rm", "--platform=linux/arm64",
        *aws_env(),
        "-e", "AWS_REGION=us-west-2",
        "-e", f"OPENCLAW_CONFIG_PATH=/cfg/{config.name}",
        "-v", f"{config.parent}:/cfg:ro", "-v", f"{work}:/work:ro",
        "--entrypoint", "sh", IMAGE, "-c",
        f"openclaw agent exec --config /cfg/{config.name} --state-dir /state "
        f"--message-file /opt/kinglet/prompt.md --model {MODEL} "
        f"--timeout 500 --json 2>/dev/null",
    ]

    p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    try:
        envelope = json.loads(p.stdout)
    except json.JSONDecodeError:
        print(f"  container produced no envelope: {p.stdout[-400:]}{p.stderr[-400:]}")
        return None
    if envelope.get("error"):
        err = envelope["error"]
        print(f"  the agent did not complete: {err.get('message')} "
              f"({err.get('kind')}) — this is a harness failure, not a verdict")
        return None
    result = extract_json(agent_reply_text(p.stdout))
    if result is None:
        print(f"  no JSON object in the reply: {(envelope.get('final') or '')[-300:]}")
    return result


def floor_only_result(meta: dict) -> dict:
    return {
        "schema_version": 1, "overall_risk": meta["overall_floor"],
        "packages": [{"name": p["name"], "directory": p["directory"],
                      "risk": p["floor"], "verdict": "UNKNOWN", "usage": "unknown",
                      "reason_codes": [], "evidence": []}
                     for p in meta["packages"]],
        "notes": "Floor-only replay (--no-model).",
    }


def replay(name: str, *, use_model: bool, show_comment: bool,
           use_tree: bool = True) -> bool:
    path = FIXTURES / (name if name.endswith(".json") else f"{name}.json")
    fixture = json.loads(path.read_text())
    fixture["_name"] = path.name
    print(f"\n=== {path.stem} — {fixture['pr']['title'][:70]} ===")

    with tempfile.TemporaryDirectory() as td:
        work = Path(td) / "bundle"
        work.mkdir()
        task, meta = build_bundle(fixture, work, use_tree=use_tree)
        print(f"  packages: {[p['name'] for p in task['packages']]}")
        print(f"  floor:    {meta['overall_floor']}")

        if use_model:
            cfg = Path(td) / "oc.json"
            cfg.write_text((ROOT / "reviewer" / "openclaw" / "openclaw.json").read_text())
            cfg.chmod(0o600)
            try:
                result = run_container(work, cfg)
            except NoCredentials as e:
                print(f"  {e}")
                return False
            if result is None:
                return False
        else:
            result = floor_only_result(meta)

    try:
        validate_schema(result)
        validated = cross_check(result, meta)
    except ResultRejected as e:
        print(f"  REJECTED: {e}")
        return False

    print(f"  model:    {result['overall_risk']}  ->  final {validated.overall_risk}")
    for p in validated.packages:
        print(f"    {p.name}@{p.directory}: {p.risk} {p.verdict} "
              f"({p.usage}) evidence={len(p.evidence)}"
              + (f" dropped={len(p.dropped_evidence)}" if p.dropped_evidence else ""))
    for w in validated.warnings:
        print(f"    warning: {w}")

    if show_comment:
        rows = [Row(name=p.name, directory=p.directory,
                    change=f"{m.get('from')} → {m.get('to')}", risk=p.risk,
                    verdict=p.verdict, reason_codes=p.reason_codes,
                    evidence=p.evidence)
                for p in validated.packages
                for m in [next(x for x in meta["packages"]
                               if (x["name"], x["directory"]) == (p.name, p.directory))]]
        print("\n" + render_comment(
            review_key="replay", sha=fixture["head"]["sha"],
            overall_risk=validated.overall_risk, rows=rows,
            floor_reasons=floor_reason_summary(meta),
            advisories=[Advisory(a["ghsa_id"], a["severity"], a["summary"])
                        for a in meta["security"]],
            notes=validated.notes, now=datetime.now(timezone.utc)))
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("fixture", nargs="?", help="fixture stem, e.g. csa-wrangler-pr29")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--no-model", action="store_true",
                    help="skip the container and echo the floor")
    ap.add_argument("--no-tree", action="store_true",
                    help="rebuild repo/ from the snapshot's patches instead of "
                         "fetching the tarball; plumbing only")
    ap.add_argument("--comment", action="store_true", help="print the rendered comment")
    args = ap.parse_args()

    names = ([f.stem for f in sorted(FIXTURES.glob("*-pr*.json"))]
             if args.all else [args.fixture])
    if not names or names == [None]:
        ap.error("give a fixture name or --all")

    failed = [n for n in names
              if not replay(n, use_model=not args.no_model,
                            show_comment=args.comment, use_tree=not args.no_tree)]
    print(f"\n{len(names) - len(failed)}/{len(names)} replayed cleanly")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
