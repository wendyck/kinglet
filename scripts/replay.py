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

**What a replay does and does not prove.** The bundle is rebuilt from the
snapshot, and a snapshot holds the PR's patches — not the repository. So
`repo/` contains the changed manifests and nothing else, and the model has no
source to grep. Verdicts from a replay are therefore meaningless: everything
comes back `UNKNOWN`, or `DEAD` when the model correctly observes that a package
it cannot see is not imported.

A replay validates the *plumbing* — the package set matches, the schema holds,
evidence validation and `max(floor, model)` behave, the comment renders. It does
not validate the skill. For that, run the real pipeline, or drop a tree into
`tests/fixtures/real/<fixture>-tree/` and it will be copied into `repo/`.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import yaml  # noqa: E402

from common.dependabot import normalize, parse_pr  # noqa: E402
from common.render import Advisory, Row, render_comment  # noqa: E402
from common.risk_floor import overall_floor, package_floor  # noqa: E402
from common.validate import (  # noqa: E402
    ResultRejected, cross_check, floor_reason_summary, validate_schema,
)

FIXTURES = ROOT / "tests" / "fixtures" / "real"
IMAGE = "kinglet-reviewer:dev"
MODEL = "amazon-bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0"


def build_bundle(fixture: dict, work: Path) -> tuple[dict, dict]:
    """Recreate what Prepare would have written, from the snapshot.

    Release notes are not fetched — a replay should be reproducible and offline
    where possible. If a fixture has recorded notes beside it they are used.
    """
    cfg = yaml.safe_load((ROOT / "config" / "repos.yml").read_text())
    repo_cfg = (cfg.get("repos") or {}).get(fixture["repo"], {})

    parsed = parse_pr(fixture["commits"][0]["message"], fixture["changed_files"])
    floors = {u.key(): package_floor(u, repo_cfg) for u in parsed.updates}
    overall = overall_floor(floors, parsed.reasons)

    (work / "repo").mkdir(parents=True, exist_ok=True)
    (work / "untrusted" / "release_notes").mkdir(parents=True, exist_ok=True)
    (work / "untrusted" / "pr_body.md").write_text(fixture["pr"].get("body") or "")

    # Reconstruct just enough of the tree for usage checks: the manifests the PR
    # touched, plus any recorded source files.
    file_index: dict[str, int] = {}
    for f in fixture["changed_files"]:
        path = work / "repo" / f["filename"]
        path.parent.mkdir(parents=True, exist_ok=True)
        added = [l[1:] for l in (f.get("patch") or "").splitlines()
                 if l.startswith("+") and not l.startswith("+++")]
        path.write_text("\n".join(added) + "\n")
        file_index[f["filename"]] = len(added)

    extra = FIXTURES / f"{Path(fixture['_name']).stem}-tree"
    if extra.is_dir():
        for src in extra.rglob("*"):
            if src.is_file():
                rel = src.relative_to(extra)
                dst = work / "repo" / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(src.read_text())
                file_index[str(rel)] = len(src.read_text().splitlines())

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


def run_container(work: Path, config: Path) -> dict | None:
    cmd = [
        "docker", "run", "--rm", "--platform=linux/arm64",
        "-e", "AWS_REGION=us-west-2",
        "-e", f"OPENCLAW_CONFIG_PATH=/cfg/{config.name}",
        "-v", f"{config.parent}:/cfg:ro", "-v", f"{work}:/work:ro",
        "--entrypoint", "sh", IMAGE, "-c",
        f"openclaw agent exec --config /cfg/{config.name} --state-dir /state "
        f"--message-file /opt/kinglet/prompt.md --model {MODEL} "
        f"--timeout 500 --json 2>/dev/null",
    ]
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        creds = subprocess.run(["aws", "configure", "export-credentials",
                                "--format", "env-no-export"],
                               capture_output=True, text=True).stdout
        break
    for line in creds.splitlines():
        if "=" in line:
            cmd[3:3] = ["-e", line.strip()]

    p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    try:
        envelope = json.loads(p.stdout)
    except json.JSONDecodeError:
        print(f"  container produced no envelope: {p.stdout[-400:]}{p.stderr[-400:]}")
        return None
    final = envelope.get("final") or ""
    import re
    for block in re.findall(r"```(?:json)?\s*(.+?)```", final, re.S) + [final]:
        try:
            obj = json.loads(block.strip())
            if isinstance(obj, dict) and "packages" in obj:
                return obj
        except json.JSONDecodeError:
            continue
    print(f"  no JSON object in the reply: {final[-300:]}")
    return None


def floor_only_result(meta: dict) -> dict:
    return {
        "schema_version": 1, "overall_risk": meta["overall_floor"],
        "packages": [{"name": p["name"], "directory": p["directory"],
                      "risk": p["floor"], "verdict": "UNKNOWN", "usage": "unknown",
                      "reason_codes": [], "evidence": []}
                     for p in meta["packages"]],
        "notes": "Floor-only replay (--no-model).",
    }


def replay(name: str, *, use_model: bool, show_comment: bool) -> bool:
    path = FIXTURES / (name if name.endswith(".json") else f"{name}.json")
    fixture = json.loads(path.read_text())
    fixture["_name"] = path.name
    print(f"\n=== {path.stem} — {fixture['pr']['title'][:70]} ===")

    with tempfile.TemporaryDirectory() as td:
        work = Path(td) / "bundle"
        work.mkdir()
        task, meta = build_bundle(fixture, work)
        print(f"  packages: {[p['name'] for p in task['packages']]}")
        print(f"  floor:    {meta['overall_floor']}")

        if use_model:
            cfg = Path(td) / "oc.json"
            cfg.write_text((ROOT / "reviewer" / "openclaw" / "openclaw.json").read_text())
            cfg.chmod(0o600)
            result = run_container(work, cfg)
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
    ap.add_argument("--comment", action="store_true", help="print the rendered comment")
    args = ap.parse_args()

    names = ([f.stem for f in sorted(FIXTURES.glob("*-pr*.json"))]
             if args.all else [args.fixture])
    if not names or names == [None]:
        ap.error("give a fixture name or --all")

    failed = [n for n in names
              if not replay(n, use_model=not args.no_model, show_comment=args.comment)]
    print(f"\n{len(names) - len(failed)}/{len(names)} replayed cleanly")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
