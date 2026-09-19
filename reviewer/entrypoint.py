#!/usr/bin/env python3
"""Reviewer task entrypoint (SPEC.md §5.3).

A small deterministic script, not an LLM. It fetches the bundle, makes it
read-only, runs exactly one isolated agent turn, extracts the final JSON object,
and writes the result to S3.

It holds no GitHub credentials and never talks to GitHub. Its only AWS access is
the task role: read one bundle, write one result, invoke one Bedrock profile.

Exit codes: 0 on success, non-zero on any failure, which trips the Step Functions
Catch and sends the PR to the §5.8 failure path.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import boto3

WORK = Path(os.environ.get("KINGLET_WORK", "/work"))
STATE = Path(os.environ.get("OPENCLAW_STATE_DIR", "/state"))
CONFIG = Path(os.environ.get("OPENCLAW_CONFIG_PATH", "/opt/kinglet/openclaw/openclaw.json"))
PROMPT = Path(os.environ.get("KINGLET_PROMPT", "/opt/kinglet/prompt.md"))

AGENT_TIMEOUT_S = int(os.environ.get("KINGLET_AGENT_TIMEOUT", "540"))

# Safe-extraction caps (§5.2 step 4 applies the same limits on the way in; we
# re-apply them here because Tier 2 must not trust its own input either).
MAX_BUNDLE_BYTES = 50 * 1024 * 1024
MAX_BUNDLE_FILES = 20_000


def log(msg: str) -> None:
    print(f"[kinglet-reviewer] {msg}", flush=True)


def fail(msg: str) -> "NoReturn":  # type: ignore[valid-type]
    print(f"[kinglet-reviewer] FATAL: {msg}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        fail(f"required environment variable {name} is not set")
    return v


# ── bundle ───────────────────────────────────────────────────────────────────


def safe_extract(tar_path: Path, dest: Path) -> None:
    """Extract with the §4 malicious-tarball controls: no links, no absolute
    paths, no traversal, and hard caps on size and file count."""
    dest_real = dest.resolve()
    total = 0
    count = 0
    with tarfile.open(tar_path, "r:gz") as tf:
        for member in tf:
            count += 1
            if count > MAX_BUNDLE_FILES:
                fail(f"bundle exceeds {MAX_BUNDLE_FILES} files")
            if member.islnk() or member.issym():
                fail(f"bundle contains a link: {member.name}")
            if not member.isfile() and not member.isdir():
                fail(f"bundle contains a special file: {member.name}")
            if member.name.startswith("/") or ".." in Path(member.name).parts:
                fail(f"unsafe path in bundle: {member.name}")
            target = (dest_real / member.name).resolve()
            if target != dest_real and dest_real not in target.parents:
                fail(f"path escapes destination: {member.name}")
            total += member.size
            if total > MAX_BUNDLE_BYTES:
                fail(f"bundle exceeds {MAX_BUNDLE_BYTES} bytes uncompressed")
            tf.extract(member, dest_real, filter="data")


def fetch_bundle(bucket: str, key: str) -> None:
    log(f"fetching s3://{bucket}/{key}")
    WORK.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", dir="/tmp", delete=True) as tmp:
        boto3.client("s3").download_fileobj(bucket, key, tmp)
        tmp.flush()
        safe_extract(Path(tmp.name), WORK)
    log(f"extracted to {WORK}")


def freeze_work() -> None:
    """Make the bundle read-only (§5.3 step 1).

    openclaw state lives on a separate tmpfs at /state precisely so this does not
    break it (spike F15).
    """
    for p in sorted(WORK.rglob("*"), reverse=True):
        try:
            p.chmod(0o500 if p.is_dir() else 0o400)
        except OSError:
            pass
    WORK.chmod(0o500)
    log(f"{WORK} is now read-only")


# ── agent ────────────────────────────────────────────────────────────────────

JSON_BLOCK = re.compile(r"\{.*\}", re.S)


def extract_json(text: str) -> dict | None:
    """Pull the last JSON object out of the agent's reply.

    Tries the whole reply first, then the last fenced block, then the widest
    brace span. The agent is told to emit only JSON; this tolerates it wrapping
    the object in prose or a code fence anyway.
    """
    for candidate in _json_candidates(text):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "packages" in parsed:
            return parsed
    return None


def _json_candidates(text: str):
    text = text.strip()
    yield text
    fences = re.findall(r"```(?:json)?\s*(.+?)```", text, re.S)
    for f in reversed(fences):
        yield f.strip()
    m = JSON_BLOCK.search(text)
    if m:
        yield m.group(0)


def run_agent(model: str) -> str:
    cmd = [
        "openclaw", "agent", "exec",
        "--isolated",
        "--config", str(CONFIG),
        "--state-dir", str(STATE),
        "--message-file", str(PROMPT),
        "--model", model,
        "--timeout", str(AGENT_TIMEOUT_S),
        "--json",
    ]
    log(f"running: {' '.join(cmd)}")
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=AGENT_TIMEOUT_S + 60)
    if p.returncode != 0:
        log(f"agent exited {p.returncode}; stderr: {p.stderr[-2000:]}")
    return p.stdout


def agent_reply_text(envelope_stdout: str) -> str:
    """Get the agent's message out of the `agent exec --json` envelope.

    Falls back to the raw stdout if the envelope shape is not what we expect, so
    a wrapper change degrades to "try to parse anyway" rather than a hard failure.
    """
    try:
        env_obj = json.loads(envelope_stdout)
    except json.JSONDecodeError:
        return envelope_stdout
    for key in ("result", "text", "message", "reply", "output", "content"):
        v = env_obj.get(key) if isinstance(env_obj, dict) else None
        if isinstance(v, str) and v.strip():
            return v
    return envelope_stdout


# ── main ─────────────────────────────────────────────────────────────────────


def main() -> int:
    bucket = env("KINGLET_BUCKET")
    bundle_key = env("KINGLET_BUNDLE_KEY")
    result_key = env("KINGLET_RESULT_KEY")
    model = env("KINGLET_MODEL")

    fetch_bundle(bucket, bundle_key)
    freeze_work()

    result = None
    for attempt in (1, 2):  # §5.3: retry once, then give up
        log(f"agent attempt {attempt}")
        reply = agent_reply_text(run_agent(model))
        result = extract_json(reply)
        if result is not None:
            break
        log(f"attempt {attempt}: no parseable JSON object in the reply")

    if result is None:
        fail("agent produced no parseable JSON object after 2 attempts")

    body = json.dumps(result, separators=(",", ":")).encode()
    boto3.client("s3").put_object(Bucket=bucket, Key=result_key, Body=body,
                                  ContentType="application/json")
    log(f"wrote s3://{bucket}/{result_key} ({len(body)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
