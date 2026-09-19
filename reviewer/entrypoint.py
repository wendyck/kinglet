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
import tempfile
from pathlib import Path

import boto3

from safe_tar import UnsafeArchive, freeze, safe_extract

WORK = Path(os.environ.get("KINGLET_WORK", "/work"))
STATE = Path(os.environ.get("OPENCLAW_STATE_DIR", "/state"))
CONFIG = Path(os.environ.get("OPENCLAW_CONFIG_PATH", "/opt/kinglet/openclaw/openclaw.json"))
PROMPT = Path(os.environ.get("KINGLET_PROMPT", "/opt/kinglet/prompt.md"))

AGENT_TIMEOUT_S = int(os.environ.get("KINGLET_AGENT_TIMEOUT", "540"))

# Extraction uses the same common/safe_tar module Prepare does — one tested
# implementation rather than two that can drift. Tier 2 re-applies the checks
# because it must not trust its own input either, even though Prepare built
# this bundle.


def log(msg: str) -> None:
    print(f"[kinglet-reviewer] {msg}", flush=True)


def fail(msg: str) -> None:
    print(f"[kinglet-reviewer] FATAL: {msg}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        fail(f"required environment variable {name} is not set")
    return v


# ── bundle ───────────────────────────────────────────────────────────────────


def fetch_bundle(bucket: str, key: str) -> None:
    log(f"fetching s3://{bucket}/{key}")
    WORK.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", dir="/tmp", delete=True) as tmp:
        boto3.client("s3").download_fileobj(bucket, key, tmp)
        tmp.flush()
        try:
            # strip_top_level=False: Prepare's bundle is not wrapped the way a
            # GitHub tarball is. Stripping would rename repo/ away and drop
            # task.json, which has no directory component at all.
            result = safe_extract(Path(tmp.name), WORK, strip_top_level=False)
        except UnsafeArchive as e:
            fail(f"refusing the bundle: {e}")
    log(f"extracted {result.files} files ({result.total_bytes} bytes) to {WORK}")


def freeze_work() -> None:
    """Make the bundle read-only (§5.3 step 1).

    openclaw state lives on a separate tmpfs at /state precisely so this does not
    break it (spike F15).
    """
    freeze(WORK)
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
        # No --isolated: it cannot be combined with --config, and it would
        # discard the hardened posture rather than apply it (spike F18).
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
    # The root filesystem is read-only, so openclaw's HOME and cache have to be
    # created on the writable state tmpfs before it runs.
    for d in (STATE / "home", STATE / "cache"):
        d.mkdir(parents=True, exist_ok=True)

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
