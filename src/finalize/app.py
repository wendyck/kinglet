"""Finalize Lambda (SPEC.md §5.5, §5.6, §5.8, §7.2, §7.3).

The only component that writes to GitHub, and the only one that decides what a
PR is finally labelled. It runs in two modes:

- **ok** — validate the reviewer's result against meta, take `max(floor, model)`,
  scan for supersessions, render the sticky comment and set the label.
- **failure** — reached by the Step Functions Catch from any state. Posts
  "could not complete this review", sets `risk:high`, and records the review key
  with `status=failed` so the poller does not retry in a loop (§5.8).

Its token carries `pull_requests: write` and nothing else, minted per run and
scoped to the one repository.
"""

from __future__ import annotations

import json
import logging
import os

import boto3

from common import github_app as gh
from common.dependabot import parse_pr
from common.render import (
    Advisory, Row, SUPERSEDED_MARKER_PREFIX, marker,
    render_comment, render_superseded_comment,
)
from common.supersede import PRUpdates, scan, supersedes_for
from common.validate import (
    apply_output_guardrail, cross_check, floor_reason_summary, validate_schema,
)

log = logging.getLogger()
log.setLevel(logging.INFO)

BUCKET = os.environ.get("KINGLET_BUCKET", "")
SNS_TOPIC = os.environ.get("KINGLET_SNS_TOPIC", "")
GUARDRAIL_ID = os.environ.get("KINGLET_GUARDRAIL_ID", "")
GUARDRAIL_VERSION = os.environ.get("KINGLET_GUARDRAIL_VERSION", "1")
VERSION = os.environ.get("KINGLET_VERSION", "0.1.0")
BOT_LOGIN = os.environ.get("KINGLET_BOT_LOGIN", "kinglet-bot[bot]")

RISK_LABELS = ("risk:low", "risk:medium", "risk:high")


def _s3_json(key: str) -> dict:
    body = boto3.client("s3").get_object(Bucket=BUCKET, Key=key)["Body"].read()
    return json.loads(body)


def output_guardrail(text: str) -> tuple[bool, list[str]]:
    """§7.2 step 4. Authoritative — this is Tier 1's own pass, not the
    reviewer's."""
    if not GUARDRAIL_ID or not text.strip():
        return False, []
    try:
        resp = boto3.client("bedrock-runtime").apply_guardrail(
            guardrailIdentifier=GUARDRAIL_ID, guardrailVersion=GUARDRAIL_VERSION,
            source="OUTPUT", content=[{"text": {"text": text}}])
    except Exception as e:
        log.error("output ApplyGuardrail failed: %s", e)
        return True, ["GUARDRAIL_UNAVAILABLE"]
    if resp.get("action") != "GUARDRAIL_INTERVENED":
        return False, []
    matched = []
    for a in resp.get("assessments", []):
        matched += [t["name"] for t in a.get("topicPolicy", {}).get("topics", [])]
        matched += [f["type"] for f in a.get("contentPolicy", {}).get("filters", [])]
    return True, sorted(set(matched))


# ── comments and labels (§5.5) ───────────────────────────────────────────────


def upsert_sticky(repo: str, number: int, body: str, *, token: str,
                  prefix: str) -> None:
    """Edit our own comment if it exists, otherwise create one."""
    for c in gh.list_issue_comments(repo, number, token=token):
        if (c.get("user") or {}).get("login") == BOT_LOGIN and prefix in (c.get("body") or ""):
            gh.update_comment(repo, c["id"], body, token=token)
            return
    gh.create_comment(repo, number, body, token=token)


def remove_sticky(repo: str, number: int, *, token: str, prefix: str) -> None:
    for c in gh.list_issue_comments(repo, number, token=token):
        if (c.get("user") or {}).get("login") == BOT_LOGIN and prefix in (c.get("body") or ""):
            gh.delete_comment(repo, c["id"], token=token)


def set_risk_label(repo: str, number: int, risk: str, *, token: str) -> None:
    """Replace any other `risk:*` label, leave everything else alone (§5.5).

    Scoped strictly to the `risk:` prefix: the token can delete any label in the
    repo, so the code must not be casual about which ones it touches.
    """
    target = f"risk:{risk}"
    existing = gh.current_labels(repo, number, token=token)
    keep = [l for l in existing if not l.startswith("risk:")]
    if set(existing) == set(keep + [target]):
        return
    gh.set_labels(repo, number, keep + [target], token=token)


# ── supersede scan (§5.6) ────────────────────────────────────────────────────


def scan_repo_supersessions(repo: str, *, token: str) -> tuple[dict, dict[int, str]]:
    """Verdicts for every open Dependabot PR, plus their titles."""
    from poller.app import is_dependabot_pr

    prs, titles = [], {}
    for pr in gh.list_open_pulls(repo, token=token):
        if not is_dependabot_pr(pr):
            continue
        number = pr["number"]
        commits = gh.list_pull_commits(repo, number, token=token)
        if not commits:
            continue
        files = gh.list_pull_files(repo, number, token=token)
        parsed = parse_pr(commits[0]["commit"]["message"], files)
        prs.append(PRUpdates(number=number, updates=parsed.updates))
        titles[number] = pr.get("title", "")
    return scan(prs), titles


def apply_supersede_comments(repo: str, verdicts: dict, *, token: str) -> None:
    """Post, update or remove the separate superseded comment on each PR.

    Removal matters as much as posting: if the superseding PR is closed or
    rebased to a different target, the relationship goes away and the comment
    must go with it (§5.6).
    """
    for number, verdict in verdicts.items():
        if verdict.supersessions:
            body = render_superseded_comment(
                by=verdict.by,
                packages=[(s.package, s.directory, s.by_pr) for s in verdict.supersessions],
                fully=verdict.fully)
            upsert_sticky(repo, number, body, token=token,
                          prefix=SUPERSEDED_MARKER_PREFIX)
        else:
            remove_sticky(repo, number, token=token, prefix=SUPERSEDED_MARKER_PREFIX)


# ── the handler ──────────────────────────────────────────────────────────────


def handler(event, context):  # noqa: ARG001
    mode = event.get("mode", "ok")
    repo = event["repo"]
    number = int(event["pr"])
    installation_id = int(event["installation_id"])
    review_key = event.get("review_key", "")
    sha = event.get("head_sha", "")

    app = gh.GitHubApp()
    token = app.installation_token(
        installation_id, repositories=[repo.split("/")[-1]],
        permissions={"pull_requests": "write"})

    if mode == "failure":
        return _finalize_failure(repo, number, review_key, sha, event, token=token)

    meta = _s3_json(event["meta_key"])
    try:
        result = _s3_json(event["result_key"])
        validate_schema(result)
        validated = cross_check(result, meta)
    except Exception as e:  # noqa: BLE001 - any failure here routes to §5.8
        log.error("result rejected for %s#%s: %s", repo, number, e)
        return _finalize_failure(repo, number, review_key, sha,
                                 {**event, "reason": f"INVALID_RESULT: {e}"}, token=token)

    validated = apply_output_guardrail(validated, output_guardrail)

    verdicts, _ = scan_repo_supersessions(repo, token=token)
    supersedes = supersedes_for(number, verdicts)

    by_key = {(p["name"], p["directory"]): p for p in meta.get("packages", [])}
    rows = []
    for p in validated.packages:
        m = by_key.get((p.name, p.directory), {})
        rows.append(Row(
            name=p.name, directory=p.directory,
            change=f"{m.get('from') or '?'} → {m.get('to') or '?'}",
            risk=p.risk, verdict=p.verdict,
            reason_codes=p.reason_codes, evidence=p.evidence))

    advisories = [Advisory(a["ghsa_id"], a["severity"], a["summary"])
                  for a in meta.get("security", [])]

    body = render_comment(
        review_key=review_key, sha=sha, overall_risk=validated.overall_risk,
        rows=rows, floor_reasons=floor_reason_summary(meta),
        advisories=advisories, supersedes=supersedes,
        notes=validated.notes, version=VERSION)

    upsert_sticky(repo, number, body, token=token, prefix="<!-- kinglet:v1 ")
    set_risk_label(repo, number, validated.overall_risk, token=token)
    apply_supersede_comments(repo, verdicts, token=token)

    if validated.warnings:
        log.warning("%s#%s validation warnings: %s", repo, number, validated.warnings)

    log.info("finalized %s#%s risk=%s packages=%d",
             repo, number, validated.overall_risk, len(rows))
    return {"status": "ok", "repo": repo, "pr": number,
            "risk": validated.overall_risk, "warnings": validated.warnings}


def _finalize_failure(repo: str, number: int, review_key: str, sha: str,
                      event: dict, *, token: str) -> dict:
    """§5.8. Treat as unreviewed, label high, and stop the poller looping."""
    reason = event.get("reason") or (event.get("error") or {}).get("Error") or "UNKNOWN"
    body = "\n".join([
        marker(review_key, sha, status="failed"),
        "### 🐦 Kinglet dependency review — **risk: HIGH** 🔴",
        "",
        f"Kinglet could not complete this review (`{str(reason)[:200]}`). "
        "**Treat this PR as unreviewed.**",
        "",
        f"To retry: `scripts/retry.sh {repo} {number}`",
        "",
        f"<sub>kinglet {VERSION} · failed</sub>",
    ])
    try:
        upsert_sticky(repo, number, body, token=token, prefix="<!-- kinglet:v1 ")
        set_risk_label(repo, number, "high", token=token)
    except Exception as e:
        log.error("could not post failure comment on %s#%s: %s", repo, number, e)

    if SNS_TOPIC:
        try:
            boto3.client("sns").publish(
                TopicArn=SNS_TOPIC,
                Subject=f"kinglet: review failed for {repo}#{number}"[:100],
                Message=json.dumps({"repo": repo, "pr": number, "reason": str(reason)[:1000]}))
        except Exception as e:
            log.error("SNS publish failed: %s", e)

    log.error("finalize failure for %s#%s: %s", repo, number, reason)
    return {"status": "failed", "repo": repo, "pr": number, "reason": str(reason)[:200]}
