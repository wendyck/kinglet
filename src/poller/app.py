"""Poller Lambda (SPEC.md §5.1).

Runs every 10 minutes. Finds open Dependabot PRs on enrolled repos that have not
been reviewed at their current content, and starts at most N executions.

There is no webhook and no public ingress: polling is what removes the ALB, the
domain and the webhook secret from the design (§3).

Two ideas carry most of the weight:

- **The review key** is a hash of the dependency change itself, not the head SHA.
  Dependabot rebases whenever `main` moves, which changes the SHA but not the
  change, so keying on the SHA would re-review the same PR all day.
- **The execution name** embeds that key, so `StartExecution` is idempotent.
  Two overlapping polls cannot start two reviews of the same thing:
  `ExecutionAlreadyExists` means "already in flight", which is a skip, not an
  error.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass

import boto3
import yaml

from common import github_app as gh
from common.dependabot import ACTIONS_MANIFESTS, ecosystem_for, parse_trailer
from common.render import parse_marker

log = logging.getLogger()
log.setLevel(logging.INFO)

STATE_MACHINE_ARN = os.environ.get("KINGLET_STATE_MACHINE_ARN", "")
# A hard ceiling on reviews per UTC day. AWS has no per-day Bedrock cost cap —
# the per-day token quotas are AWS-set ceilings in the tens of millions and are
# not adjustable — so this is the only control that bounds kinglet's own spend
# in real time. Budgets are a lagging backstop; this is the cap.
MAX_STARTS_PER_DAY = int(os.environ.get("KINGLET_MAX_STARTS_PER_DAY", "25"))
CONFIG_PATH = os.environ.get("KINGLET_CONFIG", "config/repos.yml")
BOT_LOGIN = "dependabot[bot]"

# An execution name must be <=80 chars and match [0-9A-Za-z_-]
_NAME_SAFE = re.compile(r"[^0-9A-Za-z_-]")


def load_config(path: str | None = None) -> dict:
    with open(path or CONFIG_PATH) as fh:
        return yaml.safe_load(fh) or {}


# ── authenticity (§5.1) ──────────────────────────────────────────────────────


def is_dependabot_pr(pr: dict) -> bool:
    """All four checks must hold. A PR failing any of them is not reviewed at
    all — Kinglet only reviews Dependabot (§1, non-goals)."""
    user = pr.get("user") or {}
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    head_repo = head.get("repo") or {}
    base_repo = base.get("repo") or {}
    return (
        user.get("login") == BOT_LOGIN
        and user.get("type") == "Bot"
        and bool(head_repo.get("full_name"))
        and head_repo.get("full_name") == base_repo.get("full_name")
        and str(head.get("ref", "")).startswith("dependabot/")
    )


# ── the review key (§5.1) ────────────────────────────────────────────────────


def is_manifest(filename: str) -> bool:
    return ecosystem_for(filename) is not None or bool(ACTIONS_MANIFESTS.match(filename))


def review_key(commit_message: str, changed_files: list[dict]) -> str:
    """sha256 over the parsed dependency list plus the manifest patch text.

    Deliberately excludes the head SHA, the PR body and the commit message
    prose: a rebase changes all three while changing nothing that matters. It
    includes filenames so the same bump in a different directory is a different
    review.
    """
    trailer = parse_trailer(commit_message) or []
    deps = sorted(
        json.dumps({k: v for k, v in entry.items()}, sort_keys=True)
        for entry in trailer
    )
    patches = sorted(
        f"{f.get('filename')}\n{f.get('patch') or ''}"
        for f in changed_files
        if is_manifest(f.get("filename", ""))
    )
    h = hashlib.sha256()
    for part in deps + patches:
        h.update(part.encode())
        h.update(b"\x00")
    return h.hexdigest()


def execution_name(repo: str, number: int, key: str) -> str:
    """`<repo>-<pr>-<key12>`, trimmed to Step Functions' 80-char limit."""
    slug = _NAME_SAFE.sub("-", repo.replace("/", "-"))
    name = f"{slug}-{number}-{key[:12]}"
    return name[:80]


# ── the existing comment (§5.1, §5.5) ────────────────────────────────────────


def reviewed_key(comments: list[dict], bot_login: str) -> str | None:
    """The review key recorded in our own sticky comment, if any."""
    for c in comments:
        if (c.get("user") or {}).get("login") != bot_login:
            continue
        marker = parse_marker(c.get("body") or "")
        if marker and marker.get("key"):
            return marker["key"]
    return None


# ── the poll ─────────────────────────────────────────────────────────────────


@dataclass
class Scan:
    """What one repository's poll found.

    The counts exist so a quiet poll can be told apart from a broken one. A
    result of "nothing to do" and a result of "discovery returned nothing"
    are the same summary otherwise, and they mean opposite things.
    """

    candidates: list[dict]
    dependabot_prs: int = 0
    already_reviewed: int = 0


def candidates_for_repo(repo: str, *, token: str, bot_login: str) -> Scan:
    """Open Dependabot PRs on `repo` that need a review, newest PR last."""
    scan = Scan(candidates=[])
    for pr in gh.list_open_pulls(repo, token=token):
        if not is_dependabot_pr(pr):
            continue
        scan.dependabot_prs += 1
        number = pr["number"]
        commits = gh.list_pull_commits(repo, number, token=token)
        if not commits:
            continue
        files = gh.list_pull_files(repo, number, token=token)
        key = review_key(commits[0]["commit"]["message"], files)

        comments = gh.list_issue_comments(repo, number, token=token)
        if reviewed_key(comments, bot_login) == key:
            log.info("skip %s#%s: already reviewed at key %s", repo, number, key[:12])
            scan.already_reviewed += 1
            continue

        scan.candidates.append({
            "repo": repo,
            "pr": number,
            "head_sha": pr["head"]["sha"],
            "review_key": key,
            "title": pr.get("title", "")[:200],
        })
    scan.candidates.sort(key=lambda c: c["pr"])
    return scan


def executions_started_today(sfn, state_machine_arn: str, *, now=None) -> int:
    """Count executions started since UTC midnight.

    Read from Step Functions itself rather than a counter we maintain: there is
    no state to drift, and a restarted or redeployed stack cannot accidentally
    reset the day's tally to zero.
    """
    from datetime import datetime, timezone
    now = now or datetime.now(timezone.utc)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)

    count = 0
    token = None
    for _ in range(20):  # page cap: 20 * 100 is far beyond any sane day
        kwargs = {"stateMachineArn": state_machine_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = sfn.list_executions(**kwargs)
        for ex in page.get("executions", []):
            if ex["startDate"] >= midnight:
                count += 1
            else:
                # list_executions returns newest first, so the first older one
                # means everything after it is older too.
                return count
        token = page.get("nextToken")
        if not token:
            break
    return count


def handler(event, context):  # noqa: ARG001
    cfg = load_config()
    enrolled = set((cfg.get("repos") or {}).keys())
    max_starts = int(os.environ.get(
        "KINGLET_MAX_STARTS",
        (cfg.get("defaults") or {}).get("max_starts_per_run", 2)))
    bot_login = os.environ.get("KINGLET_BOT_LOGIN", "kinglet-bot[bot]")

    app = gh.GitHubApp()
    sfn = boto3.client("stepfunctions")

    today = executions_started_today(sfn, STATE_MACHINE_ARN)
    budget_left = max(0, MAX_STARTS_PER_DAY - today)
    if budget_left == 0:
        log.warning("daily cap reached: %d executions started today (cap %d); "
                    "starting nothing", today, MAX_STARTS_PER_DAY)
        return {"started": [], "skipped": 0, "considered": 0,
                "daily_cap_reached": True, "started_today": today}

    started, skipped, considered = [], 0, 0
    repos_polled, dependabot_prs, already_reviewed = 0, 0, 0

    for inst in app.installations():
        inst_id = inst["id"]
        installed = set(app.installation_repositories(inst_id))
        # Both switches must agree (§5.1): an accidental install does not start
        # a review, and a config entry without an install does nothing.
        for repo in sorted(installed & enrolled):
            repos_polled += 1
            token = app.installation_token(
                inst_id, repositories=[repo.split("/")[-1]],
                permissions={"contents": "read", "pull_requests": "read"})
            scan = candidates_for_repo(repo, token=token, bot_login=bot_login)
            dependabot_prs += scan.dependabot_prs
            already_reviewed += scan.already_reviewed
            for cand in scan.candidates:
                considered += 1
                if len(started) >= min(max_starts, budget_left):
                    skipped += 1
                    continue
                name = execution_name(repo, cand["pr"], cand["review_key"])
                try:
                    sfn.start_execution(
                        stateMachineArn=STATE_MACHINE_ARN,
                        name=name,
                        input=json.dumps({**cand, "installation_id": inst_id}))
                    started.append(name)
                    log.info("started %s", name)
                except sfn.exceptions.ExecutionAlreadyExists:
                    # Already in flight for this exact content. Not an error.
                    log.info("in flight, skipping %s", name)
                    skipped += 1

    result = {"started": started, "skipped": skipped, "considered": considered,
              "repos_polled": repos_polled, "dependabot_prs": dependabot_prs,
              "already_reviewed": already_reviewed,
              "max_starts": max_starts, "started_today": today + len(started),
              "daily_cap": MAX_STARTS_PER_DAY}
    log.info("poll complete: %s", json.dumps(result))
    return result
