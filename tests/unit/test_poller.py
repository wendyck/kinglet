"""Tests for the Poller (SPEC.md §5.1).

Two behaviours matter most and are easy to get wrong:

- the review key must survive a rebase, or every poll re-reviews everything;
- the authenticity checks must reject a spoofed "Dependabot" PR, since passing
  one would feed attacker-authored manifests into the pipeline.
"""

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from poller.app import (  # noqa: E402
    execution_name, is_dependabot_pr, is_manifest, review_key, reviewed_key,
)
from common.render import marker  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "real"
BOT = "kinglet-bot[bot]"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def as_pr(fx: dict) -> dict:
    """Rebuild the PR shape the GitHub list endpoint returns."""
    return {
        "number": fx["pr"]["number"],
        "title": fx["pr"]["title"],
        "user": fx["user"],
        "head": {"sha": fx["head"]["sha"], "ref": fx["head"]["ref"],
                 "repo": {"full_name": fx["head"]["repo_full_name"]}},
        "base": {"ref": fx["base"]["ref"],
                 "repo": {"full_name": fx["base"]["repo_full_name"]}},
    }


# ── authenticity ─────────────────────────────────────────────────────────────


def test_all_real_prs_pass():
    for f in sorted(FIXTURES.glob("*.json")):
        assert is_dependabot_pr(as_pr(fixture(f.name))), f.name


@pytest.mark.parametrize("mutate,why", [
    (lambda p: p["user"].update(login="dependabot"), "login without the [bot] suffix"),
    (lambda p: p["user"].update(login="attacker"), "wrong login"),
    (lambda p: p["user"].update(type="User"), "a User impersonating the bot"),
    (lambda p: p["head"]["repo"].update(full_name="attacker/csa-wrangler"), "fork head"),
    (lambda p: p["head"].update(ref="feature/sneaky"), "non-dependabot branch"),
    (lambda p: p["head"].update(repo=None), "deleted head repo"),
])
def test_spoofed_prs_are_rejected(mutate, why):
    pr = as_pr(fixture("csa-wrangler-pr29.json"))
    mutate(pr)
    assert not is_dependabot_pr(pr), why


# ── the review key ───────────────────────────────────────────────────────────


def test_key_is_stable_across_a_rebase():
    """A rebase moves the head SHA and the commit prose but not the change."""
    fx = fixture("csa-wrangler-pr29.json")
    msg, files = fx["commits"][0]["message"], fx["changed_files"]
    before = review_key(msg, files)

    rebased_msg = msg + "\n\nRebased onto 9f8e7d6.\n"
    after = review_key(rebased_msg, copy.deepcopy(files))
    assert before == after


def test_key_changes_when_the_patch_changes():
    fx = fixture("csa-wrangler-pr29.json")
    msg, files = fx["commits"][0]["message"], fx["changed_files"]
    bumped = copy.deepcopy(files)
    bumped[0]["patch"] = bumped[0]["patch"].replace("0.121.0", "0.122.0")
    assert review_key(msg, files) != review_key(msg, bumped)


def test_key_changes_when_the_trailer_changes():
    fx = fixture("csa-wrangler-pr29.json")
    files = fx["changed_files"]
    other = fx["commits"][0]["message"].replace("anthropic", "anthropiq")
    assert review_key(fx["commits"][0]["message"], files) != review_key(other, files)


def test_key_distinguishes_the_same_bump_in_different_directories():
    """#10 and #28 both touch scripts/; a hypothetical root-level twin must not
    collide with them."""
    fx = fixture("csa-wrangler-pr28.json")
    msg, files = fx["commits"][0]["message"], fx["changed_files"]
    moved = copy.deepcopy(files)
    moved[0]["filename"] = "requirements.txt"
    assert review_key(msg, files) != review_key(msg, moved)


def test_key_ignores_non_manifest_files():
    """A README tweak in the same PR must not invalidate the review."""
    fx = fixture("csa-wrangler-pr29.json")
    msg, files = fx["commits"][0]["message"], fx["changed_files"]
    noisy = copy.deepcopy(files) + [
        {"filename": "README.md", "patch": "@@\n-old\n+new\n"}]
    assert review_key(msg, files) == review_key(msg, noisy)


def test_key_is_order_independent():
    fx = fixture("csa-wrangler-pr27.json")
    msg, files = fx["commits"][0]["message"], fx["changed_files"]
    assert review_key(msg, files) == review_key(msg, list(reversed(files)))


def test_every_real_pr_gets_a_distinct_key():
    keys = {}
    for f in sorted(FIXTURES.glob("*.json")):
        fx = fixture(f.name)
        k = review_key(fx["commits"][0]["message"], fx["changed_files"])
        assert k not in keys, f"{f.name} collides with {keys.get(k)}"
        keys[k] = f.name
    assert len(keys) == 8


@pytest.mark.parametrize("path,manifest", [
    ("requirements.txt", True), ("scripts/requirements.txt", True),
    (".github/workflows/ci.yml", True), ("pyproject.toml", True),
    ("README.md", False), ("src/planner/app.py", False),
])
def test_manifest_detection(path, manifest):
    assert is_manifest(path) is manifest


# ── execution naming ─────────────────────────────────────────────────────────


def test_execution_name_shape():
    name = execution_name("wendyck/csa-wrangler", 29, "a" * 64)
    assert name == "wendyck-csa-wrangler-29-aaaaaaaaaaaa"


def test_execution_name_is_within_step_functions_limits():
    name = execution_name("some-org/" + "x" * 200, 12345, "b" * 64)
    assert len(name) <= 80
    assert all(c.isalnum() or c in "-_" for c in name)


def test_execution_name_differs_per_key():
    a = execution_name("o/r", 1, "a" * 64)
    b = execution_name("o/r", 1, "c" * 64)
    assert a != b


# ── dedupe against the sticky comment ────────────────────────────────────────


def test_reviewed_key_reads_our_own_marker():
    comments = [
        {"user": {"login": "someone"}, "body": "unrelated"},
        {"user": {"login": BOT}, "body": marker("deadbeef1234", "abc", "ok") + "\nbody"},
    ]
    assert reviewed_key(comments, BOT) == "deadbeef1234"


def test_reviewed_key_ignores_a_marker_from_another_author():
    """Anyone can paste our marker into a comment; only ours counts."""
    comments = [{"user": {"login": "attacker"},
                 "body": marker("deadbeef1234", "abc", "ok")}]
    assert reviewed_key(comments, BOT) is None


def test_reviewed_key_none_when_unreviewed():
    assert reviewed_key([{"user": {"login": BOT}, "body": "hi"}], BOT) is None


def test_failed_review_still_records_a_key_so_the_poller_does_not_loop():
    """§5.8: the failure path writes the marker with status=failed."""
    comments = [{"user": {"login": BOT},
                 "body": marker("deadbeef1234", "abc", "failed")}]
    assert reviewed_key(comments, BOT) == "deadbeef1234"


# ── the daily spend cap (§13 Q1) ─────────────────────────────────────────────

from datetime import datetime, timedelta, timezone  # noqa: E402

from poller.app import executions_started_today  # noqa: E402


class FakeSFN:
    """list_executions returns newest first, which the counter relies on."""

    def __init__(self, start_dates):
        self.pages = [sorted(start_dates, reverse=True)]
        self.calls = 0

    def list_executions(self, **kwargs):
        self.calls += 1
        return {"executions": [{"startDate": d} for d in self.pages[0]]}


NOW = datetime(2026, 9, 19, 14, 0, tzinfo=timezone.utc)
MIDNIGHT = NOW.replace(hour=0, minute=0)


def test_counts_only_executions_since_utc_midnight():
    sfn = FakeSFN([
        MIDNIGHT + timedelta(hours=1),
        MIDNIGHT + timedelta(hours=2),
        MIDNIGHT - timedelta(minutes=5),      # yesterday
        MIDNIGHT - timedelta(hours=10),       # yesterday
    ])
    assert executions_started_today(sfn, "arn", now=NOW) == 2


def test_counts_zero_on_a_fresh_day():
    sfn = FakeSFN([MIDNIGHT - timedelta(minutes=1)])
    assert executions_started_today(sfn, "arn", now=NOW) == 0


def test_stops_reading_at_the_first_older_execution():
    """Newest-first ordering means one old entry ends the scan — a busy history
    must not turn every poll into twenty API calls."""
    sfn = FakeSFN([MIDNIGHT - timedelta(days=d) for d in range(1, 50)])
    assert executions_started_today(sfn, "arn", now=NOW) == 0
    assert sfn.calls == 1


def test_an_execution_exactly_at_midnight_counts_as_today():
    sfn = FakeSFN([MIDNIGHT])
    assert executions_started_today(sfn, "arn", now=NOW) == 1
