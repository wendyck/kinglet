"""Tests for Finalize's decision logic (SPEC.md §5.5, §5.8).

The GitHub calls are stubbed; what matters here is which calls are made. The
label logic in particular must be narrow: the Finalize token can delete any
label in the repo, so touching a non-risk label would be a real bug.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import finalize.app as fin  # noqa: E402
from common.render import SUPERSEDED_MARKER_PREFIX, marker  # noqa: E402

BOT = "kinglet-bot[bot]"
STICKY = "<!-- kinglet:v1 "


@pytest.fixture(autouse=True)
def bot_login(monkeypatch):
    monkeypatch.setattr(fin, "BOT_LOGIN", BOT)


class FakeGH:
    def __init__(self, comments=None, labels=None):
        self._comments = comments or []
        self._labels = labels or []
        self.created, self.updated, self.deleted, self.label_sets = [], [], [], []

    def list_issue_comments(self, repo, number, *, token):
        return self._comments

    def create_comment(self, repo, number, body, *, token):
        self.created.append(body)
        return {"id": 1}

    def update_comment(self, repo, cid, body, *, token):
        self.updated.append((cid, body))
        return {"id": cid}

    def delete_comment(self, repo, cid, *, token):
        self.deleted.append(cid)

    def current_labels(self, repo, number, *, token):
        return self._labels

    def set_labels(self, repo, number, labels, *, token):
        self.label_sets.append(sorted(labels))
        return []


@pytest.fixture
def fake(monkeypatch):
    f = FakeGH()
    for name in ("list_issue_comments", "create_comment", "update_comment",
                 "delete_comment", "current_labels", "set_labels"):
        monkeypatch.setattr(fin.gh, name, getattr(f, name))
    return f


# ── sticky comment (§5.5) ────────────────────────────────────────────────────


def test_creates_a_comment_when_none_exists(fake):
    fin.upsert_sticky("o/r", 1, "body", token="t", prefix=STICKY)
    assert fake.created == ["body"] and not fake.updated


def test_edits_our_existing_comment(fake):
    fake._comments = [{"id": 7, "user": {"login": BOT},
                       "body": marker("k", "s") + "\nold"}]
    fin.upsert_sticky("o/r", 1, "new", token="t", prefix=STICKY)
    assert fake.updated == [(7, "new")] and not fake.created


def test_does_not_edit_someone_elses_comment(fake):
    """Anyone can paste our marker; we only ever edit our own comment."""
    fake._comments = [{"id": 7, "user": {"login": "attacker"},
                       "body": marker("k", "s") + "\nnot ours"}]
    fin.upsert_sticky("o/r", 1, "new", token="t", prefix=STICKY)
    assert fake.created == ["new"] and not fake.updated


def test_review_and_superseded_comments_are_separate(fake):
    fake._comments = [{"id": 7, "user": {"login": BOT}, "body": marker("k", "s")}]
    fin.upsert_sticky("o/r", 1, "superseded body", token="t",
                      prefix=SUPERSEDED_MARKER_PREFIX)
    assert fake.created == ["superseded body"], "must not overwrite the review comment"


def test_remove_sticky_deletes_only_ours(fake):
    fake._comments = [
        {"id": 1, "user": {"login": "someone"}, "body": SUPERSEDED_MARKER_PREFIX + "-->"},
        {"id": 2, "user": {"login": BOT}, "body": SUPERSEDED_MARKER_PREFIX + "by=#9 -->"},
    ]
    fin.remove_sticky("o/r", 1, token="t", prefix=SUPERSEDED_MARKER_PREFIX)
    assert fake.deleted == [2]


# ── labels (§5.5) ────────────────────────────────────────────────────────────


def test_sets_the_risk_label(fake):
    fake._labels = []
    fin.set_risk_label("o/r", 1, "high", token="t")
    assert fake.label_sets == [["risk:high"]]


def test_replaces_a_previous_risk_label(fake):
    fake._labels = ["risk:low"]
    fin.set_risk_label("o/r", 1, "high", token="t")
    assert fake.label_sets == [["risk:high"]]


def test_preserves_unrelated_labels(fake):
    """The token can delete any label. This must not be casual about it."""
    fake._labels = ["dependencies", "python", "risk:low"]
    fin.set_risk_label("o/r", 1, "medium", token="t")
    assert fake.label_sets == [["dependencies", "python", "risk:medium"]]


def test_no_write_when_the_label_is_already_correct(fake):
    fake._labels = ["dependencies", "risk:high"]
    fin.set_risk_label("o/r", 1, "high", token="t")
    assert fake.label_sets == [], "an unchanged label should not be rewritten"


# ── failure path (§5.8) ──────────────────────────────────────────────────────


def test_failure_marks_high_and_records_the_key(fake, monkeypatch):
    monkeypatch.setattr(fin, "SNS_TOPIC", "")
    out = fin._finalize_failure("o/r", 3, "abc123", "deadbeef",
                                {"reason": "States.Timeout"}, token="t")
    assert out["status"] == "failed"
    body = fake.created[0]
    parsed = __import__("common.render", fromlist=["parse_marker"]).parse_marker(body)
    assert parsed["status"] == "failed"
    assert parsed["key"] == "abc123"
    assert "Treat this PR as unreviewed" in body
    assert fake.label_sets == [["risk:high"]]


def test_failure_comment_mentions_how_to_retry(fake, monkeypatch):
    monkeypatch.setattr(fin, "SNS_TOPIC", "")
    fin._finalize_failure("o/r", 3, "k", "s", {}, token="t")
    assert "scripts/retry.sh o/r 3" in fake.created[0]


def test_failure_survives_github_being_unavailable(fake, monkeypatch):
    """A failed review must still return, or the Catch state itself fails."""
    monkeypatch.setattr(fin, "SNS_TOPIC", "")
    monkeypatch.setattr(fin.gh, "list_issue_comments",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("502")))
    out = fin._finalize_failure("o/r", 3, "k", "s", {}, token="t")
    assert out["status"] == "failed"
