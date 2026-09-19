"""Tests for the comment renderer (SPEC.md §7.3, §5.6, §5.7).

The renderer is the last thing between untrusted input and a PR comment, so the
end of this file runs the adversarial corpus through sanitize + render and
asserts nothing live reaches the output.
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from common.render import (  # noqa: E402
    Advisory, MARKER_PREFIX, Row, describe, marker, parse_marker,
    render_comment, render_superseded_comment, security_banner,
)
from common.sanitize import sanitize_notes  # noqa: E402

NOW = datetime(2026, 9, 19, 18, 30, tzinfo=timezone.utc)

ROWS = [Row(name="anthropic", directory="/scripts", change=">=0.116.0 → >=0.121.0",
            risk="high", verdict="VERIFY", reason_codes=["ZERO_X_MINOR"],
            evidence=[{"path": "scripts/add_recipes.py", "line": 42}])]


def render(**kw):
    base = dict(review_key="abc123def456", sha="b7b1db2208c1ffff", overall_risk="high",
                rows=ROWS, now=NOW)
    base.update(kw)
    return render_comment(**base)


# ── the marker, which drives dedupe (§5.1) ───────────────────────────────────


def test_marker_round_trips():
    m = marker("abc123", "deadbeef", "ok")
    parsed = parse_marker(f"noise\n{m}\nmore noise")
    assert parsed == {"key": "abc123", "sha": "deadbeef", "status": "ok"}


def test_parse_marker_returns_none_when_absent():
    assert parse_marker("an ordinary comment") is None


def test_comment_starts_with_the_marker():
    assert render().startswith(MARKER_PREFIX)


def test_failure_status_is_representable():
    assert parse_marker(marker("k", "s", "failed"))["status"] == "failed"


# ── structure ────────────────────────────────────────────────────────────────


def test_headline_carries_the_overall_risk():
    assert "**risk: HIGH**" in render(overall_risk="high")
    assert "**risk: LOW**" in render(overall_risk="low")


def test_advisory_disclaimer_is_present():
    assert "Advisory only" in render()


def test_table_has_one_row_per_package():
    out = render(rows=[
        Row("a", "/", "1→2", "low", "SAFE"),
        Row("b", "/scripts", "3→4", "medium", "VERIFY"),
    ])
    body = [l for l in out.splitlines() if l.startswith("| `")]
    assert len(body) == 2


def test_tier1_strings_are_code_spanned():
    out = render()
    assert "`anthropic`" in out and "`/scripts`" in out
    assert "`>=0.116.0 → >=0.121.0`" in out


def test_reason_codes_become_fixed_wording():
    out = render()
    assert describe("ZERO_X_MINOR") in out
    assert "ZERO_X_MINOR" not in out.split("Floor reasons")[0]


def test_evidence_is_rendered_as_path_and_line():
    assert "`scripts/add_recipes.py:42`" in render()


def test_missing_evidence_renders_a_dash():
    out = render(rows=[Row("a", "/", "1→2", "low", "SAFE")])
    assert "| — |" in out


def test_footer_has_version_short_sha_and_timestamp():
    out = render(version="1.2.3")
    assert "kinglet 1.2.3" in out
    assert "`b7b1db2208c1`" in out
    assert "2026-09-19 18:30 UTC" in out


def test_floor_reasons_line():
    out = render(floor_reasons={"ZERO_X_MINOR": ["anthropic"]})
    assert "**Floor reasons:**" in out and "`anthropic`" in out


def test_supersedes_line_renders_pr_links():
    out = render(supersedes=[(10, "boto3")])
    assert "**Supersedes:** #10 (`boto3`)" in out


def test_no_supersedes_line_when_empty():
    assert "Supersedes" not in render()


def test_notes_are_quoted_and_labeled_untrusted():
    out = render(notes="looks fine")
    assert "> **Model notes (untrusted, sanitized):** looks fine" in out


def test_no_notes_block_when_empty():
    assert "Model notes" not in render(notes="")


# ── the security banner (§5.7) ───────────────────────────────────────────────


def test_no_banner_without_advisories():
    assert security_banner([]) == ""
    assert "Security update" not in render()


def test_banner_counts_and_reports_highest_severity():
    out = render(advisories=[
        Advisory("GHSA-aaaa-bbbb-cccc", "moderate", "Regex denial of service"),
        Advisory("GHSA-dddd-eeee-ffff", "high", "Header injection"),
    ])
    assert "fixes 2 advisories (highest: HIGH)" in out
    assert "GHSA-aaaa-bbbb-cccc" in out and "GHSA-dddd-eeee-ffff" in out


def test_banner_singular_for_one_advisory():
    out = render(advisories=[Advisory("GHSA-x", "moderate", "thing")])
    assert "fixes 1 advisory (highest: MODERATE)" in out


def test_banner_sits_above_the_review_heading():
    out = render(advisories=[Advisory("GHSA-x", "high", "thing")])
    assert out.index("Security update") < out.index("Kinglet dependency review")


def test_advisory_summary_is_sanitized():
    """Advisory text is third-party, so it gets the same treatment as notes."""
    out = render(advisories=[
        Advisory("GHSA-x", "high", "RCE ![p](https://attacker.invalid/b.png) here")])
    assert "attacker.invalid" not in out and "![" not in out


# ── superseded comment (§5.6) ────────────────────────────────────────────────


def test_fully_superseded_single_package():
    out = render_superseded_comment(by=[28], packages=[("boto3", "/scripts", 28)], fully=True)
    assert "superseded by #28" in out
    assert "`boto3`" in out and "`/scripts`" in out
    assert "Consider closing this one." in out
    assert "by=#28" in out


def test_partially_superseded_lists_each_package():
    out = render_superseded_comment(
        by=[27, 28],
        packages=[("recipe-scrapers", "/scripts", 27), ("boto3", "/scripts", 28)],
        fully=False)
    assert "partly superseded" in out
    assert "→ #27" in out and "→ #28" in out
    assert "still relevant" in out


def test_superseded_marker_lists_all_superseding_prs():
    out = render_superseded_comment(by=[27, 28], packages=[("x", "/", 27)], fully=True)
    assert "by=#27,#28" in out


# ── end to end against the adversarial corpus ────────────────────────────────

CORPUS = json.loads((ROOT / "tests" / "fixtures" / "adversarial" / "corpus.json").read_text())
LIVE = re.compile(r"https?://|!\[|\]\(|<img|<a\s|www\.", re.I)


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: c["id"])
def test_no_corpus_content_survives_into_a_comment(case):
    """Whatever the model echoes back from a hostile bundle, the rendered
    comment must contain nothing live."""
    out = render(notes=sanitize_notes(case["content"]),
                 advisories=[Advisory("GHSA-x", "high", case["content"])])
    # Strip the one construct kinglet emits legitimately: its own #N references.
    body = out.replace("](", "")
    assert not LIVE.search(body), f"live construct survived: {LIVE.search(body).group(0)}"
    assert "attacker.invalid" not in out


def test_a_package_name_cannot_break_out_of_the_table():
    """§7.2: names come from Tier 1 parsing, but they originate in a PR."""
    out = render(rows=[Row(name="evil`|` |--|\n| x", directory="/", change="1→2",
                           risk="low", verdict="SAFE")])
    rows = [l for l in out.splitlines() if l.startswith("| `")]
    assert len(rows) == 1, "a crafted name added table rows"
    assert "`" in rows[0]


def test_reasons_are_ordered_by_significance():
    """The code that drove the level should lead, not whichever was appended
    first. RANGE_FLOOR_ONLY is informational and belongs last."""
    out = render(rows=[Row("anthropic", "/scripts", ">=0.116.0 → >=0.121.0", "high",
                           "VERIFY",
                           reason_codes=["RANGE_FLOOR_ONLY", "ZERO_X_MINOR", "WATCHLIST"])])
    why = [l for l in out.splitlines() if l.startswith("| `anthropic`")][0]
    assert why.index(describe("ZERO_X_MINOR")) < why.index(describe("WATCHLIST"))
    assert why.index(describe("WATCHLIST")) < why.index(describe("RANGE_FLOOR_ONLY"))


def test_pr_wide_floor_reason_renders_without_empty_parens():
    """UNEXPECTED_CHANGE and PROMPT_ATTACK_SUSPECTED apply to the PR, not to a
    package, so they have no names to list."""
    out = render(floor_reasons={"PROMPT_ATTACK_SUSPECTED": [],
                                "ZERO_X_MINOR": ["anthropic"]})
    line = [l for l in out.splitlines() if l.startswith("**Floor reasons:**")][0]
    assert "()" not in line
    assert describe("PROMPT_ATTACK_SUSPECTED") in line
    assert "(`anthropic`)" in line


# ── the reviewer's envelope parsing (reviewer/entrypoint.py) ─────────────────


def test_agent_reply_text_reads_the_final_key():
    """`openclaw agent exec --json` puts the reply in `final`. Missing that key
    cost two live Fargate runs: the fallback returned the whole envelope, which
    parses as JSON but has no `packages`, so every attempt looked like a model
    failure."""
    # entrypoint.py imports safe_tar as a top-level module, the way it is laid
    # out inside the image.
    sys.path.insert(0, str(ROOT / "src" / "common"))
    sys.path.insert(0, str(ROOT / "reviewer"))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "kinglet_entrypoint", ROOT / "reviewer" / "entrypoint.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["kinglet_entrypoint"] = mod
    try:
        spec.loader.exec_module(mod)
    except ImportError as e:  # boto3 is a Lambda/container dep, not a test dep
        pytest.skip(f"reviewer deps not importable: {e}")

    envelope = json.dumps({"ok": True, "status": "ok",
                           "final": '```json\n{"packages": [], "notes": ""}\n```'})
    text = mod.agent_reply_text(envelope)
    assert text.startswith("```json")
    assert mod.extract_json(text) == {"packages": [], "notes": ""}
