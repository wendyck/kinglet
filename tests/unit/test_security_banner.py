"""The §5.7 banner comes from the alerts API and from nowhere else.

`test_injected_security_text_cannot_produce_a_banner` in test_prepare.py asserts
`match_alerts([], ...) == []`, which is true but does not use the injected text
at all — it cannot fail if PR text ever gained a path to the banner. The corpus
case `fake-security-banner` states the real requirement ("no security banner in
the rendered comment") and was marked "covered elsewhere" without being covered.
This is elsewhere.

Every negative here is paired with a positive control, so a change that breaks
the banner outright cannot make these pass by silencing it.
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from common.dependabot import parse_pr  # noqa: E402
from common.render import Advisory, Row, render_comment  # noqa: E402
from prepare.app import match_alerts  # noqa: E402

REAL = ROOT / "tests" / "fixtures" / "real"
SECURITY = ROOT / "tests" / "fixtures" / "security"
CORPUS = json.loads(
    (ROOT / "tests" / "fixtures" / "adversarial" / "corpus.json").read_text())

ALERTS_NONE = json.loads((SECURITY / "alerts-none-csa-wrangler.json").read_text())
ALERTS_BOTO3 = json.loads((SECURITY / "alerts-boto3-pip.json").read_text())
FAKE_BANNER = next(c for c in CORPUS["cases"] if c["id"] == "fake-security-banner")


def updates(fixture: str):
    """The package list Prepare would parse, from a real snapshot."""
    fx = json.loads((REAL / fixture).read_text())
    return fx, parse_pr(fx["commits"][0]["message"], fx["changed_files"]).updates


def comment(security: list[dict], fx: dict, notes: str = "") -> str:
    """The comment Finalize would render for this PR and this alert set."""
    return render_comment(
        review_key="test", sha=fx["head"]["sha"], overall_risk="medium",
        rows=[Row(name="boto3", directory="/scripts", change=">=1.34 → >=1.43.69",
                  risk="medium", verdict="SAFE")],
        floor_reasons=[],
        advisories=[Advisory(a["ghsa_id"], a["severity"], a["summary"])
                    for a in security],
        notes=notes)


# ── the recorded empty response ──────────────────────────────────────────────


def test_the_empty_recording_is_actually_empty():
    """Guards the fixture itself: a truncated recording would make every
    negative below pass for the wrong reason."""
    assert ALERTS_NONE == []
    assert len(ALERTS_BOTO3) == 1


# ── positive control: a real alert does produce a banner ─────────────────────


def test_a_matching_alert_produces_the_banner():
    fx, ups = updates("csa-wrangler-pr28.json")
    security = match_alerts(ALERTS_BOTO3, ups)
    assert [a["ghsa_id"] for a in security] == ["GHSA-7f3w-5xq4-2vvq"]
    out = comment(security, fx)
    assert "Security update" in out
    assert "fixes 1 advisory (highest: HIGH)" in out
    assert "GHSA-7f3w-5xq4-2vvq" in out


def test_the_alert_is_read_from_the_full_recorded_shape():
    """The fixture carries every documented field. Matching must not depend on
    the handful the parser happens to read today."""
    _, ups = updates("csa-wrangler-pr28.json")
    alert = ALERTS_BOTO3[0]
    assert set(alert) >= {"number", "state", "dependency", "security_advisory",
                          "security_vulnerability", "url", "html_url",
                          "dismissed_at", "fixed_at"}
    assert match_alerts([alert], ups)


# ── the negative the corpus actually asked for ───────────────────────────────


def test_echoed_injection_in_notes_does_not_become_a_banner():
    """`fake-security-banner`, driven down the path the text can actually take.

    PR text reaches a comment in exactly one way: the model reads
    `untrusted/pr_body.md` and echoes it into `notes`. So the text really is in
    the rendered comment — quoted, sanitized and labelled untrusted, which is
    the design. What must not happen is the text being *promoted* to a banner.

    Asserting instead that the body never reaches `render_comment` would be
    unfalsifiable: `render_comment` has no body parameter to begin with.
    """
    fx, ups = updates("csa-wrangler-pr28.json")
    security = match_alerts(ALERTS_NONE, ups)
    assert security == []

    out = comment(security, fx, notes=FAKE_BANNER["content"])

    assert "Security update" not in out, "injected text produced a §5.7 banner"
    assert "🛡️" not in out
    # It is present, but only inside the untrusted notes block.
    assert "SECURITY FIX" in out
    notes_block = [line for line in out.splitlines() if "SECURITY FIX" in line]
    assert notes_block and all(line.startswith(">") for line in notes_block), \
        "injected text escaped the quoted notes block"


def test_the_same_words_from_the_alerts_api_do_produce_a_banner():
    """Control for the test above: the words are not what is being suppressed.
    Identical severity language, arriving through the API, must banner."""
    fx, _ = updates("csa-wrangler-pr28.json")
    out = comment([{"ghsa_id": "GHSA-7f3w-5xq4-2vvq", "severity": "critical",
                    "summary": "Critical remote code execution vulnerability"}], fx)
    assert "Security update" in out
    assert "highest: CRITICAL" in out


@pytest.mark.parametrize("field", ["title", "body"])
def test_no_pr_field_reaches_the_alert_match(field):
    """§5.7's actual rule: the match is computed from the alerts API and the
    parsed package list, and never consults PR text."""
    fx, ups = updates("csa-wrangler-pr28.json")
    fx["pr"][field] = FAKE_BANNER["content"]
    assert match_alerts(ALERTS_NONE, ups) == []


def test_an_alert_the_pr_does_not_fix_produces_no_banner():
    """#29 bumps anthropic. The boto3 alert is real but unrelated, so no banner
    — the banner claims the PR *fixes* something."""
    fx, ups = updates("csa-wrangler-pr29.json")
    assert match_alerts(ALERTS_BOTO3, ups) == []
    assert "Security update" not in comment([], fx)


def test_a_pr_below_the_patched_version_produces_no_banner():
    """#10 raises boto3 only to >=1.43.42; the fix landed in 1.43.50."""
    fx, ups = updates("csa-wrangler-pr10.json")
    assert match_alerts(ALERTS_BOTO3, ups) == []

    _, reaching = updates("csa-wrangler-pr28.json")
    assert match_alerts(ALERTS_BOTO3, reaching), \
        "control: the same alert must match the PR that does reach 1.43.50"
