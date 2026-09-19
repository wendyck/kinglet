"""Tests for §7.2 validation — the checks that make an untrusted result usable."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from common.sanitize import WITHHELD  # noqa: E402
from common.validate import (  # noqa: E402
    ResultRejected, apply_output_guardrail, cross_check, floor_reason_summary,
    validate_schema,
)

META = {
    "overall_floor": "high",
    "global_reasons": [],
    "file_index": {"scripts/add_recipes.py": 12, "requirements.txt": 3},
    "packages": [{"name": "anthropic", "directory": "/scripts",
                  "floor": "high", "floor_reasons": ["ZERO_X_MINOR"]}],
}


def result(**kw):
    pkg = {"name": "anthropic", "directory": "/scripts", "risk": "low",
           "verdict": "SAFE", "usage": "used", "reason_codes": [],
           "evidence": [{"path": "scripts/add_recipes.py", "line": 2}]}
    pkg.update(kw.pop("package", {}))
    base = {"schema_version": 1, "overall_risk": "low", "packages": [pkg], "notes": "fine"}
    base.update(kw)
    return base


# ── schema ───────────────────────────────────────────────────────────────────


def test_valid_result_passes_schema():
    validate_schema(result())


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(schema_version=2),
    lambda r: r.update(overall_risk="critical"),
    lambda r: r["packages"][0].update(verdict="LGTM"),
    lambda r: r["packages"][0].update(usage="maybe"),
    lambda r: r["packages"][0].update(reason_codes=["MADE_UP_CODE"]),
    lambda r: r["packages"][0].update(extra="field"),
    lambda r: r.update(notes="x" * 601),
    lambda r: r["packages"][0].update(
        evidence=[{"path": "a", "line": 1} for _ in range(6)]),
])
def test_schema_violations_are_rejected(mutate):
    r = result()
    mutate(r)
    with pytest.raises(ResultRejected):
        validate_schema(r)


# ── the package set must match exactly ───────────────────────────────────────


def test_dropping_a_package_is_rejected():
    with pytest.raises(ResultRejected, match="missing"):
        cross_check(result(packages=[]), META)


def test_inventing_a_package_is_rejected():
    r = result()
    r["packages"].append({"name": "ghost", "directory": "/", "risk": "low",
                          "verdict": "SAFE", "usage": "used",
                          "reason_codes": [], "evidence": []})
    with pytest.raises(ResultRejected, match="extra"):
        cross_check(r, META)


def test_renaming_a_package_is_rejected():
    with pytest.raises(ResultRejected):
        cross_check(result(package={"name": "anthropiq"}), META)


def test_moving_a_package_to_another_directory_is_rejected():
    with pytest.raises(ResultRejected):
        cross_check(result(package={"directory": "/"}), META)


# ── evidence ─────────────────────────────────────────────────────────────────


def test_valid_evidence_is_kept():
    out = cross_check(result(), META)
    assert out.packages[0].evidence == [{"path": "scripts/add_recipes.py", "line": 2}]
    assert out.packages[0].verdict == "SAFE"


def test_repo_prefix_is_stripped():
    out = cross_check(result(package={
        "evidence": [{"path": "repo/scripts/add_recipes.py", "line": 2}]}), META)
    assert out.packages[0].evidence[0]["path"] == "scripts/add_recipes.py"


def test_unknown_file_is_dropped_and_verdict_becomes_unknown():
    out = cross_check(result(package={
        "evidence": [{"path": "scripts/nonexistent.py", "line": 1}]}), META)
    assert out.packages[0].evidence == []
    assert out.packages[0].verdict == "UNKNOWN"
    assert out.warnings


def test_line_past_end_of_file_is_dropped():
    out = cross_check(result(package={
        "evidence": [{"path": "scripts/add_recipes.py", "line": 900}]}), META)
    assert out.packages[0].evidence == []
    assert out.packages[0].verdict == "UNKNOWN"


def test_traversal_in_evidence_is_dropped():
    out = cross_check(result(package={
        "evidence": [{"path": "../../etc/passwd", "line": 1}]}), META)
    assert out.packages[0].evidence == []


def test_partially_valid_evidence_still_downgrades_the_verdict():
    """One fabricated citation makes the whole analysis suspect."""
    out = cross_check(result(package={"evidence": [
        {"path": "scripts/add_recipes.py", "line": 2},
        {"path": "scripts/ghost.py", "line": 1}]}), META)
    assert len(out.packages[0].evidence) == 1
    assert out.packages[0].verdict == "UNKNOWN"


# ── risk is max(floor, model) ────────────────────────────────────────────────


def test_model_cannot_lower_a_package_below_its_floor():
    out = cross_check(result(package={"risk": "low"}), META)
    assert out.packages[0].risk == "high"


def test_model_can_raise_above_the_floor():
    meta = {**META, "overall_floor": "low",
            "packages": [{"name": "anthropic", "directory": "/scripts",
                          "floor": "low", "floor_reasons": []}]}
    out = cross_check(result(package={"risk": "high"}, overall_risk="high"), meta)
    assert out.packages[0].risk == "high" and out.overall_risk == "high"


def test_overall_cannot_drop_below_the_global_floor():
    meta = {**META, "overall_floor": "high",
            "packages": [{"name": "anthropic", "directory": "/scripts",
                          "floor": "low", "floor_reasons": []}]}
    assert cross_check(result(overall_risk="low"), meta).overall_risk == "high"


def test_floor_reasons_are_merged_into_the_row():
    out = cross_check(result(package={"reason_codes": ["IMPORT_ONLY_IN_SCRIPTS"]}), META)
    assert "ZERO_X_MINOR" in out.packages[0].reason_codes
    assert "IMPORT_ONLY_IN_SCRIPTS" in out.packages[0].reason_codes


def test_tier1_only_reason_code_from_the_model_is_stripped():
    """§5.6: SUPERSEDED_ELSEWHERE is Tier 1's to set, never the model's."""
    out = cross_check(result(package={"reason_codes": ["SUPERSEDED_ELSEWHERE"]}), META)
    assert "SUPERSEDED_ELSEWHERE" not in out.packages[0].reason_codes
    assert any("Tier 1-only" in w for w in out.warnings)


# ── notes ────────────────────────────────────────────────────────────────────


def test_notes_are_sanitized_during_cross_check():
    out = cross_check(result(notes="see ![x](https://attacker.invalid/p.png)"), META)
    assert "attacker.invalid" not in out.notes and "![" not in out.notes


def test_blocked_notes_are_withheld_and_raise_the_risk():
    meta = {**META, "overall_floor": "low",
            "packages": [{"name": "anthropic", "directory": "/scripts",
                          "floor": "low", "floor_reasons": []}]}
    out = cross_check(result(), meta)
    assert out.overall_risk == "low"
    out = apply_output_guardrail(out, lambda text: (True, ["CredentialDisclosure"]))
    assert out.notes == WITHHELD
    assert out.overall_risk == "medium"


def test_clean_notes_pass_the_guardrail_untouched():
    out = apply_output_guardrail(cross_check(result(), META), lambda t: (False, []))
    assert out.notes == "fine"


def test_floor_reason_summary_groups_by_code():
    summary = floor_reason_summary(META)
    assert summary == {"ZERO_X_MINOR": ["anthropic"]}
