"""Tests for the deterministic risk floor (SPEC.md §6).

The floor is the one thing prompt injection cannot move, so these tests are
about the *rules*, not about any particular PR. The real fixtures at the bottom
are the regression guard for the semantic/importance split (§6).
"""

import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from common.dependabot import Update, parse_pr  # noqa: E402
from common.risk_floor import (  # noqa: E402
    HIGH, LOW, MEDIUM, Floor, bump_kind, is_production_manifest, overall_floor,
    package_floor, worst,
)

FIXTURES = ROOT / "tests" / "fixtures" / "real"
CONFIG = yaml.safe_load((ROOT / "config" / "repos.yml").read_text())

CSA = CONFIG["repos"]["wendyck/csa-wrangler"]
CAL = CONFIG["repos"]["wendyck/calendar-digest"]


def pip(name, frm, to, manifest="requirements.txt", **kw) -> Update:
    to_spec = kw.pop("to_spec", f"=={to}")
    return Update(name=name, ecosystem="pip", directory="/", manifest=manifest,
                  from_spec=f"=={frm}", to_spec=to_spec,
                  from_version=frm, to_version=to,
                  is_range=to_spec.startswith(">="), **kw)


def action(name, frm, to, **kw) -> Update:
    return Update(name=name, ecosystem="actions", directory="/",
                  manifest=".github/workflows/ci.yml",
                  from_spec=f"v{frm}", to_spec=kw.pop("to_spec", f"v{to}"),
                  from_version=frm, to_version=to, is_range=False, **kw)


# ── helpers ──────────────────────────────────────────────────────────────────


def test_worst_orders_levels():
    assert worst(LOW, HIGH, MEDIUM) == HIGH
    assert worst(LOW, LOW) == LOW
    assert worst() == LOW


@pytest.mark.parametrize("frm,to,kind", [
    ("1.0.0", "2.0.0", "major"), ("1.2.0", "1.3.0", "minor"),
    ("1.2.3", "1.2.4", "patch"), ("0.116.0", "0.121.0", "minor"),
    ("1.34", "1.43.42", "minor"), ("4", "7", "major"), ("2.0.0", "1.0.0", "none"),
])
def test_bump_kind(frm, to, kind):
    from common.risk_floor import _parse
    assert bump_kind(_parse(frm, "pip"), _parse(to, "pip")) == kind


@pytest.mark.parametrize("manifest,prod", [
    ("requirements.txt", True), ("pyproject.toml", True),
    ("src/planner/requirements.txt", True),
    ("scripts/requirements.txt", False), ("requirements-dev.txt", False),
    ("tests/requirements.txt", False),
])
def test_production_manifest_is_decided_by_path(manifest, prod):
    assert is_production_manifest(manifest) is prod


# ── the §6 table ─────────────────────────────────────────────────────────────


def test_major_pip_bump_is_high():
    assert package_floor(pip("requests", "2.0.0", "3.0.0")).level == HIGH


def test_pre_1_0_minor_is_high():
    f = package_floor(pip("anthropic", "0.116.0", "0.121.0"))
    assert f.level == HIGH and "ZERO_X_MINOR" in f.reasons


def test_pre_1_0_patch_is_not_high():
    assert package_floor(pip("anthropic", "0.116.0", "0.116.1")).level == LOW


def test_framework_minor_is_high():
    f = package_floor(pip("boto3", "1.34.0", "1.43.0"), CSA)
    assert f.level == HIGH and "FRAMEWORK" in f.reasons


def test_watchlist_minor_is_medium():
    f = package_floor(pip("beautifulsoup4", "4.12.0", "4.13.0",
                          manifest="scripts/requirements.txt"), CSA)
    assert f.level == MEDIUM and "WATCHLIST" in f.reasons


def test_production_minor_is_medium_even_off_the_lists():
    f = package_floor(pip("httpx", "0.27.0", "0.28.0"), CSA)
    assert f.level == HIGH  # 0.x minor dominates
    f2 = package_floor(pip("httpx", "1.27.0", "1.28.0"), CSA)
    assert f2.level == MEDIUM and "PRODUCTION_MINOR" in f2.reasons


def test_dev_manifest_minor_is_low():
    f = package_floor(pip("pytest", "9.0.3", "9.1.1", manifest="requirements-dev.txt"), CSA)
    assert f.level == LOW


def test_patch_is_low():
    assert package_floor(pip("moto", "5.2.1", "5.2.3"), CAL).level == LOW


def test_new_dependency_is_high():
    u = pip("brand-new", "0", "1.0.0")
    u.from_spec, u.from_version, u.is_new = None, None, True
    f = package_floor(u)
    assert f.level == HIGH and "NEW_DEPENDENCY" in f.reasons


def test_actions_major_is_medium_not_high():
    f = package_floor(action("actions/checkout", "4", "7"))
    assert f.level == MEDIUM and "ACTION_MAJOR" in f.reasons


def test_actions_major_by_tag_adds_a_reason():
    f = package_floor(action("actions/checkout", "4", "7"))
    assert "ACTION_TAG_REF" in f.reasons


def test_actions_major_pinned_by_sha_has_no_tag_reason():
    sha = "a" * 40
    f = package_floor(action("actions/checkout", "4", "7", to_spec=sha))
    assert "ACTION_TAG_REF" not in f.reasons


def test_actions_minor_is_low():
    assert package_floor(action("actions/checkout", "4.1", "4.2")).level == LOW


# ── the update-type cross-check (S5/F2) ──────────────────────────────────────


def test_update_type_absent_is_fine():
    f = package_floor(pip("anthropic", "0.116.0", "0.121.0", update_type=None))
    assert f.level == HIGH and "UNPARSEABLE" not in f.reasons


def test_update_type_agreeing_is_fine():
    f = package_floor(pip("requests", "2.1.0", "2.2.0",
                          update_type="version-update:semver-minor"), CSA)
    assert "UNPARSEABLE" not in f.reasons


def test_update_type_disagreeing_is_high_unparseable():
    """If Dependabot says major and the patch says patch, we misread something."""
    f = package_floor(pip("requests", "2.1.0", "2.1.1",
                          update_type="version-update:semver-major"))
    assert f.level == HIGH and "UNPARSEABLE" in f.reasons


def test_unparseable_versions_are_high():
    u = pip("weird", "1.0", "1.1")
    u.from_version, u.to_version = None, None
    assert package_floor(u).level == HIGH


# ── global reasons ───────────────────────────────────────────────────────────


def test_global_reasons_raise_the_overall_floor():
    floors = {("pip", "/", "moto"): Floor(LOW, ["PATCH"])}
    assert overall_floor(floors, []).level == LOW
    for reason in ("UNEXPECTED_CHANGE", "UNPARSEABLE", "PROMPT_ATTACK_SUSPECTED"):
        assert overall_floor(floors, [reason]).level == HIGH


def test_overall_is_the_max_over_packages():
    floors = {
        ("pip", "/", "a"): Floor(LOW, []),
        ("pip", "/", "b"): Floor(MEDIUM, []),
        ("pip", "/", "c"): Floor(LOW, []),
    }
    assert overall_floor(floors).level == MEDIUM


# ── real fixtures ────────────────────────────────────────────────────────────


def floor_for(fixture: str):
    fx = json.loads((FIXTURES / fixture).read_text())
    rc = CONFIG["repos"].get(fx["repo"], {})
    r = parse_pr(fx["commits"][0]["message"], fx["changed_files"])
    floors = {u.key(): package_floor(u, rc) for u in r.updates}
    return overall_floor(floors, r.reasons), floors, r


@pytest.mark.parametrize("fixture,expected", [
    ("csa-wrangler-pr7.json", MEDIUM),    # checkout 4->7
    ("csa-wrangler-pr20.json", MEDIUM),   # setup-python 6->7
    ("csa-wrangler-pr29.json", HIGH),     # anthropic 0.x minor
])
def test_fixtures_where_6_and_12_agree(fixture, expected):
    assert floor_for(fixture)[0].level == expected


@pytest.mark.parametrize("fixture,expected", [
    ("csa-wrangler-pr10.json", MEDIUM),   # boto3 range, framework, softened
    ("csa-wrangler-pr28.json", MEDIUM),   # same
    ("csa-wrangler-pr26.json", MEDIUM),   # recipe-scrapers pinned, watchlist
    ("csa-wrangler-pr27.json", MEDIUM),   # dev group; recipe-scrapers drives it
    ("calendar-digest-pr6.json", HIGH),   # anthropic 0.x minor drives the group
])
def test_fixtures_resolved_by_the_semantic_importance_split(fixture, expected):
    assert floor_for(fixture)[0].level == expected


# ── range softening (§6) ─────────────────────────────────────────────────────


def test_range_softens_an_importance_rule():
    """A `>=` raise does not change what the build resolves, so 'this package
    matters here' drops one step."""
    pinned = package_floor(pip("boto3", "1.34.0", "1.43.0",
                               manifest="scripts/requirements.txt"), CSA)
    ranged = package_floor(pip("boto3", "1.34.0", "1.43.0",
                               manifest="scripts/requirements.txt",
                               to_spec=">=1.43.0"), CSA)
    assert pinned.level == HIGH and "FRAMEWORK" in pinned.reasons
    assert ranged.level == MEDIUM
    assert {"FRAMEWORK", "RANGE_FLOOR_ONLY", "RANGE_SOFTENED"} <= set(ranged.reasons)


def test_range_does_not_soften_a_semantic_rule():
    """0.x minors are breaking by convention; the raised floor still crosses
    that boundary. This is #29, and it must stay high."""
    ranged = package_floor(pip("anthropic", "0.116.0", "0.121.0",
                               manifest="scripts/requirements.txt",
                               to_spec=">=0.121.0"), CSA)
    assert ranged.level == HIGH
    assert "ZERO_X_MINOR" in ranged.reasons
    assert "RANGE_SOFTENED" not in ranged.reasons


def test_range_crossing_a_major_is_not_softened():
    ranged = package_floor(pip("requests", "2.9.0", "3.0.0", to_spec=">=3.0.0"), CSA)
    assert ranged.level == HIGH and "MAJOR_BUMP" in ranged.reasons


def test_softening_never_goes_below_low():
    ranged = package_floor(pip("httpx", "1.1.0", "1.2.0",
                               manifest="scripts/requirements.txt",
                               to_spec=">=1.2.0"), CSA)
    assert ranged.level == LOW


def test_range_floor_only_is_recorded_even_when_it_does_not_cap():
    _, floors, r = floor_for("csa-wrangler-pr28.json")
    boto3 = next(f for k, f in floors.items() if k[2] == "boto3")
    assert "RANGE_FLOOR_ONLY" in boto3.reasons


def test_no_real_fixture_is_unparseable():
    for f in sorted(FIXTURES.glob("*.json")):
        overall, _, r = floor_for(f.name)
        assert "UNPARSEABLE" not in overall.reasons, f"{f.name}: {r.reasons}"


# ── SPEC §12 Phase 3: the real-fixture table, per package ────────────────────
#
# The overall level is asserted above. This pins the per-package levels and the
# reason codes the table names, because those are what drift silently: a config
# or rule change can keep every overall level identical while changing why.

SPEC_TABLE = {
    "csa-wrangler-pr7.json": {
        ("actions/checkout", "/"): (MEDIUM, {"ACTION_MAJOR", "ACTION_TAG_REF"}),
    },
    "csa-wrangler-pr20.json": {
        ("actions/setup-python", "/"): (MEDIUM, {"ACTION_MAJOR", "ACTION_TAG_REF"}),
    },
    "csa-wrangler-pr26.json": {
        ("recipe-scrapers", "/scripts"): (MEDIUM, {"WATCHLIST"}),
    },
    "csa-wrangler-pr27.json": {
        ("pytest", "/"): (LOW, set()),
        ("recipe-scrapers", "/scripts"): (MEDIUM, {"WATCHLIST"}),
    },
    "csa-wrangler-pr10.json": {
        ("boto3", "/scripts"): (MEDIUM, {"FRAMEWORK", "RANGE_FLOOR_ONLY", "RANGE_SOFTENED"}),
    },
    "csa-wrangler-pr28.json": {
        ("boto3", "/scripts"): (MEDIUM, {"FRAMEWORK", "RANGE_FLOOR_ONLY", "RANGE_SOFTENED"}),
    },
    "csa-wrangler-pr29.json": {
        ("anthropic", "/scripts"): (HIGH, {"ZERO_X_MINOR", "WATCHLIST", "RANGE_FLOOR_ONLY"}),
    },
}


@pytest.mark.parametrize("fixture", sorted(SPEC_TABLE))
def test_spec_table_package_levels_and_reasons(fixture):
    _, floors, parsed = floor_for(fixture)
    by_name = {(u.name, u.directory): floors[u.key()] for u in parsed.updates}

    expected = SPEC_TABLE[fixture]
    assert set(by_name) == set(expected), "the fixture's package set changed"
    for key, (level, reasons) in expected.items():
        got = by_name[key]
        assert got.level == level, f"{key}: {got.level} != {level} ({got.reasons})"
        assert reasons <= set(got.reasons), \
            f"{key}: missing {sorted(reasons - set(got.reasons))} from {got.reasons}"


def test_pr29_is_semantic_so_the_range_does_not_soften_it():
    """SPEC §12: "#29 … high, ZERO_X_MINOR — semantic, so not softened".

    #29 and #28 are both `>=` range raises. #28's floor comes from an importance
    rule and softens; #29's comes from a semantic rule and must not.
    """
    _, floors, parsed = floor_for("csa-wrangler-pr29.json")
    anthropic = floors[next(u.key() for u in parsed.updates if u.name == "anthropic")]
    assert "RANGE_FLOOR_ONLY" in anthropic.reasons, "it is still a range raise"
    assert "RANGE_SOFTENED" not in anthropic.reasons
    assert anthropic.level == HIGH

    _, floors28, parsed28 = floor_for("csa-wrangler-pr28.json")
    boto3 = floors28[next(u.key() for u in parsed28.updates if u.name == "boto3")]
    assert "RANGE_SOFTENED" in boto3.reasons, "control: an importance rule does soften"


def test_calendar_digest_pr6_is_driven_by_one_package_in_the_group():
    """SPEC §12 leaves #6 as "per-package, depends on the group contents".

    It is a 7-package group whose overall `high` comes from `anthropic` alone.
    If that package ever drops out, the group should not stay high by accident.
    """
    overall, floors, parsed = floor_for("calendar-digest-pr6.json")
    by_name = {u.name: floors[u.key()] for u in parsed.updates}
    assert len(by_name) == 7
    assert overall.level == HIGH

    assert by_name["anthropic"].level == HIGH
    assert "ZERO_X_MINOR" in by_name["anthropic"].reasons
    assert [n for n, f in by_name.items() if f.level == HIGH] == ["anthropic"]

    # The rest of the group is genuinely quieter, not incidentally so.
    assert by_name["boto3"].level == LOW
    assert {"google-api-python-client", "google-auth"} <= {
        n for n, f in by_name.items() if f.level == MEDIUM}
