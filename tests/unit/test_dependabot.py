"""Tests for the Dependabot PR parser, driven by the 8 real snapshotted PRs.

These encode the S5 findings: the trailer has no directory, no `from` and no
ecosystem; `update-type` is missing on every range update; and
`dependency-version` contradicts the patch on #10. If any of those assumptions
regress, the floor silently computes on the wrong inputs.
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from common.dependabot import (  # noqa: E402
    Update, directory_of, ecosystem_for, normalize, parse_pr, parse_trailer,
)

FIXTURES = ROOT / "tests" / "fixtures" / "real"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def parse_fixture(name: str):
    fx = load(name)
    return parse_pr(fx["commits"][0]["message"], fx["changed_files"])


def one(result, pkg: str) -> Update:
    hits = [u for u in result.updates if normalize(u.name, u.ecosystem) == pkg]
    assert len(hits) == 1, f"expected exactly one {pkg}, got {[u.name for u in result.updates]}"
    return hits[0]


# ── ecosystem and directory derivation (F1) ──────────────────────────────────


@pytest.mark.parametrize("path,eco", [
    ("requirements.txt", "pip"),
    ("requirements-dev.txt", "pip"),
    ("scripts/requirements.txt", "pip"),
    ("pyproject.toml", "pip"),
    (".github/workflows/ci.yml", "actions"),
    ("Dockerfile", "docker"),
    ("src/planner/app.py", None),
    ("README.md", None),
])
def test_ecosystem_from_path(path, eco):
    assert ecosystem_for(path) == eco


@pytest.mark.parametrize("path,directory", [
    ("requirements.txt", "/"),
    ("requirements-dev.txt", "/"),
    ("scripts/requirements.txt", "/scripts"),
    (".github/workflows/ci.yml", "/"),
])
def test_directory_from_path(path, directory):
    assert directory_of(path) == directory


def test_pep503_normalization():
    assert normalize("recipe-scrapers", "pip") == "recipe-scrapers"
    assert normalize("recipe_scrapers", "pip") == "recipe-scrapers"
    assert normalize("Recipe.Scrapers", "pip") == "recipe-scrapers"


# ── the trailer itself ───────────────────────────────────────────────────────


def test_trailer_parses_on_all_eight_real_prs():
    for f in sorted(FIXTURES.glob("*.json")):
        fx = json.loads(f.read_text())
        entries = parse_trailer(fx["commits"][0]["message"])
        assert entries, f"{f.name}: no trailer"
        assert all(e.get("dependency-name") for e in entries), f.name


def test_trailer_terminator_is_the_yaml_end_marker():
    """A parser that stops at the first column-0 line gets nothing, because the
    sequence entries start at column 0. This is the bug the S5 probe hit."""
    msg = (
        "deps: bump x\n\n---\nupdated-dependencies:\n"
        "- dependency-name: x\n  dependency-version: '2'\n"
        "...\n\nSigned-off-by: dependabot[bot]\n"
    )
    entries = parse_trailer(msg)
    assert entries == [{"dependency-name": "x", "dependency-version": "2"}]


def test_missing_trailer_is_unparseable():
    r = parse_pr("just a commit message", [
        {"filename": "requirements.txt", "patch": "-boto3==1.0\n+boto3==1.1\n"}])
    assert r.unparseable


# ── real PRs ─────────────────────────────────────────────────────────────────


def test_pr29_range_update_takes_versions_from_the_patch():
    """#29: anthropic >=0.116.0 -> >=0.121.0, a range with no update-type."""
    r = parse_fixture("csa-wrangler-pr29.json")
    u = one(r, "anthropic")
    assert (u.directory, u.ecosystem) == ("/scripts", "pip")
    assert u.manifest == "scripts/requirements.txt"
    assert u.from_version == "0.116.0"
    assert u.to_version == "0.121.0"
    assert u.is_range
    assert u.update_type is None, "S5/F2: range updates carry no update-type"


def test_pr10_patch_beats_the_trailers_dependency_version():
    """S5/F5: the trailer says 1.43.34, the patch says >=1.43.42."""
    fx = load("csa-wrangler-pr10.json")
    trailer = parse_trailer(fx["commits"][0]["message"])
    assert trailer[0]["dependency-version"] == "1.43.34"

    u = one(parse_fixture("csa-wrangler-pr10.json"), "boto3")
    assert u.to_version == "1.43.42", "the patch must win"
    assert u.from_version == "1.34"


def test_pr10_and_pr28_share_a_directory():
    """S5/F3: the spec claimed these were in different directories. They are
    both scripts/requirements.txt, which makes them a supersede pair."""
    a = one(parse_fixture("csa-wrangler-pr10.json"), "boto3")
    b = one(parse_fixture("csa-wrangler-pr28.json"), "boto3")
    assert a.directory == b.directory == "/scripts"
    assert a.key() == b.key()
    assert (a.to_version, b.to_version) == ("1.43.42", "1.43.69")


def test_pr27_is_multi_directory_and_excludes_boto3():
    """S5/F4: #27 is pytest + recipe-scrapers, across two directories."""
    r = parse_fixture("csa-wrangler-pr27.json")
    assert {normalize(u.name, "pip") for u in r.updates} == {"pytest", "recipe-scrapers"}
    assert one(r, "pytest").directory == "/"
    assert one(r, "recipe-scrapers").directory == "/scripts"


def test_pr26_and_pr27_collide_on_recipe_scrapers_at_the_same_version():
    """The equal-target tie-break case that replaced the planned negative."""
    a = one(parse_fixture("csa-wrangler-pr26.json"), "recipe-scrapers")
    b = one(parse_fixture("csa-wrangler-pr27.json"), "recipe-scrapers")
    assert a.key() == b.key()
    assert a.to_version == b.to_version == "15.12.0"


@pytest.mark.parametrize("fixture,action,frm,to", [
    ("csa-wrangler-pr7.json", "actions/checkout", "4", "7"),
    ("csa-wrangler-pr20.json", "actions/setup-python", "6", "7"),
])
def test_actions_bumps(fixture, action, frm, to):
    r = parse_fixture(fixture)
    u = one(r, action)
    assert u.ecosystem == "actions"
    assert u.directory == "/"
    assert (u.from_version, u.to_version) == (frm, to)
    assert not u.is_range


def test_pr6_group_of_seven():
    r = parse_fixture("calendar-digest-pr6.json")
    assert len(r.updates) == 7
    assert all(u.group == "python-deps" for u in r.updates)
    # the group spans both manifests
    assert {u.manifest for u in r.updates} == {"requirements.txt", "requirements-dev.txt"}
    assert all(u.from_version and u.to_version for u in r.updates)


def test_every_real_pr_parses_without_unparseable():
    for f in sorted(FIXTURES.glob("*.json")):
        r = parse_fixture(f.name)
        assert r.updates, f.name
        assert not r.unparseable, f"{f.name}: {r.reasons}"
        for u in r.updates:
            assert u.to_version, f"{f.name}: {u.name} has no target version"
            assert u.directory.startswith("/"), f"{f.name}: {u.directory}"
