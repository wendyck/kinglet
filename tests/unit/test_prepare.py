"""Tests for Prepare's decision logic (SPEC.md §5.2, §5.7).

The network and AWS parts are exercised end to end in Phase 1's deploy check;
what is unit-tested here is everything that decides *what* gets written — the
file allowlist, the evidence index, and the security-alert match rule, which
must never be influenced by PR text.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from common.dependabot import Update  # noqa: E402
from prepare.app import allowed_change, build_file_index, match_alerts  # noqa: E402


def pkg(name, directory="/scripts", manifest="scripts/requirements.txt",
        to_version="1.43.69", eco="pip") -> Update:
    return Update(name=name, ecosystem=eco, directory=directory, manifest=manifest,
                  from_spec=">=1.34", to_spec=f">={to_version}", from_version="1.34",
                  to_version=to_version, is_range=True)


def alert(name, *, eco="pip", manifest="scripts/requirements.txt", patched="1.43.0",
          ghsa="GHSA-aaaa-bbbb-cccc", severity="high", summary="A vulnerability"):
    return {
        "dependency": {"package": {"ecosystem": eco, "name": name},
                       "manifest_path": manifest},
        "security_vulnerability": {"first_patched_version": {"identifier": patched}},
        "security_advisory": {"ghsa_id": ghsa, "severity": severity, "summary": summary},
    }


# ── the manifest allowlist (§5.2 step 3) ─────────────────────────────────────


@pytest.mark.parametrize("path", [
    "requirements.txt", "requirements-dev.txt", "scripts/requirements.txt",
    "pyproject.toml", "poetry.lock", "uv.lock",
    ".github/workflows/ci.yml", ".github/workflows/deploy.yaml",
    "Dockerfile", "Dockerfile.dev",
])
def test_allowed_manifest_changes(path):
    assert allowed_change(path)


@pytest.mark.parametrize("path", [
    "src/planner/app.py", "README.md", ".github/workflows/../../evil.py",
    "setup.py", "Makefile", ".github/actions/custom/action.yml",
])
def test_changes_outside_the_allowlist(path):
    assert not allowed_change(path), f"{path} should not be allowed"


# ── the evidence index (§7.2) ────────────────────────────────────────────────


def test_file_index_counts_lines(tmp_path):
    (tmp_path / "a.py").write_text("one\ntwo\nthree\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.py").write_text("x\n")
    index = build_file_index(tmp_path)
    assert index == {"a.py": 3, "sub/b.py": 1}


def test_file_index_skips_binaries_and_git(tmp_path):
    (tmp_path / "ok.py").write_text("x\n")
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("secret\n")
    index = build_file_index(tmp_path)
    assert "ok.py" in index
    assert "blob.bin" not in index
    assert not any(k.startswith(".git/") for k in index)


def test_file_index_is_what_bounds_a_hallucinated_citation(tmp_path):
    """Finalize drops evidence past the line count; the index is the source."""
    (tmp_path / "short.py").write_text("one\ntwo\n")
    index = build_file_index(tmp_path)
    assert index["short.py"] == 2  # a claim of line 900 will be dropped


# ── the security-alert match rule (§5.7) ─────────────────────────────────────


def test_matching_alert_produces_a_banner_entry():
    out = match_alerts([alert("boto3")], [pkg("boto3")])
    assert len(out) == 1
    assert out[0]["ghsa_id"] == "GHSA-aaaa-bbbb-cccc"
    assert out[0]["severity"] == "high"


def test_no_match_for_a_different_package():
    assert match_alerts([alert("requests")], [pkg("boto3")]) == []


def test_no_match_when_the_target_is_below_the_patched_version():
    out = match_alerts([alert("boto3", patched="2.0.0")], [pkg("boto3", to_version="1.43.69")])
    assert out == []


def test_match_when_the_target_reaches_the_patched_version():
    out = match_alerts([alert("boto3", patched="1.43.0")], [pkg("boto3", to_version="1.43.69")])
    assert len(out) == 1


def test_name_normalization_is_applied():
    out = match_alerts([alert("Recipe_Scrapers")], [pkg("recipe-scrapers", to_version="15.12.0")])
    assert len(out) == 1


def test_directory_must_line_up():
    out = match_alerts(
        [alert("boto3", manifest="other/requirements.txt")],
        [pkg("boto3", directory="/scripts", manifest="scripts/requirements.txt")])
    assert out == []


def test_injected_security_text_cannot_produce_a_banner():
    """§5.7: the banner comes from the alerts API alone. No alerts, no banner,
    whatever the PR body claims."""
    assert match_alerts([], [pkg("boto3")]) == []


def test_unknown_ecosystem_is_ignored():
    assert match_alerts([alert("left-pad", eco="npm")], [pkg("left-pad")]) == []


def test_actions_ecosystem_alias_is_handled():
    out = match_alerts(
        [alert("actions/checkout", eco="github-actions",
               manifest=".github/workflows/ci.yml", patched="5")],
        [pkg("actions/checkout", directory="/", manifest=".github/workflows/ci.yml",
             to_version="7", eco="actions")])
    assert len(out) == 1
