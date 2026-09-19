"""Tests for supersede detection (SPEC.md §5.6).

Driven by the real PRs, since S5 showed the spec's own examples were wrong about
which ones overlap.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from common.dependabot import parse_pr  # noqa: E402
from common.supersede import PRUpdates, scan, supersedes_for  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "real"


def pr_updates(fixture: str) -> PRUpdates:
    fx = json.loads((FIXTURES / fixture).read_text())
    parsed = parse_pr(fx["commits"][0]["message"], fx["changed_files"])
    return PRUpdates(number=fx["pr"]["number"], updates=parsed.updates)


def test_higher_target_supersedes_lower():
    """#28 raises boto3 to >=1.43.69; #10 only to >=1.43.42, same directory."""
    v = scan([pr_updates("csa-wrangler-pr10.json"), pr_updates("csa-wrangler-pr28.json")])
    assert v[10].by == [28]
    assert v[10].fully
    assert v[28].supersessions == []


def test_equal_target_breaks_the_tie_on_pr_number():
    """#26 and #27 both bump recipe-scrapers to 15.12.0 in /scripts."""
    v = scan([pr_updates("csa-wrangler-pr26.json"), pr_updates("csa-wrangler-pr27.json")])
    assert v[26].by == [27]
    assert v[26].fully, "#26 is only recipe-scrapers, so it is fully superseded"
    assert v[27].supersessions == [], "#27 also has pytest, which nothing supersedes"


def test_partially_superseded_group_pr():
    """#27 is pytest + recipe-scrapers; only recipe-scrapers is covered by #26's
    successor set, so a group PR can be partly superseded."""
    v = scan([pr_updates("csa-wrangler-pr26.json"), pr_updates("csa-wrangler-pr27.json")])
    assert v[27].total_packages == 2
    assert not v[27].fully


def test_different_directories_do_not_supersede():
    """The negative case §12 wanted. #10/#28 share a directory, so it has to be
    synthesized: move one to the repo root."""
    a = pr_updates("csa-wrangler-pr10.json")
    b = pr_updates("csa-wrangler-pr28.json")
    for u in b.updates:
        u.manifest = "requirements.txt"
        u.directory = "/"
    v = scan([a, b])
    assert v[10].supersessions == []
    assert v[28].supersessions == []


def test_unrelated_prs_do_not_interact():
    v = scan([pr_updates("csa-wrangler-pr7.json"), pr_updates("csa-wrangler-pr29.json")])
    assert all(not verdict.supersessions for verdict in v.values())


def test_actions_bumps_across_prs():
    a = pr_updates("csa-wrangler-pr7.json")   # checkout 4 -> 7
    b = PRUpdates(number=99, updates=[u for u in pr_updates("csa-wrangler-pr7.json").updates])
    for u in b.updates:
        u.to_version, u.to_spec = "8", "v8"
    v = scan([a, b])
    assert v[7].by == [99]


def test_supersedes_for_reports_the_other_side():
    v = scan([pr_updates("csa-wrangler-pr10.json"), pr_updates("csa-wrangler-pr28.json")])
    assert supersedes_for(28, v) == [(10, "boto3")]
    assert supersedes_for(10, v) == []


def test_three_way_picks_the_newest():
    a = pr_updates("csa-wrangler-pr10.json")           # >=1.43.42
    b = pr_updates("csa-wrangler-pr28.json")           # >=1.43.69
    c = PRUpdates(number=99, updates=[u for u in pr_updates("csa-wrangler-pr28.json").updates])
    for u in c.updates:
        u.to_version, u.to_spec = "1.44.0", ">=1.44.0"
    v = scan([a, b, c])
    assert v[10].by == [99]
    assert v[28].by == [99]
    assert v[99].supersessions == []


def test_all_eight_real_prs_together():
    """The real state of both repos. Only the two known pairs should fire."""
    prs = [pr_updates(f.name) for f in sorted(FIXTURES.glob("csa-wrangler-*.json"))]
    v = scan(prs)
    fired = {n: verdict.by for n, verdict in v.items() if verdict.supersessions}
    assert fired == {10: [28], 26: [27]}
