"""Detect superseded Dependabot PRs (SPEC.md §5.6).

Entirely deterministic Tier 1 logic. The model is not involved and cannot be:
PR numbers and package names come from GitHub API fields and parsed trailers,
which is what makes `#N` the only link Kinglet ever emits.

Dependabot closes its own superseded PRs within one update config. It misses the
cross-config cases — a group PR against a single-package PR, a security update
against a version update, an old PR left open after a config change — and those
are exactly what this covers.

Superseding is about merge hygiene, not risk. A superseded PR keeps its label.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from packaging.version import InvalidVersion, Version

from .dependabot import Update


@dataclass
class PRUpdates:
    """One open Dependabot PR, reduced to what the match rule needs."""

    number: int
    updates: list[Update]


@dataclass
class Supersession:
    """`package` in `pr` is superseded by `by_pr`."""

    pr: int
    package: str
    directory: str
    by_pr: int


@dataclass
class Verdict:
    pr: int
    supersessions: list[Supersession] = field(default_factory=list)
    total_packages: int = 0

    @property
    def fully(self) -> bool:
        return bool(self.supersessions) and len(
            {(s.package, s.directory) for s in self.supersessions}) >= self.total_packages

    @property
    def by(self) -> list[int]:
        return sorted({s.by_pr for s in self.supersessions})


def _version(update: Update) -> Version | None:
    raw = update.to_version
    if not raw:
        return None
    try:
        return Version(str(raw).lstrip("v"))
    except InvalidVersion:
        return None


def _beats(a: Update, a_pr: int, b: Update, b_pr: int) -> bool:
    """Does (a, a_pr) supersede (b, b_pr)? Assumes the keys already match."""
    va, vb = _version(a), _version(b)
    if va is None or vb is None:
        return False
    if va != vb:
        return va > vb
    # §5.6: on an equal target, the higher PR number wins. This is the
    # csa-wrangler #26/#27 case, where both bump recipe-scrapers to 15.12.0.
    return a_pr > b_pr


def scan(prs: list[PRUpdates]) -> dict[int, Verdict]:
    """Verdicts for every PR in `prs`, keyed by PR number.

    The match rule (§5.6): same ecosystem, same directory, same normalized name,
    and a strictly newer target — or an equal target and a higher PR number.
    """
    verdicts = {p.number: Verdict(pr=p.number, total_packages=len(
        {u.key() for u in p.updates})) for p in prs}

    for x in prs:
        for xu in x.updates:
            best: tuple[int, Update] | None = None
            for y in prs:
                if y.number == x.number:
                    continue
                for yu in y.updates:
                    if yu.key() != xu.key():
                        continue
                    if not _beats(yu, y.number, xu, x.number):
                        continue
                    if best is None or _beats(yu, y.number, best[1], best[0]):
                        best = (y.number, yu)
            if best is not None:
                verdicts[x.number].supersessions.append(Supersession(
                    pr=x.number,
                    package=xu.name,
                    directory=xu.directory,
                    by_pr=best[0],
                ))

    return verdicts


def supersedes_for(pr: int, verdicts: dict[int, Verdict]) -> list[tuple[int, str]]:
    """`(older PR, package)` pairs that `pr` supersedes — for its own comment."""
    out = []
    for other in verdicts.values():
        for s in other.supersessions:
            if s.by_pr == pr:
                out.append((other.pr, s.package))
    return sorted(set(out))
