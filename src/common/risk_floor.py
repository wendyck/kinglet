"""The deterministic risk floor (SPEC.md §6).

Computed in Tier 1, per package, then maxed. The model may raise a package above
its floor and may never lower it, so this module — not the reviewer — decides the
worst case for every PR.

Two rules about inputs, from the S5 and S1–S4 spikes:

- **Compare parsed version pairs.** `update-type` is absent on every range
  update, including the pre-1.0 case that is the flagship `high`, so it is only
  ever a cross-check. A disagreement between a present `update-type` and the
  parsed pair means we have misread something, and misreading is `high`.
- **Decide production-vs-tooling by manifest path**, never by the trailer's
  `dependency-type`, which reports `direct:production` for packages that live in
  `scripts/`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from packaging.version import InvalidVersion, Version

from .dependabot import Update, normalize

LOW, MEDIUM, HIGH = "low", "medium", "high"
_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}


def worst(*levels: str) -> str:
    return max(levels, key=lambda l: _ORDER[l], default=LOW)


# Manifests that hold tooling rather than deployed code (§6, F5).
TOOLING_PATH = re.compile(r"(^|/)(scripts|tests|tools|dev)/|requirements-dev\.txt$|(^|/)dev-requirements\.txt$")


def is_production_manifest(manifest: str) -> bool:
    return not TOOLING_PATH.search(manifest)


@dataclass
class Floor:
    level: str = LOW
    reasons: list[str] = field(default_factory=list)

    def raise_to(self, level: str, reason: str) -> None:
        if reason not in self.reasons:
            self.reasons.append(reason)
        self.level = worst(self.level, level)


def _parse(v: str | None, ecosystem: str) -> Version | None:
    if not v:
        return None
    text = v.strip().lstrip("v")
    try:
        return Version(text)
    except InvalidVersion:
        # Actions are often bare majors ("7") or non-PEP440 tags.
        m = re.match(r"^(\d+(?:\.\d+)*)", text)
        if not m:
            return None
        try:
            return Version(m.group(1))
        except InvalidVersion:
            return None


def _part(v: Version, i: int) -> int:
    return v.release[i] if len(v.release) > i else 0


def bump_kind(frm: Version | None, to: Version | None) -> str | None:
    """'major' | 'minor' | 'patch' | 'none', or None if not comparable."""
    if frm is None or to is None:
        return None
    if to <= frm:
        return "none"
    if _part(to, 0) != _part(frm, 0):
        return "major"
    if _part(to, 1) != _part(frm, 1):
        return "minor"
    return "patch"


def _update_type_kind(update_type: str | None) -> str | None:
    if not update_type:
        return None
    if update_type.endswith("semver-major"):
        return "major"
    if update_type.endswith("semver-minor"):
        return "minor"
    if update_type.endswith("semver-patch"):
        return "patch"
    return None


def package_floor(u: Update, repo_config: dict | None = None) -> Floor:
    """The floor for one package in one directory."""
    cfg = repo_config or {}
    frameworks = {normalize(n, u.ecosystem) for n in cfg.get("frameworks", []) or []}
    watchlist = {normalize(n, u.ecosystem) for n in cfg.get("watchlist", []) or []}
    name = normalize(u.name, u.ecosystem)

    floor = Floor()

    frm = _parse(u.from_version, u.ecosystem)
    to = _parse(u.to_version, u.ecosystem)
    kind = bump_kind(frm, to)

    if u.is_new:
        floor.raise_to(HIGH, "NEW_DEPENDENCY")
        return floor

    if kind is None:
        floor.raise_to(HIGH, "UNPARSEABLE")
        return floor

    # `update-type`, when present, must agree with what we parsed.
    declared = _update_type_kind(u.update_type)
    if declared and declared != kind:
        floor.raise_to(HIGH, "UNPARSEABLE")
        return floor

    if u.ecosystem == "actions":
        if kind == "major":
            floor.raise_to(MEDIUM, "ACTION_MAJOR")
            # A tag reference plus a major change means the runtime can move
            # under you without the SHA changing.
            if u.to_spec and not re.fullmatch(r"[0-9a-f]{40}", u.to_spec.strip()):
                floor.raise_to(MEDIUM, "ACTION_TAG_REF")
        return floor

    # pip (and, for now, anything else that parses)
    if kind == "major":
        floor.raise_to(HIGH, "MAJOR_BUMP")
    elif kind == "minor":
        if frm is not None and _part(frm, 0) == 0:
            floor.raise_to(HIGH, "ZERO_X_MINOR")
        if name in frameworks:
            floor.raise_to(HIGH, "FRAMEWORK")
        if name in watchlist:
            floor.raise_to(MEDIUM, "WATCHLIST")
        if is_production_manifest(u.manifest):
            floor.raise_to(MEDIUM, "PRODUCTION_MINOR")
    else:  # patch or none
        if name in frameworks and kind == "patch":
            pass  # §6 lists frameworks for minor or major only
        floor.raise_to(LOW, "PATCH" if kind == "patch" else "NO_CHANGE")

    if u.is_range and kind in ("minor", "patch"):
        floor.reasons.append("RANGE_FLOOR_ONLY")

    return floor


def overall_floor(floors: dict, global_reasons: list[str] | None = None) -> Floor:
    """Max over every package, plus PR-wide reasons (§5.2 steps 3 and 7)."""
    out = Floor()
    for reason in global_reasons or []:
        out.raise_to(HIGH, reason)
    for f in floors.values():
        out.level = worst(out.level, f.level)
    return out
