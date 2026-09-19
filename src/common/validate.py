"""Validate the reviewer's output against meta (SPEC.md §7.2).

The reviewer is untrusted. Schema validation proves the JSON is well-formed; it
proves nothing about whether the claims are real. These cross-checks do that
work:

- the package set must match exactly, so the model cannot drop a risky package
  or invent one;
- every evidence citation must point at a file and line that actually exist,
  because a plausible-looking `file:line` is the cheapest possible fabrication;
- risk is `max(floor, model)` per package, which is the rule prompt injection
  cannot move.

A package whose evidence does not survive is not merely un-cited — its verdict
drops to `UNKNOWN`. Wrong evidence means the analysis behind it is unreliable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .risk_floor import LOW, MEDIUM, worst
from .sanitize import WITHHELD, sanitize_notes

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "result.schema.json"

# §7.1: Tier 1 sets this one, and the model must never claim it.
TIER1_ONLY_CODES = {"SUPERSEDED_ELSEWHERE"}


class ResultRejected(Exception):
    """The result cannot be trusted at all. Caller uses the §5.8 failure path."""


@dataclass
class ValidatedPackage:
    name: str
    directory: str
    risk: str
    verdict: str
    usage: str
    reason_codes: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    dropped_evidence: list[dict] = field(default_factory=list)


@dataclass
class ValidatedResult:
    packages: list[ValidatedPackage]
    overall_risk: str
    notes: str
    warnings: list[str] = field(default_factory=list)


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def validate_schema(result: dict) -> None:
    """Raise ResultRejected unless the result matches schemas/result.schema.json."""
    try:
        import jsonschema
    except ImportError as e:  # pragma: no cover - dependency is declared
        raise ResultRejected(f"jsonschema unavailable: {e}") from None
    try:
        jsonschema.validate(result, load_schema())
    except jsonschema.ValidationError as e:
        path = "/".join(str(p) for p in e.absolute_path) or "<root>"
        raise ResultRejected(f"schema violation at {path}: {e.message}") from None


def _norm_evidence_path(path: str) -> str:
    """Model paths are relative to /work, where the tree sits under `repo/`.

    The file index is relative to the tree itself, so strip the prefix. Also
    refuse anything that tries to climb out, which should be impossible given
    fs-readonly but costs nothing to check twice.
    """
    p = str(path).strip().lstrip("/")
    parts = PurePosixPath(p).parts
    if ".." in parts:
        return ""
    if parts and parts[0] == "repo":
        p = str(PurePosixPath(*parts[1:])) if len(parts) > 1 else ""
    return p


def cross_check(result: dict, meta: dict) -> ValidatedResult:
    """Apply §7.2 to a schema-valid result. Raises ResultRejected on mismatch."""
    warnings: list[str] = []

    meta_packages = {(p["name"], p["directory"]): p for p in meta.get("packages", [])}
    model_packages = {(p["name"], p["directory"]): p for p in result.get("packages", [])}

    missing = sorted(set(meta_packages) - set(model_packages))
    extra = sorted(set(model_packages) - set(meta_packages))
    if missing or extra:
        raise ResultRejected(
            f"package set mismatch; missing={missing} extra={extra}")

    file_index = meta.get("file_index") or {}
    packages: list[ValidatedPackage] = []

    for key, meta_pkg in sorted(meta_packages.items()):
        model_pkg = model_packages[key]
        name, directory = key

        kept, dropped = [], []
        for item in model_pkg.get("evidence", []):
            path = _norm_evidence_path(item.get("path", ""))
            line = item.get("line")
            known = file_index.get(path)
            if path and known is not None and isinstance(line, int) and 1 <= line <= known:
                kept.append({"path": path, "line": line})
            else:
                dropped.append(item)

        verdict = model_pkg.get("verdict", "UNKNOWN")
        if dropped:
            # §7.2: invalid entries are dropped and the verdict becomes UNKNOWN.
            warnings.append(
                f"{name}@{directory}: dropped {len(dropped)} unverifiable evidence entries")
            verdict = "UNKNOWN"

        codes = [c for c in model_pkg.get("reason_codes", []) if c not in TIER1_ONLY_CODES]
        if len(codes) != len(model_pkg.get("reason_codes", [])):
            warnings.append(f"{name}@{directory}: stripped a Tier 1-only reason code")

        floor_level = meta_pkg.get("floor", LOW)
        floor_reasons = meta_pkg.get("floor_reasons", [])
        merged = list(dict.fromkeys(floor_reasons + codes))

        packages.append(ValidatedPackage(
            name=name, directory=directory,
            risk=worst(floor_level, model_pkg.get("risk", LOW)),
            verdict=verdict,
            usage=model_pkg.get("usage", "unknown"),
            reason_codes=merged,
            evidence=kept[:5],
            dropped_evidence=dropped,
        ))

    overall = worst(
        meta.get("overall_floor", LOW),
        result.get("overall_risk", LOW),
        *[p.risk for p in packages],
    )

    return ValidatedResult(packages=packages, overall_risk=overall,
                           notes=sanitize_notes(result.get("notes")),
                           warnings=warnings)


def apply_output_guardrail(validated: ValidatedResult, guardrail) -> ValidatedResult:
    """§7.2 step 4. `guardrail(text) -> (intervened, matched)`.

    A blocked note is replaced, and the overall risk is raised to at least
    medium: if the reviewer tried to say something the guardrail would not
    repeat, that is itself a signal.
    """
    if not validated.notes:
        return validated
    intervened, matched = guardrail(validated.notes)
    if intervened:
        validated.notes = WITHHELD
        validated.overall_risk = worst(validated.overall_risk, MEDIUM)
        validated.warnings.append(f"notes withheld by guardrail: {matched}")
    return validated


def floor_reason_summary(meta: dict) -> dict[str, list[str]]:
    """`{reason_code: [package names]}` for the comment's floor-reasons line."""
    out: dict[str, list[str]] = {}
    for p in meta.get("packages", []):
        for code in p.get("floor_reasons", []):
            out.setdefault(code, []).append(p["name"])
    for code in meta.get("global_reasons", []):
        out.setdefault(code, [])
    return out
