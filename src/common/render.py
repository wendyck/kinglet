"""Render the sticky PR comment (SPEC.md §7.3).

Every visible string is produced here, from a fixed template. The model supplies
enums, `file:line` references and one free-text field; it never authors prose.
Per-package wording comes from `REASON_WORDING`, so a new reason code shows up as
a known phrase or not at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .sanitize import code_span, sanitize_advisory_summary, table_cell

MARKER_PREFIX = "<!-- kinglet:v1 "
SUPERSEDED_MARKER_PREFIX = "<!-- kinglet:superseded v1 "

RISK_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🔴"}

# Fixed wording. The model picks codes; we pick words (§7.1).
REASON_WORDING = {
    "MAJOR_BUMP": "Major version bump",
    "ZERO_X_MINOR": "Pre-1.0 minor bump",
    "NO_IMPORTS": "Not imported anywhere",
    "IMPORT_ONLY_IN_SCRIPTS": "Used only in tooling",
    "API_REMOVED_IN_USE": "Removed API is used here",
    "DEPRECATION_IN_USE": "Deprecated API is used here",
    "CHANGELOG_BREAKING": "Release notes flag a breaking change",
    "CHANGELOG_SECURITY_FIX": "Release notes mention a security fix",
    "ACTION_RUNTIME_CHANGE": "Action runtime changed",
    "RANGE_FLOOR_ONLY": "Raises the minimum only",
    "SUPERSEDED_ELSEWHERE": "Superseded by a newer PR",
    "INCONCLUSIVE": "Analysis inconclusive",
    # Floor-only codes, never emitted by the model.
    "NEW_DEPENDENCY": "New dependency added",
    "FRAMEWORK": "Framework package for this repo",
    "WATCHLIST": "On this repo's watchlist",
    "PRODUCTION_MINOR": "Minor bump in a production manifest",
    "RANGE_SOFTENED": "Softened: the build already floats past this",
    "ACTION_MAJOR": "GitHub Action major version",
    "ACTION_TAG_REF": "Action pinned by tag, not SHA",
    "PATCH": "Patch bump",
    "NO_CHANGE": "No forward version change",
    "UNPARSEABLE": "Could not parse the update reliably",
    "UNEXPECTED_CHANGE": "PR touches files outside the manifest allowlist",
    "PROMPT_ATTACK_SUSPECTED": "Prompt-injection suspected in PR-derived text",
}


# Reasons are shown most-significant first: the code that actually drove the
# level should lead, not whichever happened to be appended first.
_REASON_PRIORITY = [
    "UNEXPECTED_CHANGE", "PROMPT_ATTACK_SUSPECTED", "UNPARSEABLE",
    "NEW_DEPENDENCY", "MAJOR_BUMP", "ZERO_X_MINOR",
    "API_REMOVED_IN_USE", "DEPRECATION_IN_USE", "CHANGELOG_BREAKING",
    "CHANGELOG_SECURITY_FIX", "ACTION_RUNTIME_CHANGE", "ACTION_MAJOR",
    "FRAMEWORK", "WATCHLIST", "PRODUCTION_MINOR", "ACTION_TAG_REF",
    "NO_IMPORTS", "IMPORT_ONLY_IN_SCRIPTS", "SUPERSEDED_ELSEWHERE",
    "RANGE_FLOOR_ONLY", "RANGE_SOFTENED", "PATCH", "NO_CHANGE", "INCONCLUSIVE",
]
_PRIORITY_INDEX = {code: i for i, code in enumerate(_REASON_PRIORITY)}


def order_reasons(codes) -> list[str]:
    return sorted(codes, key=lambda c: (_PRIORITY_INDEX.get(c, len(_REASON_PRIORITY)), c))


def describe(code: str) -> str:
    return REASON_WORDING.get(code, code.replace("_", " ").capitalize())


@dataclass
class Row:
    """One table row. Every field here is Tier 1's, except risk/verdict/reasons."""

    name: str
    directory: str
    change: str
    risk: str
    verdict: str
    reason_codes: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)


@dataclass
class Advisory:
    ghsa_id: str
    severity: str
    summary: str


def marker(review_key: str, sha: str, status: str = "ok") -> str:
    return f"{MARKER_PREFIX}key={review_key} sha={sha} status={status} -->"


def parse_marker(comment_body: str) -> dict | None:
    """Read back a marker so the poller can skip an already-reviewed PR (§5.1)."""
    start = comment_body.find(MARKER_PREFIX)
    if start == -1:
        return None
    end = comment_body.find("-->", start)
    if end == -1:
        return None
    fields = comment_body[start + len(MARKER_PREFIX):end].strip().split()
    out = {}
    for f in fields:
        k, _, v = f.partition("=")
        if k and v:
            out[k] = v
    return out or None


def _evidence_cell(evidence: list[dict]) -> str:
    if not evidence:
        return "—"
    return "<br>".join(code_span(f"{e['path']}:{e['line']}") for e in evidence[:5])


def _why_cell(reason_codes: list[str]) -> str:
    if not reason_codes:
        return "—"
    return "; ".join(describe(c) for c in order_reasons(reason_codes)[:4])


def security_banner(advisories: list[Advisory]) -> str:
    """§5.7. Driven by the alerts API only, never by PR text."""
    if not advisories:
        return ""
    order = {"critical": 3, "high": 2, "moderate": 1, "medium": 1, "low": 0}
    highest = max(advisories, key=lambda a: order.get(a.severity.lower(), 0))
    n = len(advisories)
    lines = [
        f"### 🛡️ Security update — fixes {n} "
        f"{'advisory' if n == 1 else 'advisories'} "
        f"(highest: {highest.severity.upper()})",
    ]
    for a in advisories:
        summary = sanitize_advisory_summary(a.summary)
        lines.append(f"- {table_cell(a.ghsa_id)} · {table_cell(a.severity.lower())}"
                     + (f" · {summary}" if summary else ""))
    return "\n".join(lines) + "\n"


def render_comment(
    *,
    review_key: str,
    sha: str,
    overall_risk: str,
    rows: list[Row],
    floor_reasons: dict[str, list[str]] | None = None,
    advisories: list[Advisory] | None = None,
    supersedes: list[tuple[int, str]] | None = None,
    notes: str = "",
    version: str = "0.1.0",
    now: datetime | None = None,
) -> str:
    """The full sticky comment."""
    ts = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")
    parts = [marker(review_key, sha)]

    banner = security_banner(advisories or [])
    if banner:
        parts.append(banner)

    emoji = RISK_EMOJI.get(overall_risk, "")
    parts.append(f"### 🐦 Kinglet dependency review — **risk: {overall_risk.upper()}** {emoji}".rstrip())
    parts.append("_Automated triage. Advisory only — kinglet does not merge or approve._\n")

    parts.append("| Package | Dir | Change | Risk | Verdict | Why | Evidence |")
    parts.append("|---|---|---|---|---|---|---|")
    for r in rows:
        parts.append(
            f"| {code_span(r.name)} | {code_span(r.directory)} | {code_span(r.change)} "
            f"| {table_cell(r.risk)} | {table_cell(r.verdict)} "
            f"| {_why_cell(r.reason_codes)} | {_evidence_cell(r.evidence)} |"
        )
    parts.append("")

    if floor_reasons:
        # A PR-wide reason (UNEXPECTED_CHANGE, PROMPT_ATTACK_SUSPECTED) names no
        # package, so it renders without the empty parenthetical.
        parts_ = []
        for code in order_reasons(floor_reasons):
            names = floor_reasons[code]
            if names:
                parts_.append(f"{describe(code)} "
                              f"({', '.join(code_span(n) for n in sorted(names))})")
            else:
                parts_.append(describe(code))
        summary = ", ".join(parts_)
        parts.append(f"**Floor reasons:** {summary}")

    if supersedes:
        items = ", ".join(f"#{int(num)} ({code_span(pkg)})" for num, pkg in supersedes)
        parts.append(f"**Supersedes:** {items}")

    if floor_reasons or supersedes:
        parts.append("")

    if notes:
        parts.append(f"> **Model notes (untrusted, sanitized):** {notes}\n")

    parts.append(f"<sub>kinglet {version} · reviewed {code_span(sha[:12])} · {ts}</sub>")
    return "\n".join(parts)


def render_superseded_comment(
    *, by: list[int], packages: list[tuple[str, str, int]], fully: bool
) -> str:
    """The separate sticky comment on a superseded PR (§5.6).

    `packages` is (name, directory, superseding PR number). Deterministic Tier 1
    output — the model is not involved, and `#N` links are the only links
    kinglet ever emits.
    """
    by_list = ",".join(f"#{int(n)}" for n in by)
    head = f"{SUPERSEDED_MARKER_PREFIX}by={by_list} -->"
    if fully and len(by) == 1 and len(packages) == 1:
        name, directory, num = packages[0]
        body = (
            f"This PR appears to be superseded by #{int(num)} — it updates "
            f"{code_span(name)} in {code_span(directory)} to a newer version. "
            "Consider closing this one."
        )
    else:
        lines = ["This PR appears to be partly superseded:" if not fully
                 else "This PR appears to be superseded:"]
        for name, directory, num in packages:
            lines.append(f"- {code_span(name)} in {code_span(directory)} → #{int(num)}")
        lines.append("")
        lines.append("Consider closing this one." if fully
                     else "The remaining packages in this PR are still relevant.")
        body = "\n".join(lines)
    return f"{head}\n### 🐦 Kinglet\n{body}"
