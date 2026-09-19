"""Parse a Dependabot PR into a package list (SPEC.md §5.2 step 5).

The `updated-dependencies` trailer is necessary but not sufficient. It carries
the package name, a target version, the dependency type and (sometimes) the
group — but **no directory, no ecosystem and no `from` version**, and on range
updates its `dependency-version` disagrees with the actual patch. Those all come
from the changed files instead. See `docs/spikes/S5-dependabot-trailer.md`,
findings F1, F2 and F5.

The patch is authoritative for versions. The trailer is authoritative for which
packages Dependabot *intended* to touch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

# ── ecosystems, by manifest path ─────────────────────────────────────────────

PIP_MANIFESTS = re.compile(r"(^|/)(requirements[^/]*\.txt|pyproject\.toml|setup\.cfg)$")
ACTIONS_MANIFESTS = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")
DOCKER_MANIFESTS = re.compile(r"(^|/)Dockerfile[^/]*$")


def ecosystem_for(path: str) -> str | None:
    if ACTIONS_MANIFESTS.match(path):
        return "actions"
    if PIP_MANIFESTS.search(path):
        return "pip"
    if DOCKER_MANIFESTS.search(path):
        return "docker"
    return None


def normalize(name: str, ecosystem: str) -> str:
    """PEP 503 for pip; Actions names are case-insensitive owner/repo."""
    if ecosystem == "pip":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def directory_of(path: str) -> str:
    """The manifest's directory, as Dependabot writes it: '/' or '/scripts'.

    Workflow files belong to the repository root: Dependabot's `github-actions`
    ecosystem is configured with `directory: "/"` regardless of where under
    .github/workflows the file sits.
    """
    if ACTIONS_MANIFESTS.match(path):
        return "/"
    parent = str(PurePosixPath(path).parent)
    return "/" if parent == "." else "/" + parent


# ── the trailer ──────────────────────────────────────────────────────────────


def trailer_block(message: str) -> list[str] | None:
    """The raw lines of the `updated-dependencies:` YAML block, or None.

    Terminated by YAML's `...` end-of-document marker, which Dependabot emits.
    A parser that stops at the first column-0 line stops immediately, because
    the sequence entries themselves start at column 0 with '-'.
    """
    lines = message.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.strip() == "updated-dependencies:")
    except StopIteration:
        return None
    out: list[str] = []
    for line in lines[start + 1:]:
        if line.strip() in ("...", "---"):
            break
        if line.startswith("-") or line[:1] in (" ", "\t"):
            out.append(line)
        elif not line.strip():
            continue
        else:
            break
    return out or None


def parse_trailer(message: str) -> list[dict] | None:
    """The trailer as a list of dicts, preserving Dependabot's own key names."""
    block = trailer_block(message)
    if block is None:
        return None
    entries: list[dict] = []
    current: dict | None = None
    for line in block:
        s = line.strip()
        if not s:
            continue
        if s.startswith("- "):
            current = {}
            entries.append(current)
            s = s[2:].strip()
        if current is None or ":" not in s:
            continue
        k, _, v = s.partition(":")
        current[k.strip()] = v.strip().strip('"').strip("'")
    return entries or None


# ── the patch ────────────────────────────────────────────────────────────────

# `anthropic>=0.116.0  # comment`, `recipe-scrapers==15.11.0`, `boto3`
REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?P<extras>\[[^\]]*\])?\s*"
    r"(?P<spec>(?:[<>=!~]=?|===)\s*[^,;#\s]+(?:\s*,\s*(?:[<>=!~]=?|===)\s*[^,;#\s]+)*)?"
)
# `uses: actions/checkout@v4`
USES_LINE = re.compile(r"uses:\s*(?P<name>[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+)@(?P<ref>\S+)")
# a bare version out of a spec like `>=1.43.69` or `==15.12.0`
SPEC_VERSION = re.compile(r"(?:[<>=!~]=?|===)\s*([^,;\s]+)")


@dataclass
class Change:
    """One package's before/after, read off a manifest patch."""

    name: str
    manifest: str
    ecosystem: str
    from_spec: str | None = None
    to_spec: str | None = None

    @property
    def directory(self) -> str:
        return directory_of(self.manifest)

    @property
    def is_range(self) -> bool:
        return bool(self.to_spec) and self.to_spec.strip().startswith((">=", ">", "~=", "^"))

    def _version(self, spec: str | None) -> str | None:
        if not spec:
            return None
        if self.ecosystem == "actions":
            return spec.lstrip("v")
        m = SPEC_VERSION.search(spec)
        return m.group(1) if m else spec.strip() or None

    @property
    def from_version(self) -> str | None:
        return self._version(self.from_spec)

    @property
    def to_version(self) -> str | None:
        return self._version(self.to_spec)


def _pip_entries(line: str) -> tuple[str, str | None] | None:
    body = line.split("#", 1)[0].strip()
    if not body or body.startswith("-"):  # pip flags like -r, -e
        return None
    m = REQ_LINE.match(body)
    if not m or not m.group("name"):
        return None
    return m.group("name"), (m.group("spec") or "").strip() or None


def changes_from_patch(manifest: str, patch: str | None) -> list[Change]:
    """Pair '-' and '+' lines in a manifest patch into per-package changes."""
    eco = ecosystem_for(manifest)
    if not eco or not patch:
        return []

    removed: dict[str, str | None] = {}
    added: dict[str, str | None] = {}
    for raw in patch.splitlines():
        if raw.startswith(("+++", "---", "@@")) or not raw[:1] in ("+", "-"):
            continue
        side = added if raw[0] == "+" else removed
        body = raw[1:]
        if eco == "actions":
            m = USES_LINE.search(body)
            if m:
                side[m.group("name").lower()] = m.group("ref")
            continue
        parsed = _pip_entries(body) if eco == "pip" else None
        if parsed:
            side[normalize(parsed[0], eco)] = parsed[1]

    out: list[Change] = []
    for key in sorted(set(removed) | set(added)):
        out.append(Change(name=key, manifest=manifest, ecosystem=eco,
                          from_spec=removed.get(key), to_spec=added.get(key)))
    return out


# ── the combination ──────────────────────────────────────────────────────────


@dataclass
class Update:
    """One package, in one directory, as Kinglet reasons about it."""

    name: str
    ecosystem: str
    directory: str
    manifest: str
    from_spec: str | None
    to_spec: str | None
    from_version: str | None
    to_version: str | None
    is_range: bool
    dependency_type: str | None = None
    update_type: str | None = None
    group: str | None = None
    is_new: bool = False

    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.directory, normalize(self.name, self.ecosystem))


@dataclass
class ParseResult:
    updates: list[Update] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def unparseable(self) -> bool:
        return "UNPARSEABLE" in self.reasons


def parse_pr(commit_message: str, changed_files: list[dict]) -> ParseResult:
    """Build the package list from the trailer plus the changed-file patches.

    `changed_files` is the GitHub pull-request files payload: dicts with at
    least `filename` and `patch`.

    A package the trailer names but no patch explains, or vice versa, is a
    signal that parsing is incomplete — the caller raises the floor rather than
    reviewing a list it cannot vouch for.
    """
    result = ParseResult()

    trailer = parse_trailer(commit_message)
    if trailer is None:
        result.reasons.append("UNPARSEABLE")

    # Patch-derived changes, indexed by (ecosystem, directory, normalized name).
    by_key: dict[tuple[str, str, str], Change] = {}
    for f in changed_files:
        for ch in changes_from_patch(f.get("filename", ""), f.get("patch")):
            by_key[(ch.ecosystem, ch.directory, ch.name)] = ch

    if not by_key:
        if "UNPARSEABLE" not in result.reasons:
            result.reasons.append("UNPARSEABLE")
        return result

    # Trailer metadata, indexed by normalized name. The trailer has no
    # directory, so a package touched in two directories inherits the same
    # metadata in both — which is correct: Dependabot emits one entry per
    # package per PR.
    meta: dict[str, dict] = {}
    for entry in trailer or []:
        raw = entry.get("dependency-name")
        if not raw:
            continue
        for eco in ("pip", "actions", "docker"):
            meta[normalize(raw, eco)] = entry

    named = {normalize(e["dependency-name"], "pip")
             for e in (trailer or []) if e.get("dependency-name")}

    for (eco, directory, name), ch in sorted(by_key.items()):
        entry = meta.get(name, {})
        result.updates.append(Update(
            name=entry.get("dependency-name", name),
            ecosystem=eco,
            directory=directory,
            manifest=ch.manifest,
            from_spec=ch.from_spec,
            to_spec=ch.to_spec,
            from_version=ch.from_version,
            to_version=ch.to_version,
            is_range=ch.is_range,
            dependency_type=entry.get("dependency-type"),
            update_type=entry.get("update-type"),
            group=entry.get("dependency-group"),
            is_new=ch.from_spec is None and ch.to_spec is not None
                   and name not in {k[2] for k in by_key if k != (eco, directory, name)},
        ))

    # The trailer named something no patch explains: we would review a package
    # without knowing its versions.
    if trailer:
        seen = {normalize(u.name, "pip") for u in result.updates}
        if named - seen:
            result.reasons.append("UNPARSEABLE")

    return result
