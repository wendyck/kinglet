"""Fetch upstream release notes for a package (SPEC.md §5.2 step 6).

Everything this module returns is **untrusted**. It is written to `untrusted/`
in the bundle, labeled as data by the fs-readonly server, and passed through
`ApplyGuardrail` before the reviewer sees it. A compromised or typosquatted
upstream controls this text entirely.

Failure is normal and must not fail the review. A package with no discoverable
changelog is a package the reviewer judges on usage alone, which is why every
path here degrades to an empty string rather than raising.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger(__name__)

MAX_NOTES_BYTES = 20 * 1024
HTTP_TIMEOUT = 15
USER_AGENT = "kinglet"

_GITHUB_REPO = re.compile(r"github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?$")


def _get_json(url: str, token: str | None = None) -> dict | list | None:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"token {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            return json.load(r)
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
        log.info("release-notes fetch failed for %s: %s", url, e)
        return None


def pypi_source_repo(package: str) -> tuple[str, str] | None:
    """Find a package's GitHub repo from its PyPI metadata."""
    data = _get_json(f"https://pypi.org/pypi/{urllib.parse.quote(package)}/json")
    if not isinstance(data, dict):
        return None
    info = data.get("info") or {}
    candidates = list((info.get("project_urls") or {}).values())
    candidates += [info.get("home_page"), info.get("project_url"), info.get("package_url")]
    for url in candidates:
        if not isinstance(url, str):
            continue
        m = _GITHUB_REPO.search(url.strip())
        if m:
            return m.group(1), m.group(2)
    return None


def _version_key(tag: str) -> tuple:
    """Sortable key from a tag like `v1.43.69` or `15.12.0`."""
    nums = re.findall(r"\d+", tag or "")
    return tuple(int(n) for n in nums[:4]) if nums else (0,)


def github_releases_between(owner: str, repo: str, from_version: str | None,
                            to_version: str | None, token: str | None = None) -> str:
    """Release bodies for versions in `(from, to]`, newest first.

    Unauthenticated by default. Upstream repos are not ours, so an installation
    token does not apply to them; the anonymous API allows 60 requests an hour,
    which is ample for a handful of packages per PR but is the reason this
    degrades quietly rather than raising.
    """
    data = _get_json(
        f"https://api.github.com/repos/{owner}/{repo}/releases?per_page=100", token)
    if not isinstance(data, list):
        return ""

    lo = _version_key(from_version) if from_version else None
    hi = _version_key(to_version) if to_version else None

    chunks: list[str] = []
    for rel in data:
        tag = rel.get("tag_name") or rel.get("name") or ""
        key = _version_key(tag)
        if lo and key <= lo:
            continue
        if hi and key > hi:
            continue
        body = (rel.get("body") or "").strip()
        header = f"## {tag}"
        chunks.append(f"{header}\n\n{body}" if body else header)

    chunks.sort(key=lambda c: _version_key(c.split("\n", 1)[0]), reverse=True)
    return "\n\n".join(chunks)


def fetch(name: str, ecosystem: str, from_version: str | None, to_version: str | None,
          token: str | None = None) -> str:
    """Release notes for one package, truncated to 20 KB, or "" on any failure."""
    try:
        if ecosystem == "actions":
            owner, _, repo = name.partition("/")
            if not repo:
                return ""
            text = github_releases_between(owner, repo, from_version, to_version, token)
        elif ecosystem == "pip":
            source = pypi_source_repo(name)
            if not source:
                return ""
            text = github_releases_between(*source, from_version, to_version, token)
        else:
            return ""
    except Exception as e:  # never fail a review over a changelog
        log.warning("release notes for %s failed: %s", name, e)
        return ""

    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) > MAX_NOTES_BYTES:
        encoded = encoded[:MAX_NOTES_BYTES]
        text = encoded.decode("utf-8", errors="ignore") + "\n\n… truncated at 20 KB"
    return text
