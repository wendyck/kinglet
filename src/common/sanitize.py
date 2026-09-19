"""Sanitize untrusted text before it reaches a PR comment (SPEC.md §7.2 step 4).

Everything here treats its input as attacker-controlled. Two sources qualify:
the model's `notes` field, and advisory summaries from the Dependabot alerts API
(§5.7) — third-party text either way.

The threat is not just ugly output. A markdown image in a GitHub comment is
fetched through camo, which turns any `![](…)` into an exfiltration beacon that
fires when a maintainer opens the PR. Links are phishing. `@mentions` and `#123`
references generate notifications and cross-links on unrelated issues.

Order matters. Normalization and invisible-character stripping run **first**, so
that `h\u200bttps://evil.test` cannot slip a URL past the URL matcher by hiding a
zero-width space inside the scheme.
"""

from __future__ import annotations

import re
import unicodedata

MAX_NOTES = 600
MAX_ADVISORY_SUMMARY = 120

WITHHELD = "(notes withheld by guardrail)"

# Zero-width and bidi controls: invisible, and used to break up patterns.
_INVISIBLE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff\u00ad]"
)
# C0/C1 controls except tab and newline, which we normalize to spaces later.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]")

_HTML_TAG = re.compile(r"<[^>\n]{0,200}>")
_HTML_ENTITY = re.compile(r"&(?:#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]{1,31});")
_MD_IMAGE = re.compile(r"!\[[^\]]{0,200}\]\([^)]{0,500}\)")
_MD_LINK = re.compile(r"\[([^\]]{0,200})\]\([^)]{0,500}\)")
_MD_REF_LINK = re.compile(r"\[([^\]]{0,200})\]\[[^\]]{0,100}\]")
_MD_REF_DEF = re.compile(r"^\s*\[[^\]]{0,100}\]:\s*\S+.*$", re.M)
# Schemes first, then bare hosts. `\b\w+://` catches javascript:, data:, file:.
_SCHEME_URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}:(?://)?[^\s<>\"']{1,500}")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b")

# Bare hosts are deliberately narrow. A dependency review is *about* dotted
# identifiers and file paths — `client.messages.create`, `scripts/add_recipes.py`
# — and a greedy host matcher destroys exactly the content the notes exist to
# carry. GitHub only autolinks a URL with a scheme, or a `www.` prefix, so a
# scheme-less host left as plain text is inert: not clickable, not fetched, no
# camo proxying. We therefore strip only what GitHub would make live, plus
# scheme-less hosts that carry a path and end in a recognizable TLD.
_RISKY_TLDS = (
    "com|net|org|io|dev|app|sh|xyz|top|info|biz|co|me|link|click|gg|ly|ru|cn|"
    "tk|ml|ga|cf|zip|mov|invalid|test|example|localhost|onion"
)
_WWW_HOST = re.compile(r"\bwww\.[A-Za-z0-9.-]{1,255}(?:/[^\s]{0,200})?")
_HOST_WITH_PATH = re.compile(
    r"(?<![A-Za-z0-9_/.-])"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9-]{1,63})*"
    rf"\.(?:{_RISKY_TLDS})/[^\s]{{0,200}}"
)
# Only `@`: it can be left dangling when an email address is removed. A lone
# `#` is inert and appears in ordinary prose ("C#", "issue #" phrasing).
_ORPHAN_AT = re.compile(r"@(?=\s|$)")
_MENTION = re.compile(r"(?<![A-Za-z0-9_])[@#][A-Za-z0-9][\w./-]{0,100}")
_BACKTICK = re.compile(r"`+")
_WS = re.compile(r"[ \t\u00a0\u2000-\u200a\u3000]+")

_REPLACEMENT = " "


def _collapse(text: str) -> str:
    text = _WS.sub(" ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return "\n".join(line.strip() for line in text.split("\n")).strip()


def scrub(text: str, limit: int) -> str:
    """Strip every construct that could act on a reader, then truncate.

    Returns plain prose. Punctuation and ordinary words survive; anything that
    links, embeds, mentions or renders does not.
    """
    if not text:
        return ""

    # 1. Normalize, then remove what is invisible. NFKC folds homoglyph and
    #    full-width tricks into their ASCII equivalents so the matchers below
    #    see what a reader would see.
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    text = _CONTROL.sub(" ", text)

    # 2. Strip markup. Images before links, since an image is a link with a
    #    bang; reference definitions before inline links, since they are
    #    line-shaped.
    text = _MD_REF_DEF.sub("", text)
    text = _MD_IMAGE.sub(_REPLACEMENT, text)
    text = _MD_LINK.sub(r"\1", text)      # keep the label, drop the target
    text = _MD_REF_LINK.sub(r"\1", text)
    text = _HTML_TAG.sub(_REPLACEMENT, text)
    text = _HTML_ENTITY.sub(_REPLACEMENT, text)
    text = _EMAIL.sub(_REPLACEMENT, text)
    text = _SCHEME_URL.sub(_REPLACEMENT, text)
    text = _WWW_HOST.sub(_REPLACEMENT, text)
    text = _HOST_WITH_PATH.sub(_REPLACEMENT, text)
    text = _MENTION.sub(_REPLACEMENT, text)
    text = _BACKTICK.sub("", text)

    # A second pass: removing a wrapper can expose what it wrapped, e.g.
    # `[text](<https://evil.test>)` leaves the URL behind after the link rule
    # keeps its label.
    text = _SCHEME_URL.sub(_REPLACEMENT, text)
    text = _WWW_HOST.sub(_REPLACEMENT, text)
    text = _HOST_WITH_PATH.sub(_REPLACEMENT, text)
    text = _ORPHAN_AT.sub("", text)

    text = _collapse(text)
    if len(text) > limit:
        text = text[:limit].rstrip()
        # Avoid ending mid-word.
        if " " in text[-20:]:
            text = text[: text.rfind(" ")].rstrip()
        text += "…"
    return text


def sanitize_notes(notes: str | None) -> str:
    """The model's free-text notes (§7.2 step 4, steps 1-3)."""
    return scrub(notes or "", MAX_NOTES)


def sanitize_advisory_summary(summary: str | None) -> str:
    """A GHSA summary — third-party text, so same treatment (§5.7)."""
    return scrub(summary or "", MAX_ADVISORY_SUMMARY)


def code_span(value: str) -> str:
    """Render a Tier 1 string inside backticks, safely.

    Package names, directories and versions come from our own parsing, not the
    model, but they originate in a PR. Stripping backticks stops a crafted name
    from closing the span and injecting markdown around it.
    """
    cleaned = _BACKTICK.sub("", unicodedata.normalize("NFKC", str(value)))
    cleaned = _INVISIBLE.sub("", cleaned).replace("|", "\\|").replace("\n", " ")
    return f"`{cleaned}`"


def table_cell(value: str) -> str:
    """Plain text in a markdown table cell: pipes and newlines would break it."""
    cleaned = _INVISIBLE.sub("", unicodedata.normalize("NFKC", str(value)))
    return cleaned.replace("|", "\\|").replace("\n", " ").strip()
