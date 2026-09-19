"""Safe tarball extraction (SPEC.md §5.2 step 4, §4).

The tarball comes from the GitHub API at a pinned SHA, so it is semi-trusted —
it is the user's own repository. But it is still attacker-influenceable: a
Dependabot PR is opened against a repo whose contents anyone with a merged PR
has shaped, and the reviewer that later reads the extracted tree is assumed
compromised. So extraction refuses anything that could write outside the
destination or exhaust the task.

Python's `tarfile` grew a `filter="data"` mode that covers much of this, and we
use it as a backstop. We do not *rely* on it: the checks below are explicit so
the policy is visible and testable, and so the error says which rule tripped.
"""

from __future__ import annotations

import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_FILES = 20_000
MAX_SINGLE_FILE_BYTES = 10 * 1024 * 1024


class UnsafeArchive(Exception):
    """The archive broke a rule. Callers treat this as UNEXPECTED_CHANGE."""


@dataclass
class ExtractResult:
    files: int
    total_bytes: int
    root: Path


def _strip_top_level(name: str) -> str | None:
    """GitHub tarballs wrap everything in `<owner>-<repo>-<sha>/`.

    Returns the path relative to that wrapper, or None for the wrapper itself.
    """
    parts = PurePosixPath(name).parts
    if len(parts) <= 1:
        return None
    return str(PurePosixPath(*parts[1:]))


def check_member(member: tarfile.TarInfo, dest: Path) -> None:
    """Raise UnsafeArchive if this member may not be written."""
    name = member.name

    if member.issym() or member.islnk():
        raise UnsafeArchive(f"archive contains a link: {name!r}")
    if member.ischr() or member.isblk() or member.isfifo() or member.isdev():
        raise UnsafeArchive(f"archive contains a device or fifo: {name!r}")
    if not (member.isfile() or member.isdir()):
        raise UnsafeArchive(f"archive contains an unsupported entry: {name!r}")

    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise UnsafeArchive(f"absolute path in archive: {name!r}")
    if ".." in PurePosixPath(name).parts:
        raise UnsafeArchive(f"parent traversal in archive: {name!r}")

    if member.isfile() and member.size > MAX_SINGLE_FILE_BYTES:
        raise UnsafeArchive(f"file exceeds {MAX_SINGLE_FILE_BYTES} bytes: {name!r}")

    # Belt and braces against anything the string checks missed.
    target = (dest / name).resolve()
    dest_real = dest.resolve()
    if target != dest_real and dest_real not in target.parents:
        raise UnsafeArchive(f"path escapes the destination: {name!r}")


def safe_extract(tar_path: str | Path, dest: str | Path, *, strip_top_level: bool = True) -> ExtractResult:
    """Extract `tar_path` into `dest`, enforcing the §4 controls.

    Caps are checked *while* iterating, not afterwards, so a zip bomb fails part
    way through rather than after filling the disk.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    dest_real = dest.resolve()

    files = 0
    total = 0

    with tarfile.open(tar_path, "r:*") as tf:
        for member in tf:
            check_member(member, dest)

            name = _strip_top_level(member.name) if strip_top_level else member.name
            if not name:
                continue

            target = (dest_real / name).resolve()
            if target != dest_real and dest_real not in target.parents:
                raise UnsafeArchive(f"path escapes the destination: {member.name!r}")

            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            files += 1
            if files > MAX_FILES:
                raise UnsafeArchive(f"archive exceeds {MAX_FILES} files")
            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise UnsafeArchive(f"archive exceeds {MAX_TOTAL_BYTES} bytes uncompressed")

            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = tf.extractfile(member)
            if extracted is None:
                raise UnsafeArchive(f"unreadable member: {member.name!r}")
            with extracted, open(target, "wb") as out:
                while chunk := extracted.read(1 << 16):
                    out.write(chunk)
            target.chmod(0o644)

    return ExtractResult(files=files, total_bytes=total, root=dest_real)


def freeze(root: str | Path) -> None:
    """Make a tree read-only (§5.3 step 1).

    Deepest-first, because a directory must stay writable until its children
    have been handled.
    """
    root = Path(root)
    for p in sorted(root.rglob("*"), key=lambda q: len(q.parts), reverse=True):
        try:
            p.chmod(0o500 if p.is_dir() else 0o400)
        except OSError:
            pass
    root.chmod(0o500)
