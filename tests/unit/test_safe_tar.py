"""Tests for safe tarball extraction (SPEC.md §5.2 step 4, §4).

Each test builds a genuinely malicious archive and asserts nothing lands outside
the destination. Building them by hand matters: `tarfile` will happily *create*
an archive containing `../../etc/passwd`, which is exactly what we need to prove
we refuse to unpack one.
"""

import io
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from common.safe_tar import (  # noqa: E402
    MAX_SINGLE_FILE_BYTES, UnsafeArchive, freeze, safe_extract,
)

WRAPPER = "wendyck-csa-wrangler-b7b1db2/"


def build(tmp_path: Path, entries, *, name="t.tar.gz") -> Path:
    """entries: list of (name, kind, payload). kind in file|dir|sym|link|fifo."""
    path = tmp_path / name
    with tarfile.open(path, "w:gz") as tf:
        for entry in entries:
            ename, kind, payload = entry
            if kind == "file":
                data = payload.encode() if isinstance(payload, str) else payload
                info = tarfile.TarInfo(ename)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            elif kind == "dir":
                info = tarfile.TarInfo(ename)
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            elif kind == "sym":
                info = tarfile.TarInfo(ename)
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                tf.addfile(info)
            elif kind == "link":
                info = tarfile.TarInfo(ename)
                info.type = tarfile.LNKTYPE
                info.linkname = payload
                tf.addfile(info)
            elif kind == "fifo":
                info = tarfile.TarInfo(ename)
                info.type = tarfile.FIFOTYPE
                tf.addfile(info)
            elif kind == "sparse_lie":
                # Declares a huge size but carries little data.
                info = tarfile.TarInfo(ename)
                info.size = payload
                tf.addfile(info, io.BytesIO(b"\0" * payload))
    return path


# ── the happy path ───────────────────────────────────────────────────────────


def test_extracts_and_strips_the_github_wrapper(tmp_path):
    src = build(tmp_path, [
        (WRAPPER, "dir", None),
        (WRAPPER + "requirements.txt", "file", "boto3>=1.34\n"),
        (WRAPPER + "scripts/", "dir", None),
        (WRAPPER + "scripts/add_recipes.py", "file", "import anthropic\n"),
    ])
    dest = tmp_path / "work"
    result = safe_extract(src, dest)
    assert result.files == 2
    assert (dest / "requirements.txt").read_text() == "boto3>=1.34\n"
    assert (dest / "scripts/add_recipes.py").exists()
    assert not (dest / WRAPPER).exists()


def test_reports_totals(tmp_path):
    src = build(tmp_path, [(WRAPPER + f"f{i}.txt", "file", "x" * 10) for i in range(5)])
    result = safe_extract(src, tmp_path / "work")
    assert result.files == 5 and result.total_bytes == 50


# ── traversal ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("bad", [
    "../escape.txt",
    WRAPPER + "../../escape.txt",
    WRAPPER + "a/../../../escape.txt",
])
def test_parent_traversal_is_refused(tmp_path, bad):
    src = build(tmp_path, [(bad, "file", "pwned")])
    with pytest.raises(UnsafeArchive, match="traversal|escapes"):
        safe_extract(src, tmp_path / "work")
    assert not (tmp_path / "escape.txt").exists()


def test_absolute_path_is_refused(tmp_path):
    src = build(tmp_path, [("/tmp/kinglet-pwned.txt", "file", "pwned")])
    with pytest.raises(UnsafeArchive, match="absolute"):
        safe_extract(src, tmp_path / "work")


# ── links, the §4 row ────────────────────────────────────────────────────────


def test_symlink_is_refused(tmp_path):
    src = build(tmp_path, [(WRAPPER + "creds", "sym", "/root/.aws/credentials")])
    with pytest.raises(UnsafeArchive, match="link"):
        safe_extract(src, tmp_path / "work")


def test_hardlink_is_refused(tmp_path):
    src = build(tmp_path, [
        (WRAPPER + "a.txt", "file", "a"),
        (WRAPPER + "b.txt", "link", WRAPPER + "a.txt"),
    ])
    with pytest.raises(UnsafeArchive, match="link"):
        safe_extract(src, tmp_path / "work")


def test_symlink_then_write_through_it_is_refused(tmp_path):
    """The classic two-step: plant a link to a directory, then write through it."""
    src = build(tmp_path, [
        (WRAPPER + "out", "sym", "/tmp"),
        (WRAPPER + "out/pwned.txt", "file", "pwned"),
    ])
    with pytest.raises(UnsafeArchive, match="link"):
        safe_extract(src, tmp_path / "work")
    assert not Path("/tmp/pwned.txt").exists()


def test_fifo_is_refused(tmp_path):
    src = build(tmp_path, [(WRAPPER + "pipe", "fifo", None)])
    with pytest.raises(UnsafeArchive, match="device or fifo"):
        safe_extract(src, tmp_path / "work")


# ── resource caps ────────────────────────────────────────────────────────────


def test_single_oversized_file_is_refused(tmp_path):
    src = build(tmp_path, [(WRAPPER + "big.bin", "sparse_lie", MAX_SINGLE_FILE_BYTES + 1)])
    with pytest.raises(UnsafeArchive, match="exceeds"):
        safe_extract(src, tmp_path / "work")


def test_too_many_files_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr("common.safe_tar.MAX_FILES", 10)
    src = build(tmp_path, [(WRAPPER + f"f{i}.txt", "file", "x") for i in range(20)])
    with pytest.raises(UnsafeArchive, match="files"):
        safe_extract(src, tmp_path / "work")


def test_total_size_cap_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr("common.safe_tar.MAX_TOTAL_BYTES", 100)
    src = build(tmp_path, [(WRAPPER + f"f{i}.txt", "file", "x" * 50) for i in range(10)])
    with pytest.raises(UnsafeArchive, match="bytes"):
        safe_extract(src, tmp_path / "work")


def test_caps_fail_partway_rather_than_after_filling_the_disk(tmp_path, monkeypatch):
    monkeypatch.setattr("common.safe_tar.MAX_FILES", 3)
    src = build(tmp_path, [(WRAPPER + f"f{i}.txt", "file", "x") for i in range(50)])
    dest = tmp_path / "work"
    with pytest.raises(UnsafeArchive):
        safe_extract(src, dest)
    assert len(list(dest.rglob("*.txt"))) <= 4


# ── freeze (§5.3 step 1) ─────────────────────────────────────────────────────


def test_freeze_makes_the_tree_read_only(tmp_path):
    src = build(tmp_path, [
        (WRAPPER + "a.txt", "file", "a"),
        (WRAPPER + "sub/b.txt", "file", "b"),
    ])
    dest = tmp_path / "work"
    safe_extract(src, dest)
    freeze(dest)
    try:
        with pytest.raises(PermissionError):
            (dest / "a.txt").write_text("changed")
        with pytest.raises(PermissionError):
            (dest / "sub" / "new.txt").write_text("new")
    finally:
        # Let pytest clean up.
        for p in dest.rglob("*"):
            p.chmod(0o700)
        dest.chmod(0o700)
