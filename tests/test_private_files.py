import os
import stat

import pytest

from app import private_files
from app.private_files import PrivateFileError

pytestmark = pytest.mark.skipif(
    os.name != "posix",
    reason="The gateway's secure private-file store targets its POSIX/WSL runtime.",
)


def test_atomic_private_write_uses_strict_modes_and_leaves_no_temp(tmp_path) -> None:
    path = tmp_path / "private" / "secret"

    private_files.atomic_write_private_text(path, "first")
    private_files.atomic_write_private_text(path, "second")

    assert private_files.read_private_text(path) == "second"
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.stat().st_nlink == 1
    assert list(path.parent.glob(".*.tmp")) == []


def test_private_read_and_write_reject_symlink_target(tmp_path) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.write_text("do not read", encoding="utf-8")
    outside.chmod(0o600)
    path = parent / "secret"
    path.symlink_to(outside)

    with pytest.raises(PrivateFileError):
        private_files.read_private_text(path)
    with pytest.raises(PrivateFileError):
        private_files.atomic_write_private_text(path, "replacement")

    assert outside.read_text(encoding="utf-8") == "do not read"


def test_private_store_rejects_symlink_parent(tmp_path) -> None:
    real_parent = tmp_path / "real-private"
    real_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-private"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(PrivateFileError):
        private_files.atomic_write_private_text(linked_parent / "secret", "value")


def test_private_store_rejects_loose_file_permissions(tmp_path) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    path = parent / "secret"
    path.write_text("secret", encoding="utf-8")
    path.chmod(0o640)

    with pytest.raises(PrivateFileError):
        private_files.read_private_text(path)
    with pytest.raises(PrivateFileError):
        private_files.atomic_write_private_text(path, "replacement")


def test_private_store_rejects_and_does_not_chmod_loose_parent(tmp_path) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o755)

    with pytest.raises(PrivateFileError):
        private_files.atomic_write_private_text(parent / "secret", "value")

    assert stat.S_IMODE(parent.stat().st_mode) == 0o755


def test_private_store_rejects_hard_linked_file(tmp_path) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    path = parent / "secret"
    path.write_text("secret", encoding="utf-8")
    path.chmod(0o600)
    os.link(path, parent / "second-name")

    with pytest.raises(PrivateFileError):
        private_files.read_private_text(path)
    with pytest.raises(PrivateFileError):
        private_files.atomic_write_private_text(path, "replacement")


def test_private_store_rejects_non_regular_target(tmp_path) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    directory_target = parent / "secret"
    directory_target.mkdir(mode=0o700)

    with pytest.raises(PrivateFileError):
        private_files.read_private_text(directory_target)


def test_private_store_rejects_wrong_owner(monkeypatch, tmp_path) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    actual_uid = os.geteuid()
    monkeypatch.setattr(private_files.os, "geteuid", lambda: actual_uid + 1)

    with pytest.raises(PrivateFileError):
        private_files.atomic_write_private_text(parent / "secret", "value")


def test_atomic_write_skips_colliding_unique_temp_name(monkeypatch, tmp_path) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    collision = parent / ".secret.collision.tmp"
    collision.write_text("existing", encoding="utf-8")
    tokens = iter(("collision", "fresh"))
    monkeypatch.setattr(private_files.secrets, "token_hex", lambda _: next(tokens))

    private_files.atomic_write_private_text(parent / "secret", "stored")

    assert collision.read_text(encoding="utf-8") == "existing"
    assert private_files.read_private_text(parent / "secret") == "stored"
