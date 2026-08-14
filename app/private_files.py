from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


class PrivateFileError(OSError):
    """Raised when a sensitive file cannot be accessed safely."""


def _require_posix_primitives() -> None:
    required = ("O_NOFOLLOW", "O_DIRECTORY", "geteuid")
    if any(not hasattr(os, name) for name in required):
        raise PrivateFileError(
            "Secure private-file storage requires POSIX no-follow semantics."
        )


def _validate_owner_and_mode(
    details: os.stat_result,
    *,
    expected_mode: int,
    kind: str,
) -> None:
    if details.st_uid != os.geteuid():
        raise PrivateFileError(f"Private {kind} is not owned by this process user.")
    if stat.S_IMODE(details.st_mode) != expected_mode:
        raise PrivateFileError(f"Private {kind} must have mode {expected_mode:04o}.")


def _open_private_directory(path: Path) -> int:
    _require_posix_primitives()
    path.mkdir(mode=PRIVATE_DIRECTORY_MODE, parents=True, exist_ok=True)

    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode):
        raise PrivateFileError("Private-file parent must be a real directory.")
    _validate_owner_and_mode(
        details,
        expected_mode=PRIVATE_DIRECTORY_MODE,
        kind="directory",
    )

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PrivateFileError("Could not safely open private-file parent.") from exc

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode):
            raise PrivateFileError("Private-file parent is not a directory.")
        _validate_owner_and_mode(
            opened,
            expected_mode=PRIVATE_DIRECTORY_MODE,
            kind="directory",
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _validate_private_file(details: os.stat_result) -> None:
    if not stat.S_ISREG(details.st_mode):
        raise PrivateFileError("Private path must be a regular file.")
    _validate_owner_and_mode(
        details,
        expected_mode=PRIVATE_FILE_MODE,
        kind="file",
    )
    if details.st_nlink != 1:
        raise PrivateFileError("Private file must have exactly one hard link.")


def _validate_existing_target(directory_fd: int, name: str) -> None:
    try:
        details = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    _validate_private_file(details)


def read_private_bytes(path: Path) -> bytes:
    """Read a private regular file without following its final symlink."""

    path = Path(path)
    directory_fd = _open_private_directory(path.parent)
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        try:
            descriptor = os.open(path.name, flags, dir_fd=directory_fd)
        except OSError as exc:
            if isinstance(exc, FileNotFoundError):
                raise
            raise PrivateFileError("Could not safely open private file.") from exc
        try:
            _validate_private_file(os.fstat(descriptor))
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_fd)


def read_private_text(path: Path) -> str:
    try:
        return read_private_bytes(path).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PrivateFileError("Private file is not valid UTF-8.") from exc


def atomic_write_private_bytes(path: Path, content: bytes) -> None:
    """Atomically replace a private file using a unique no-follow temp file."""

    path = Path(path)
    directory_fd = _open_private_directory(path.parent)
    temporary_name: str | None = None
    descriptor: int | None = None
    try:
        _validate_existing_target(directory_fd, path.name)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        flags |= getattr(os, "O_CLOEXEC", 0)
        for _ in range(32):
            candidate = f".{path.name}.{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    candidate,
                    flags,
                    PRIVATE_FILE_MODE,
                    dir_fd=directory_fd,
                )
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if descriptor is None or temporary_name is None:
            raise PrivateFileError("Could not allocate a unique private temp file.")

        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        _validate_private_file(os.fstat(descriptor))
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PrivateFileError("Could not write complete private file.")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None

        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary_name = None

        verify_fd = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_fd,
        )
        try:
            _validate_private_file(os.fstat(verify_fd))
        finally:
            os.close(verify_fd)
        os.fsync(directory_fd)
    except PrivateFileError:
        raise
    except OSError as exc:
        raise PrivateFileError("Could not atomically store private file.") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def atomic_write_private_text(path: Path, content: str) -> None:
    atomic_write_private_bytes(path, content.encode("utf-8"))
