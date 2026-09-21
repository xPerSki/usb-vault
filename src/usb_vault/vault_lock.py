"""Per-output locking and stale-temp cleanup for vault operations."""

import contextlib
import logging
import os
import sys
from pathlib import Path

from .exceptions import VaultLockError

logger = logging.getLogger(__name__)

LOCK_SUFFIX = ".vault.lock"
TEMP_SUFFIX = ".vault.tmp"

if sys.platform == "win32":
    import msvcrt

    def _try_lock(fd: int) -> bool:
        """Attempt a non-blocking exclusive lock on 1 byte at offset 0."""
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    def _unlock(fd: int) -> None:
        """Release the lock taken by `_try_lock`."""
        with contextlib.suppress(OSError):
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:  # pragma: no cover
    import fcntl

    def _try_lock(fd: int) -> bool:
        """Attempt a non-blocking exclusive advisory lock on the whole file."""
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        return True

    def _unlock(fd: int) -> None:
        """Release the lock taken by `_try_lock`."""
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)


def _is_link(path: Path) -> bool:
    """Return whether path is a symbolic link, directory junction, or reparse point."""
    try:
        if path.is_symlink():
            return True
        if hasattr(path, "is_junction") and path.is_junction():
            return True
        if sys.platform == "win32":
            st = os.lstat(path)
            if getattr(st, "st_reparse_tag", 0) != 0:
                return True
            if getattr(st, "st_file_attributes", 0) & 0x400:
                return True
        return False
    except OSError:
        return False


def _is_network_or_device_path(path: Path) -> bool:
    """Return whether path is a UNC, network, or raw device path."""
    raw = str(path)
    if raw.startswith(("\\\\", "//")):
        return True
    if sys.platform == "win32":
        drive = path.drive
        if not drive or len(drive) != 2 or drive[1] != ":" or not drive[0].isalpha():
            return True
    return False


class VaultLock:
    """OS-level exclusive lock guarding a single vault output path.

    Held for the full duration of an encrypt or decrypt call so that two
    operations can never target the same output concurrently. The lock is
    bound to an open file descriptor rather than to the mere existence of
    the lock file: if the holding process crashes or is killed, the
    operating system drops the lock automatically, so a later call can
    re-acquire it and treat any leftover files as orphaned.
    """

    __slots__ = ("path", "_fd")

    def __init__(self, output_file: Path) -> None:
        """Bind this lock to `output_file`'s sidecar lock path.

        Args:
            output_file: The vault destination this lock protects. The lock
                file is created alongside it as `<name>.vault.lock`.
        """
        self.path = output_file.with_name(output_file.name + LOCK_SUFFIX)
        self._fd: int | None = None

    def acquire(self) -> None:
        """Create/open the lock file and take a non-blocking exclusive lock.

        Raises:
            VaultLockError: If another live process already holds the lock or
                the lock path is a symbolic link, junction, or hard link.
            OSError: If the lock file itself cannot be created or opened
                (e.g. missing directory, permission denied, disk full).
        """
        if _is_link(self.path):
            raise VaultLockError(f"Lock path '{self.path}' cannot be a symbolic link.")
        if _is_network_or_device_path(self.path):
            raise VaultLockError(f"Lock path '{self.path}' cannot be a network or UNC path.")

        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(self.path), flags, 0o600)
        try:
            stat_res = os.fstat(fd)
            if stat_res.st_nlink > 1:
                raise VaultLockError(f"Lock path '{self.path}' cannot be a hard link.")
            if stat_res.st_size == 0:
                os.write(fd, b"\0")
            if not _try_lock(fd):
                raise VaultLockError(
                    "This output is already being processed by another "
                    "USB Vault operation. Wait for it to finish and try "
                    "again."
                )
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd

    def release(self) -> None:
        """Release the lock and best-effort remove the lock file.

        Safe to call even if `acquire` was never called or failed.
        Deleting the lock file is intentionally best-effort: on Windows, a
        file another process has opened cannot be removed and the
        resulting error is swallowed, leaving that file for the next
        acquirer to deal with. This is safe because correctness rests on
        the lock itself, never on the file's mere presence or absence.
        """
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        _unlock(fd)
        os.close(fd)
        with contextlib.suppress(OSError):
            if not _is_link(self.path):
                self.path.unlink()


def cleanup_orphaned_temps(output_file: Path) -> None:
    """Delete leftover `*.vault.tmp` staging files for `output_file`.

    Must only be called after this process has already acquired
    `output_file`'s `VaultLock`. That acquisition proves any
    pre-existing temp files matching this output can only be left over from
    a crashed or killed prior run, never from one that is still live -
    a live run would still be holding the lock we just took.

    Only files whose name is exactly `<output_file.name>.<anything>`
    ending in `TEMP_SUFFIX` are removed, so this never touches
    unrelated files (other apps' temp files, or a same named file that
    shares a prefix by coincidence).

    Args:
        output_file: The destination path whose staging temps should be
            swept from its parent directory.
    """
    prefix = f"{output_file.name}."
    try:
        candidates = list(output_file.parent.iterdir())
    except OSError as e:
        logger.debug("Skipping orphan temp cleanup for %s: %s", output_file, e)
        return

    for candidate in candidates:
        name = candidate.name
        if not (name.startswith(prefix) and name.endswith(TEMP_SUFFIX)):
            continue
        with contextlib.suppress(OSError):
            candidate.unlink()
