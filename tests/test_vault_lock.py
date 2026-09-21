"""Tests for per-output locking and stale-temp cleanup."""

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from usb_vault.exceptions import VaultLockError
from usb_vault.vault_lock import (
    LOCK_SUFFIX,
    TEMP_SUFFIX,
    VaultLock,
    _try_lock,
    _unlock,
    cleanup_orphaned_temps,
)


def test_acquire_creates_lock_file(tmp_path: Path):
    """Acquiring a lock must create the sidecar `*.vault.lock` file."""
    output = tmp_path / "secret.vault"
    lock = VaultLock(output)

    lock.acquire()
    try:
        assert lock.path == tmp_path / f"secret.vault{LOCK_SUFFIX}"
        assert lock.path.exists()
    finally:
        lock.release()


def test_release_removes_lock_file_when_uncontended(tmp_path: Path):
    """A cleanly released lock must remove its own lock file."""
    output = tmp_path / "secret.vault"
    lock = VaultLock(output)

    lock.acquire()
    lock.release()

    assert not lock.path.exists()


def test_release_is_safe_without_prior_acquire(tmp_path: Path):
    """Releasing a lock that was never acquired must be a harmless no-op."""
    lock = VaultLock(tmp_path / "secret.vault")
    lock.release()  # must not raise


def test_second_acquire_on_same_output_is_rejected(tmp_path: Path):
    """Two live locks on the same output must never coexist."""
    output = tmp_path / "secret.vault"
    first = VaultLock(output)
    second = VaultLock(output)

    first.acquire()
    try:
        with pytest.raises(VaultLockError):
            second.acquire()
    finally:
        first.release()


def test_lock_on_different_outputs_does_not_conflict(tmp_path: Path):
    """Locks on distinct outputs must be fully independent."""
    lock_a = VaultLock(tmp_path / "a.vault")
    lock_b = VaultLock(tmp_path / "b.vault")

    lock_a.acquire()
    try:
        lock_b.acquire()  # must not raise
        lock_b.release()
    finally:
        lock_a.release()


def test_acquire_succeeds_after_release(tmp_path: Path):
    """Once released, the same output can be locked again immediately."""
    output = tmp_path / "secret.vault"
    lock = VaultLock(output)

    lock.acquire()
    lock.release()

    lock2 = VaultLock(output)
    lock2.acquire()  # must not raise
    lock2.release()


def test_crashed_holder_lock_is_detected_as_stale(tmp_path: Path):
    """Simulates a process that died while holding the lock.

    A crash releases the OS-level lock (the OS does this automatically when
    the process' file descriptors close) but can leave the lock file on
    disk. A fresh `VaultLock` must still be able to acquire it,
    proving that mere file presence is never treated as "in use".
    """
    output = tmp_path / "secret.vault"
    lock_path = output.with_name(output.name + LOCK_SUFFIX)

    # Simulate a crashed holder: lock taken, then the OS-level lock released
    # (as the kernel would on process death) without deleting the file.
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    os.write(fd, b"\0")
    assert _try_lock(fd)
    _unlock(fd)
    os.close(fd)

    assert lock_path.exists()  # orphaned file remains, as after a real crash

    fresh = VaultLock(output)
    fresh.acquire()  # must succeed: no live holder, despite the leftover file
    fresh.release()


def test_cleanup_removes_matching_orphaned_temp(tmp_path: Path):
    """Temp files matching this output's naming convention must be removed."""
    output = tmp_path / "secret.vault"
    orphan = tmp_path / f"secret.vault.ab12cd{TEMP_SUFFIX}"
    orphan.write_bytes(b"leftover plaintext or ciphertext")

    cleanup_orphaned_temps(output)

    assert not orphan.exists()


def test_cleanup_ignores_unrelated_files(tmp_path: Path):
    """Cleanup must never touch files outside its exact naming convention."""
    output = tmp_path / "secret.vault"

    unrelated_tmp = tmp_path / "other-app.tmp"
    unrelated_tmp.write_bytes(b"belongs to something else")

    similar_prefix_wrong_suffix = tmp_path / "secret.vault.ab12cd.tmp"
    similar_prefix_wrong_suffix.write_bytes(b"not ours: missing .vault.tmp suffix")

    different_output_temp = tmp_path / f"other.vault.ab12cd{TEMP_SUFFIX}"
    different_output_temp.write_bytes(b"belongs to a different destination")

    the_lock_file = tmp_path / f"secret.vault{LOCK_SUFFIX}"
    the_lock_file.write_bytes(b"\0")

    cleanup_orphaned_temps(output)

    assert unrelated_tmp.exists()
    assert similar_prefix_wrong_suffix.exists()
    assert different_output_temp.exists()
    assert the_lock_file.exists()


def test_cleanup_on_missing_directory_does_not_raise(tmp_path: Path):
    """Cleanup must degrade gracefully if the output directory is gone."""
    output = tmp_path / "missing-dir" / "secret.vault"
    cleanup_orphaned_temps(output)  # must not raise


def test_vault_lock_rejects_hard_link_lock_file(tmp_path: Path):
    """Acquiring a lock whose lock file is a hard link must fail closed."""
    output = tmp_path / "secret.vault"
    lock_path = tmp_path / f"secret.vault{LOCK_SUFFIX}"
    lock_path.write_bytes(b"\0")

    other_link = tmp_path / "alias.lock"
    try:
        os.link(lock_path, other_link)
    except OSError:
        pytest.skip("Filesystem does not support hard links")

    lock = VaultLock(output)
    with pytest.raises(VaultLockError, match="cannot be a hard link"):
        lock.acquire()


def test_vault_lock_rejects_symlink_lock_file(tmp_path: Path):
    """Acquiring or releasing a lock file that is a symlink must fail closed."""
    output = tmp_path / "secret.vault"
    lock = VaultLock(output)

    with patch.object(Path, "is_symlink", return_value=True):
        with pytest.raises(VaultLockError, match="cannot be a symbolic link"):
            lock.acquire()

    # In release(), ensure it never unlinks a symlink
    lock_path = tmp_path / f"secret.vault{LOCK_SUFFIX}"
    lock_path.write_bytes(b"\0")
    lock._fd = os.open(str(lock_path), os.O_RDWR)
    with patch.object(Path, "is_symlink", return_value=True), patch.object(Path, "unlink") as mock_unlink:
        lock.release()
        mock_unlink.assert_not_called()


def test_vault_lock_rejects_real_junction_lock_file(tmp_path: Path):
    """Acquiring or releasing a lock file that is a real Windows junction must fail closed."""
    if sys.platform != "win32":
        pytest.skip("Windows junctions only supported on win32")

    import _winapi

    output = tmp_path / "secret.vault"
    target_dir = tmp_path / "target_dir"
    target_dir.mkdir()
    lock_path = tmp_path / f"secret.vault{LOCK_SUFFIX}"

    _winapi.CreateJunction(str(target_dir), str(lock_path))

    lock = VaultLock(output)
    with pytest.raises(VaultLockError, match="cannot be a symbolic link"):
        lock.acquire()

    # In release(), ensure it never unlinks a junction
    lock._fd = 999
    with patch("usb_vault.vault_lock._unlock"), patch("os.close"):
        lock.release()
    assert lock_path.exists()


