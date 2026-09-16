"""Tests for the cryptographic module.

Verifies the integrity of the AES-256-GCM implementation, header protection
via AAD, and the security of the file structure.
"""

import base64
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from usb_vault.crypto import (
    BUFFER_SIZE,
    FORMAT_VERSION,
    VAULT_MAGIC,
    decrypt_file,
    encrypt_file,
)
from usb_vault.exceptions import (
    DecryptionError,
    EncryptionError,
    IntegrityError,
    InvalidVaultError,
    VaultLockError,
)
from usb_vault.vault_lock import (
    LOCK_SUFFIX,
    TEMP_SUFFIX,
    VaultLock,
    _try_lock,
    _unlock,
)


def _leave_stale_lock_file(output_file: Path) -> None:
    """Simulate a crash that drops the OS lock but leaves the lock file.

    Mirrors what actually happens when a process holding a
    `VaultLock` is killed: the kernel releases the lock on process
    death, but nothing deletes the sidecar `*.vault.lock` file. Used to
    verify that a later run treats the leftover file as stale rather than as
    proof of a still-running operation.
    """
    lock_path = output_file.with_name(output_file.name + LOCK_SUFFIX)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    os.write(fd, b"\0")
    assert _try_lock(fd)
    _unlock(fd)
    os.close(fd)


def test_encryption_decryption_roundtrip(tmp_path: Path):
    """
    Tests a full encryption and decryption cycle to ensure data integrity.
    """
    password = "my-secret-password"
    original_data = b"This is the secret data"

    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    decrypted_file = tmp_path / "decrypted.txt"

    input_file.write_bytes(original_data)

    encrypt_file(
        fingerprint=password, input_file=input_file, output_file=encrypted_file
    )

    assert encrypted_file.exists()
    assert encrypted_file.read_bytes() != original_data
    assert encrypted_file.stat().st_size > len(original_data)

    decrypt_file(
        fingerprint=password, input_file=encrypted_file, output_file=decrypted_file
    )

    assert decrypted_file.exists()
    assert decrypted_file.read_bytes() == original_data


def test_decrypts_existing_version_two_fixture(tmp_path: Path):
    """Existing v2 vaults must remain readable across core refactors."""
    fixture = (
        "VVNCLVZBVUxUAgAAAAMAAQAAAAAAAQICAgICAgICAgICAgICAgIDAwMDAwMDA032"
        "+KIW6Byei4gCgPpLcfC1wE/u3vumNjQslX9vLRS9P9b+6l9c2Rs="
    )
    vault = tmp_path / "fixture.vault"
    restored = tmp_path / "restored.txt"
    vault.write_bytes(base64.b64decode(fixture))

    decrypt_file(
        "fixture-fingerprint",
        vault,
        restored,
        password=b"fixture-passphrase",
    )

    assert restored.read_bytes() == b"v2 compatibility fixture"


def test_decrypt_with_wrong_fingerprint_fails(tmp_path: Path):
    """
    Ensures that decryption fails with a DecryptionError if the wrong
    fingerprint (password) is used.
    """
    correct_password = "this-is-correct"
    wrong_password = "this-is-wrong"
    original_data = b"some sensitive information"

    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    decrypted_file = tmp_path / "decrypted.txt"

    input_file.write_bytes(original_data)
    encrypt_file(
        fingerprint=correct_password,
        input_file=input_file,
        output_file=encrypted_file,
    )

    with pytest.raises(DecryptionError) as exc_info:
        decrypt_file(
            fingerprint=wrong_password,
            input_file=encrypted_file,
            output_file=decrypted_file,
        )

    assert "Authentication failed" in str(exc_info.value)
    assert not decrypted_file.exists()


def test_decrypt_rejects_file_with_invalid_magic(tmp_path: Path):
    """Files without the USBV magic header must be rejected."""
    encrypted_file = tmp_path / "broken.vault"
    out_file = tmp_path / "out.txt"
    encrypted_file.write_bytes(b"NOT_A_VAULT_FILE")

    with pytest.raises(DecryptionError) as exc_info:
        decrypt_file("fp", encrypted_file, out_file)

    assert "Not a valid vault file" in str(exc_info.value)
    assert not out_file.exists()


def test_decrypt_rejects_unsupported_version(tmp_path: Path):
    """Vault files declaring an unsupported format version must be rejected."""
    encrypted_file = tmp_path / "broken.vault"
    out_file = tmp_path / "out.txt"
    encrypted_file.write_bytes(b"USB-VAULT\x01" + b"\x00" * 24)

    with pytest.raises(InvalidVaultError) as exc_info:
        decrypt_file("fp", encrypted_file, out_file)

    assert "version mismatch" in str(exc_info.value)
    assert not out_file.exists()


def test_decrypt_rejects_file_with_missing_params(tmp_path: Path):
    """Vault files with a valid header but truncated Argon2 params must fail."""
    encrypted_file = tmp_path / "broken.vault"
    out_file = tmp_path / "out.txt"
    encrypted_file.write_bytes(
        VAULT_MAGIC + FORMAT_VERSION.to_bytes(1, "big") + b"\x00" * 4
    )

    with pytest.raises(InvalidVaultError) as exc_info:
        decrypt_file("fp", encrypted_file, out_file)

    assert "Argon2 parameters missing" in str(exc_info.value)
    assert not out_file.exists()


def test_decrypt_rejects_file_with_missing_salt(tmp_path: Path):
    """Vault files with a valid header but truncated salt must fail safely."""
    encrypted_file = tmp_path / "broken.vault"
    out_file = tmp_path / "out.txt"
    encrypted_file.write_bytes(
        VAULT_MAGIC + FORMAT_VERSION.to_bytes(1, "big") + b"\x00" * 12 + b"a" * 10
    )

    with pytest.raises(InvalidVaultError) as exc_info:
        decrypt_file("fp", encrypted_file, out_file)

    assert "salt missing" in str(exc_info.value)
    assert not out_file.exists()


def test_decrypt_rejects_file_with_missing_nonce(tmp_path: Path):
    """Vault files with valid header and salt but truncated nonce must fail safely."""
    encrypted_file = tmp_path / "broken.vault"
    out_file = tmp_path / "out.txt"
    encrypted_file.write_bytes(
        VAULT_MAGIC
        + FORMAT_VERSION.to_bytes(1, "big")
        + b"\x00" * 12
        + (b"a" * 16)
        + b"b"
    )

    with pytest.raises(InvalidVaultError) as exc_info:
        decrypt_file("fp", encrypted_file, out_file)

    assert "nonce missing" in str(exc_info.value)
    assert not out_file.exists()


def test_tampering_with_header_params_fails(tmp_path: Path):
    """Corrupting an Argon2 parameter byte must fail decryption, not silently
    accept.

    The parameters feed key derivation and are also bound into the first
    chunk's AAD, so any change to a still-valid parameter value must be
    rejected rather than producing a wrong-but-accepted plaintext.
    """
    fingerprint = "header-aad-fingerprint"
    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    decrypted_file = tmp_path / "out.txt"
    input_file.write_bytes(b"protect the header")

    encrypt_file(fingerprint, input_file, encrypted_file)

    raw = bytearray(encrypted_file.read_bytes())
    # Flip the lowest bit of memory_cost (offset 9+1+8 = 17) so the value stays
    # valid (65536 -> 65537) but no longer matches what was used to encrypt.
    raw[17] ^= 0x01
    encrypted_file.write_bytes(raw)

    with pytest.raises(DecryptionError):
        decrypt_file(fingerprint, encrypted_file, decrypted_file)

    assert not decrypted_file.exists()


def test_encrypt_wraps_input_read_errors(tmp_path: Path):
    """Read failures must be wrapped as EncryptionError, not leaked exceptions."""
    input_file = tmp_path / "plain.txt"
    output_file = tmp_path / "data.vault"
    input_file.write_bytes(b"data")

    with patch("pathlib.Path.open", side_effect=OSError("read blocked")):
        with pytest.raises(EncryptionError) as exc_info:
            encrypt_file("fp", input_file, output_file)

    assert "Encryption failed" in str(exc_info.value)


def test_decrypt_wraps_output_write_errors(tmp_path: Path):
    """Write failures during decryption must be wrapped as DecryptionError."""
    fingerprint = "safe-fingerprint"
    plain = tmp_path / "plain.txt"
    vault = tmp_path / "data.vault"
    output_file = tmp_path / "decrypted.txt"
    plain.write_bytes(b"payload")
    encrypt_file(fingerprint, plain, vault)

    with patch("pathlib.Path.open", side_effect=OSError("disk full")):
        with pytest.raises(DecryptionError) as exc_info:
            decrypt_file(fingerprint, vault, output_file)

    assert "Decryption failed" in str(exc_info.value)


def test_roundtrip_with_optional_password(tmp_path: Path):
    """Encryption and decryption should succeed with the same optional password."""
    fingerprint = "usb-fingerprint"
    optional_password = "extra-secret"
    original_data = b"sensitive-bytes"

    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    decrypted_file = tmp_path / "out.txt"
    input_file.write_bytes(original_data)

    encrypt_file(fingerprint, input_file, encrypted_file, password=optional_password)
    decrypt_file(
        fingerprint, encrypted_file, decrypted_file, password=optional_password
    )

    assert decrypted_file.read_bytes() == original_data


def test_decrypt_with_wrong_optional_password_fails(tmp_path: Path):
    """Wrong optional password should fail authentication safely."""
    fingerprint = "usb-fingerprint"
    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    decrypted_file = tmp_path / "out.txt"
    input_file.write_bytes(b"payload")

    encrypt_file(fingerprint, input_file, encrypted_file, password="right")

    with pytest.raises(DecryptionError) as exc_info:
        decrypt_file(fingerprint, encrypted_file, decrypted_file, password="wrong")

    assert "Authentication failed" in str(exc_info.value)
    assert not decrypted_file.exists()


def test_roundtrip_large_file_uses_buffered_path(tmp_path: Path):
    """Large files should still decrypt correctly when processed via the multi-chunk streaming path."""
    fingerprint = "large-file-fingerprint"
    original_data = (b"0123456789ABCDEF" * 20000) + b"tail"

    input_file = tmp_path / "large.bin"
    encrypted_file = tmp_path / "large.vault"
    decrypted_file = tmp_path / "large.out"
    input_file.write_bytes(original_data)

    encrypt_file(fingerprint, input_file, encrypted_file)
    decrypt_file(fingerprint, encrypted_file, decrypted_file)

    assert decrypted_file.read_bytes() == original_data


def test_decrypt_fails_when_password_expected_but_missing(tmp_path: Path):
    """Decrypting without the optional password must fail if encryption used one."""
    fingerprint = "usb-fingerprint"
    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    output_file = tmp_path / "out.txt"
    input_file.write_bytes(b"secret")

    encrypt_file(fingerprint, input_file, encrypted_file, password="with-pass")

    with pytest.raises(DecryptionError):
        decrypt_file(fingerprint, encrypted_file, output_file)

    assert not output_file.exists()


def test_decrypt_fails_when_password_not_expected_but_provided(tmp_path: Path):
    """Providing a password for USB-only encrypted data must fail authentication."""
    fingerprint = "usb-fingerprint"
    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    output_file = tmp_path / "out.txt"
    input_file.write_bytes(b"secret")

    encrypt_file(fingerprint, input_file, encrypted_file)

    with pytest.raises(DecryptionError):
        decrypt_file(fingerprint, encrypted_file, output_file, password="extra")

    assert not output_file.exists()


def test_roundtrip_exact_buffer_boundary(tmp_path: Path):
    """Roundtrip should remain correct for payload sizes exactly at buffer boundaries."""
    fingerprint = "boundary-fingerprint"
    original_data = b"A" * BUFFER_SIZE

    input_file = tmp_path / "boundary.bin"
    encrypted_file = tmp_path / "boundary.vault"
    decrypted_file = tmp_path / "boundary.out"
    input_file.write_bytes(original_data)

    encrypt_file(fingerprint, input_file, encrypted_file)
    decrypt_file(fingerprint, encrypted_file, decrypted_file)

    assert decrypted_file.read_bytes() == original_data


def test_encrypt_rejects_same_input_and_output(tmp_path: Path):
    """Encryption must never overwrite its own source path."""
    source = tmp_path / "plain.txt"
    original = b"must remain intact"
    source.write_bytes(original)

    with pytest.raises(EncryptionError, match="different files"):
        encrypt_file("fp", source, source)

    assert source.read_bytes() == original


def test_decrypt_rejects_same_input_and_output(tmp_path: Path):
    """Decryption must never replace its vault source in place."""
    plain = tmp_path / "plain.txt"
    vault = tmp_path / "data.vault"
    plain.write_bytes(b"payload")
    encrypt_file("fp", plain, vault)
    original_vault = vault.read_bytes()

    with pytest.raises(DecryptionError, match="different files"):
        decrypt_file("fp", vault, vault)

    assert vault.read_bytes() == original_vault


def test_encrypt_rejects_hard_link_to_input(tmp_path: Path):
    """Different path names must not bypass the same-file protection."""
    source = tmp_path / "plain.txt"
    alias = tmp_path / "alias.txt"
    source.write_bytes(b"must remain intact")
    os.link(source, alias)

    with pytest.raises(EncryptionError, match="different files"):
        encrypt_file("fp", source, alias)

    assert source.read_bytes() == b"must remain intact"


def test_progress_callback_failure_does_not_abort_operation(tmp_path: Path):
    """A broken UI callback must not corrupt an otherwise valid operation."""
    plain = tmp_path / "plain.txt"
    vault = tmp_path / "data.vault"
    restored = tmp_path / "restored.txt"
    original = b"payload"
    plain.write_bytes(original)

    def broken_callback(_done: int, _total: int) -> None:
        raise RuntimeError("presentation failed")

    encrypt_file("fp", plain, vault, progress_callback=broken_callback)
    decrypt_file("fp", vault, restored, progress_callback=broken_callback)

    assert restored.read_bytes() == original


def test_decrypt_enforces_chunk_counter_limit(tmp_path: Path):
    """Decrypt must reject counters that cannot fit the nonce format."""
    plain = tmp_path / "plain.txt"
    vault = tmp_path / "data.vault"
    restored = tmp_path / "restored.txt"
    plain.write_bytes(b"x" * (BUFFER_SIZE + 1))
    encrypt_file("fp", plain, vault)

    with patch("usb_vault.crypto.MAX_CHUNK_COUNT", 0):
        with pytest.raises(IntegrityError, match="chunk count"):
            decrypt_file("fp", vault, restored)

    assert not restored.exists()


def test_blank_fingerprint_is_rejected(tmp_path: Path):
    """A missing hardware identity must never produce a constant vault key."""
    plain = tmp_path / "plain.txt"
    vault = tmp_path / "data.vault"
    plain.write_bytes(b"payload")

    with pytest.raises(EncryptionError, match="fingerprint"):
        encrypt_file("   ", plain, vault)

    assert not vault.exists()


def test_decrypt_rejects_trailing_garbage(tmp_path: Path):
    """Appending bytes to a valid vault file must fail safely."""
    fingerprint = "safe-fingerprint"
    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    decrypted_file = tmp_path / "out.txt"

    input_file.write_bytes(b"secret payload")
    encrypt_file(fingerprint, input_file, encrypted_file)

    with encrypted_file.open("ab") as f:
        f.write(b"x")

    with pytest.raises(DecryptionError):
        decrypt_file(fingerprint, encrypted_file, decrypted_file)

    assert not decrypted_file.exists()


def _hostile_vault_header(
    *, time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 1
) -> bytes:
    """Build a minimal v2 header with attacker-chosen Argon2 costs."""
    return (
        VAULT_MAGIC
        + FORMAT_VERSION.to_bytes(1, "big")
        + time_cost.to_bytes(4, "big")
        + memory_cost.to_bytes(4, "big")
        + parallelism.to_bytes(4, "big")
        + (b"\x00" * 16)
        + (b"\x00" * 8)
        + (b"\x00" * 32)
    )


def test_decrypt_rejects_hostile_memory_cost(tmp_path: Path):
    """Oversized memory_cost in the header must fail before Argon2 allocates."""
    encrypted_file = tmp_path / "hostile.vault"
    out_file = tmp_path / "out.txt"
    # 2 TiB in KiB — would OOM without the cap.
    encrypted_file.write_bytes(
        _hostile_vault_header(memory_cost=2 * 1024 * 1024 * 1024)
    )

    with pytest.raises(InvalidVaultError) as exc_info:
        decrypt_file("fp", encrypted_file, out_file)

    assert "Argon2 parameters" in str(exc_info.value)
    assert not out_file.exists()


def test_decrypt_rejects_hostile_time_cost(tmp_path: Path):
    """time_cost above the cap must be rejected as an invalid vault."""
    encrypted_file = tmp_path / "hostile.vault"
    out_file = tmp_path / "out.txt"
    encrypted_file.write_bytes(_hostile_vault_header(time_cost=11))

    with pytest.raises(InvalidVaultError) as exc_info:
        decrypt_file("fp", encrypted_file, out_file)

    assert "Argon2 parameters" in str(exc_info.value)
    assert not out_file.exists()


def test_decrypt_rejects_oversized_parallelism(tmp_path: Path):
    """parallelism above the cap must be rejected as an invalid vault."""
    encrypted_file = tmp_path / "hostile.vault"
    out_file = tmp_path / "out.txt"
    encrypted_file.write_bytes(_hostile_vault_header(parallelism=5))

    with pytest.raises(InvalidVaultError) as exc_info:
        decrypt_file("fp", encrypted_file, out_file)

    assert "Argon2 parameters" in str(exc_info.value)
    assert not out_file.exists()


def test_encrypt_rejects_concurrent_same_output(tmp_path: Path):
    """A second encrypt targeting a locked output must fail immediately."""
    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    input_file.write_bytes(b"payload")

    held_lock = VaultLock(encrypted_file)
    held_lock.acquire()
    try:
        with pytest.raises(VaultLockError):
            encrypt_file("fp", input_file, encrypted_file)
    finally:
        held_lock.release()

    # The output must be untouched: no other operation was ever allowed to
    # start writing to it while the lock was held.
    assert not encrypted_file.exists()


def test_decrypt_rejects_concurrent_same_output(tmp_path: Path):
    """A second decrypt targeting a locked output must fail immediately."""
    fingerprint = "fp"
    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    output_file = tmp_path / "out.txt"
    input_file.write_bytes(b"payload")
    encrypt_file(fingerprint, input_file, encrypted_file)

    held_lock = VaultLock(output_file)
    held_lock.acquire()
    try:
        with pytest.raises(VaultLockError):
            decrypt_file(fingerprint, encrypted_file, output_file)
    finally:
        held_lock.release()

    assert not output_file.exists()


def test_concurrent_lock_does_not_disturb_unrelated_output(tmp_path: Path):
    """Locking one output must never block an operation on a different one."""
    fingerprint = "fp"
    input_file = tmp_path / "plain.txt"
    other_output = tmp_path / "other.vault"
    busy_output = tmp_path / "busy.vault"
    input_file.write_bytes(b"payload")

    held_lock = VaultLock(busy_output)
    held_lock.acquire()
    try:
        encrypt_file(fingerprint, input_file, other_output)  # must not raise
    finally:
        held_lock.release()

    assert other_output.exists()


def test_encrypt_leaves_no_lock_or_temp_after_success(tmp_path: Path):
    """A successful encrypt must leave neither a lock file nor a temp file."""
    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    input_file.write_bytes(b"payload")

    encrypt_file("fp", input_file, encrypted_file)

    leftovers = [
        p
        for p in tmp_path.iterdir()
        if p.name.endswith(LOCK_SUFFIX) or p.name.endswith(TEMP_SUFFIX)
    ]
    assert leftovers == []


def test_decrypt_leaves_no_lock_or_temp_after_success(tmp_path: Path):
    """A successful decrypt must leave neither a lock file nor a temp file."""
    fingerprint = "fp"
    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    output_file = tmp_path / "out.txt"
    input_file.write_bytes(b"payload")
    encrypt_file(fingerprint, input_file, encrypted_file)

    decrypt_file(fingerprint, encrypted_file, output_file)

    leftovers = [
        p
        for p in tmp_path.iterdir()
        if p.name.endswith(LOCK_SUFFIX) or p.name.endswith(TEMP_SUFFIX)
    ]
    assert leftovers == []


def test_encrypt_leaves_no_lock_or_temp_after_failure(tmp_path: Path):
    """A failed encrypt must still release its lock and clean up its temp."""
    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    input_file.write_bytes(b"payload")

    with patch("pathlib.Path.open", side_effect=OSError("read blocked")):
        with pytest.raises(EncryptionError):
            encrypt_file("fp", input_file, encrypted_file)

    leftovers = [
        p
        for p in tmp_path.iterdir()
        if p.name.endswith(LOCK_SUFFIX) or p.name.endswith(TEMP_SUFFIX)
    ]
    assert leftovers == []


def test_temp_cleanup_error_does_not_hide_encryption_error(tmp_path: Path):
    """Cleanup trouble must not replace the operation's domain exception."""
    input_file = tmp_path / "plain.txt"
    output_file = tmp_path / "data.vault"
    input_file.write_bytes(b"payload")

    with (
        patch("usb_vault.crypto.AESGCM.encrypt", side_effect=RuntimeError("failed")),
        patch("usb_vault.crypto.Path.unlink", side_effect=OSError("cleanup failed")),
        pytest.raises(EncryptionError),
    ):
        encrypt_file("fp", input_file, output_file)


def test_decrypt_leaves_no_lock_or_temp_after_failure(tmp_path: Path):
    """A failed decrypt must still release its lock and clean up its temp."""
    fingerprint = "fp"
    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    output_file = tmp_path / "out.txt"
    input_file.write_bytes(b"payload")
    encrypt_file(fingerprint, input_file, encrypted_file)

    with pytest.raises(DecryptionError):
        decrypt_file("wrong-fingerprint", encrypted_file, output_file)

    leftovers = [
        p
        for p in tmp_path.iterdir()
        if p.name.endswith(LOCK_SUFFIX) or p.name.endswith(TEMP_SUFFIX)
    ]
    assert leftovers == []


def test_encrypt_recovers_from_crash_leftovers(tmp_path: Path):
    """A retry after a simulated crash must clean up and still succeed.

    Simulates a process killed mid-encrypt: a lock file whose OS-level lock
    has already been released (as the kernel does on process death) plus an
    orphaned staging temp for the same destination. A fresh call must detect
    the lock as stale, sweep the orphan, and complete normally.
    """
    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    input_file.write_bytes(b"payload after a simulated crash")

    _leave_stale_lock_file(encrypted_file)

    orphan_temp = tmp_path / f"data.vault.deadbeef{TEMP_SUFFIX}"
    orphan_temp.write_bytes(b"partial ciphertext from the crashed run")

    encrypt_file("fp", input_file, encrypted_file)

    assert encrypted_file.exists()
    assert not orphan_temp.exists()
    leftovers = [
        p
        for p in tmp_path.iterdir()
        if p.name.endswith(LOCK_SUFFIX) or p.name.endswith(TEMP_SUFFIX)
    ]
    assert leftovers == []


def test_decrypt_recovers_from_crash_leftovers(tmp_path: Path):
    """A retry after a simulated crash must clean up and still succeed."""
    fingerprint = "fp"
    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    output_file = tmp_path / "out.txt"
    input_file.write_bytes(b"payload after a simulated crash")
    encrypt_file(fingerprint, input_file, encrypted_file)

    _leave_stale_lock_file(output_file)

    orphan_temp = tmp_path / f"out.txt.deadbeef{TEMP_SUFFIX}"
    orphan_temp.write_bytes(b"partial plaintext from the crashed run")

    decrypt_file(fingerprint, encrypted_file, output_file)

    assert output_file.read_bytes() == b"payload after a simulated crash"
    assert not orphan_temp.exists()
    leftovers = [
        p
        for p in tmp_path.iterdir()
        if p.name.endswith(LOCK_SUFFIX) or p.name.endswith(TEMP_SUFFIX)
    ]
    assert leftovers == []


def test_orphan_temp_for_different_output_survives_cleanup(tmp_path: Path):
    """Cleanup for one output must never remove another output's temp."""
    fingerprint = "fp"
    input_file = tmp_path / "plain.txt"
    encrypted_file = tmp_path / "data.vault"
    input_file.write_bytes(b"payload")

    unrelated_orphan = tmp_path / f"someone-else.vault.deadbeef{TEMP_SUFFIX}"
    unrelated_orphan.write_bytes(b"belongs to a different destination")

    encrypt_file(fingerprint, input_file, encrypted_file)

    assert unrelated_orphan.exists()
