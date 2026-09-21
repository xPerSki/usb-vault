"""Tests for the cryptographic module.

Verifies the integrity of the AES-256-GCM implementation, header protection
via AAD, and the security of the file structure.
"""

import base64
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from usb_vault.crypto import (
    BUFFER_SIZE,
    DEFAULT_MEMORY_COST,
    DEFAULT_PARALLELISM,
    DEFAULT_TIME_COST,
    FILE_NONCE_SIZE,
    FORMAT_VERSION,
    NAME_NONCE_SIZE,
    NAME_PLAINTEXT_SIZE,
    SALT_SIZE,
    VAULT_MAGIC,
    allocate_stealth_vault_path,
    decrypt_file,
    encrypt_file,
    peek_original_basename,
    peek_vault_format,
    _build_secret,
    _decode_basename,
    _encode_basename,
    _name_aad,
    _pack_header,
    _validate_basename,
)
from usb_vault.exceptions import (
    AuthenticationError,
    DecryptionError,
    EncryptionError,
    IntegrityError,
    InvalidVaultError,
    OperationCancelled,
    VaultLockError,
)
from usb_vault.key_derivation import derive_key, generate_salt
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


def test_cancel_check_aborts_encrypt_and_cleans_up(tmp_path: Path):
    """Cancel mid-encrypt must drop temps/locks and leave the destination untouched."""
    plain = tmp_path / "big.bin"
    vault = tmp_path / "big.bin.vault"
    # Multi-chunk so cancel can fire after the first loop iteration.
    plain.write_bytes(b"x" * (BUFFER_SIZE + 16))

    calls = {"n": 0}

    def cancel_after_first_chunk() -> bool:
        calls["n"] += 1
        return calls["n"] > 1

    with pytest.raises(OperationCancelled, match="Cancelled"):
        encrypt_file("fp", plain, vault, cancel_check=cancel_after_first_chunk)

    assert not vault.exists()
    leftovers = [
        p
        for p in tmp_path.iterdir()
        if p.name.endswith(LOCK_SUFFIX) or p.name.endswith(TEMP_SUFFIX)
    ]
    assert leftovers == []


def test_cancel_check_aborts_decrypt_and_cleans_up(tmp_path: Path):
    """Cancel mid-decrypt must drop temps/locks and leave plaintext untouched."""
    plain = tmp_path / "big.bin"
    vault = tmp_path / "big.bin.vault"
    restored = tmp_path / "restored.bin"
    plain.write_bytes(b"y" * (BUFFER_SIZE + 16))
    encrypt_file("fp", plain, vault)

    calls = {"n": 0}

    def cancel_after_first_chunk() -> bool:
        calls["n"] += 1
        return calls["n"] > 1

    with pytest.raises(OperationCancelled, match="Cancelled"):
        decrypt_file(
            "fp",
            vault,
            restored,
            cancel_check=cancel_after_first_chunk,
        )

    assert not restored.exists()
    leftovers = [
        p
        for p in tmp_path.iterdir()
        if p.name.endswith(LOCK_SUFFIX) or p.name.endswith(TEMP_SUFFIX)
    ]
    assert leftovers == []
    assert vault.exists()


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
        + (2).to_bytes(1, "big")
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


def test_v3_roundtrip_peek_restores_basename(tmp_path: Path):
    """New encrypts write v3 and peek must recover the original basename."""
    fingerprint = "peek-fp"
    input_file = tmp_path / "report.pdf"
    encrypted_file = tmp_path / "a1b2c3d4e5f67890.vault"
    restored = tmp_path / "out.bin"
    input_file.write_bytes(b"document-bytes")

    encrypt_file(fingerprint, input_file, encrypted_file)

    assert encrypted_file.read_bytes()[9] == FORMAT_VERSION
    assert peek_original_basename(fingerprint, encrypted_file) == "report.pdf"

    decrypt_file(fingerprint, encrypted_file, restored)
    assert restored.read_bytes() == b"document-bytes"


def test_allocate_stealth_retries_on_collision(tmp_path: Path):
    """Stealth allocation must skip an existing name then take a free one."""
    taken = tmp_path / "aaaaaaaaaaaaaaaa.vault"
    taken.write_bytes(b"occupied")
    free = tmp_path / "bbbbbbbbbbbbbbbb.vault"
    names = iter(["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"])

    with patch(
        "usb_vault.crypto.secrets.token_hex",
        side_effect=lambda _n: next(names),
    ):
        path = allocate_stealth_vault_path(tmp_path, max_attempts=4)

    assert path == free
    assert not free.exists()


def test_allocate_stealth_exhausted_attempts_raises(tmp_path: Path):
    """Stealth allocation must fail clearly when every candidate exists."""
    existing = tmp_path / "cccccccccccccccc.vault"
    existing.write_bytes(b"occupied")

    with patch(
        "usb_vault.crypto.secrets.token_hex",
        return_value="cccccccccccccccc",
    ):
        with pytest.raises(EncryptionError, match="unique stealth"):
            allocate_stealth_vault_path(tmp_path, max_attempts=3)


def test_peek_returns_none_for_version_two_fixture(tmp_path: Path):
    """Version 2 vaults have no sealed name; peek must return None."""
    fixture = (
        "VVNCLVZBVUxUAgAAAAMAAQAAAAAAAQICAgICAgICAgICAgICAgIDAwMDAwMDA032"
        "+KIW6Byei4gCgPpLcfC1wE/u3vumNjQslX9vLRS9P9b+6l9c2Rs="
    )
    vault = tmp_path / "fixture.vault"
    vault.write_bytes(base64.b64decode(fixture))

    assert (
        peek_original_basename(
            "fixture-fingerprint",
            vault,
            password=b"fixture-passphrase",
        )
        is None
    )


def test_encrypted_vault_does_not_contain_plaintext_basename(tmp_path: Path):
    """Offline inspection must not reveal the original basename in cleartext."""
    fingerprint = "stealth-fp"
    input_file = tmp_path / "secrets.xlsx"
    encrypted_file = tmp_path / "deadbeefcafebabe.vault"
    input_file.write_bytes(b"spreadsheet-bytes")

    encrypt_file(fingerprint, input_file, encrypted_file)

    raw = encrypted_file.read_bytes()
    assert b"secrets.xlsx" not in raw
    assert peek_original_basename(fingerprint, encrypted_file) == "secrets.xlsx"


def test_peek_vault_format_accepts_supported_versions(tmp_path: Path):
    """Header peek must report supported format versions without a key."""
    plain = tmp_path / "note.txt"
    vault = tmp_path / "note.txt.vault"
    plain.write_bytes(b"hello")
    encrypt_file("fp", plain, vault)

    info = peek_vault_format(vault)
    assert info["ok"] is True
    assert info["supported"] is True
    assert info["version"] == FORMAT_VERSION
    assert info["error"] is None


def test_peek_vault_format_rejects_non_vault(tmp_path: Path):
    """Wrong magic must be flagged before any decrypt attempt."""
    junk = tmp_path / "photo.jpg"
    junk.write_bytes(b"not-a-vault")

    info = peek_vault_format(junk)
    assert info["ok"] is False
    assert info["supported"] is False
    assert info["version"] is None
    assert "Not a vault file" in info["error"]


def test_peek_vault_format_flags_future_version(tmp_path: Path):
    """A too-new format version must ask the user to update the app."""
    future = tmp_path / "future.vault"
    future.write_bytes(VAULT_MAGIC + (99).to_bytes(1, "big") + b"\x00" * 20)

    info = peek_vault_format(future)
    assert info["ok"] is True
    assert info["supported"] is False
    assert info["version"] == 99
    assert "newer app" in info["error"]


def test_peek_vault_format_flags_ancient_version(tmp_path: Path):
    """An obsolete format version must be rejected with a clear message."""
    ancient = tmp_path / "v1.vault"
    ancient.write_bytes(VAULT_MAGIC + (1).to_bytes(1, "big") + b"\x00" * 20)

    info = peek_vault_format(ancient)
    assert info["ok"] is True
    assert info["supported"] is False
    assert info["version"] == 1
    assert "not supported" in info["error"]


def test_validate_basename_rejects_drive_anchors_and_traversal():
    """Basenames with drive specifiers or directory traversals must be rejected."""
    for bad in ["D:payload.exe", "C:test.txt", "E:auto.inf", "../secret", "..\\secret", "..", "..."]:
        with pytest.raises((EncryptionError, InvalidVaultError)):
            _validate_basename(bad, for_encryption=True)
        with pytest.raises((EncryptionError, InvalidVaultError)):
            _validate_basename(bad, for_encryption=False)


def test_validate_basename_rejects_forbidden_chars_and_streams():
    """Basenames with NTFS ADS or illegal Win32 characters must be rejected."""
    for bad in ["file.txt:stream", "bad<name>.txt", "pipe|file", "wild*card", "question?mark", 'quote"file']:
        with pytest.raises((EncryptionError, InvalidVaultError)):
            _validate_basename(bad, for_encryption=True)


def test_validate_basename_rejects_dos_device_names():
    """DOS reserved device names must be rejected with or without extensions."""
    for bad in ["CON", "con.txt", "PRN", "aux.dat", "NUL", "nul.tar.gz", "COM1", "com9.log", "LPT1", "CONIN$", "CONOUT$"]:
        with pytest.raises((EncryptionError, InvalidVaultError)):
            _validate_basename(bad, for_encryption=True)


def test_validate_basename_rejects_whitespace_dots_and_control_chars():
    """Leading/trailing whitespace, trailing dots, and control chars must be rejected."""
    for bad in [" bad.txt", "bad.txt ", "trailing.", "test\x00file", "line\nbreak", ""]:
        with pytest.raises((EncryptionError, InvalidVaultError)):
            _validate_basename(bad, for_encryption=True)


def test_validate_basename_accepts_valid_names():
    """Ordinary file names must pass validation cleanly."""
    for valid in ["report.pdf", "data.xlsx", "archive.tar.gz", "photo (1).png", "my_vault_2026-09-18.doc"]:
        _validate_basename(valid, for_encryption=True)
        _validate_basename(valid, for_encryption=False)


def _pack_raw_name(bad_name: str) -> bytes:
    """Pack an arbitrary name string into a 256-byte name plaintext buffer."""
    encoded = bad_name.encode("utf-8")
    plain = bytearray(NAME_PLAINTEXT_SIZE)
    plain[0:2] = len(encoded).to_bytes(2, "big")
    plain[2 : 2 + len(encoded)] = encoded
    return bytes(plain)


def _craft_adversarial_v3_vault(
    vault_path: Path,
    fingerprint: str,
    raw_name_plain: bytes,
    password: str | bytes | bytearray | None = None,
    body_content: bytes = b"payload content",
    tamper_tag: bool = False,
) -> None:
    """Forge a format version 3 vault with arbitrary sealed name plaintext."""
    salt = generate_salt(SALT_SIZE)
    file_nonce = os.urandom(FILE_NONCE_SIZE)
    name_nonce = os.urandom(NAME_NONCE_SIZE)
    base_header = _pack_header(
        salt,
        file_nonce,
        DEFAULT_TIME_COST,
        DEFAULT_MEMORY_COST,
        DEFAULT_PARALLELISM,
        version=3,
    )
    secret = _build_secret(fingerprint, password)
    key = derive_key(
        secret,
        salt,
        time_cost=DEFAULT_TIME_COST,
        memory_cost=DEFAULT_MEMORY_COST,
        parallelism=DEFAULT_PARALLELISM,
    )
    aesgcm = AESGCM(key)
    name_record = aesgcm.encrypt(
        name_nonce,
        raw_name_plain,
        _name_aad(3, salt, file_nonce, name_nonce),
    )
    if tamper_tag:
        tampered = bytearray(name_record)
        tampered[-1] ^= 0x01
        name_record = bytes(tampered)

    public_prefix = base_header + name_nonce + name_record

    chunk_nonce = file_nonce + (0).to_bytes(4, "big")
    aad = public_prefix + salt + chunk_nonce + b"\x01"
    enc_chunk = aesgcm.encrypt(chunk_nonce, body_content, aad)

    vault_path.write_bytes(public_prefix + enc_chunk)


def test_adversarial_v3_vault_rejects_malicious_basenames(tmp_path: Path):
    """Forged v3 vaults with hostile names must fail closed on peek and decrypt."""
    fingerprint = "adversarial-usb-fp"
    password = "adversarial-password"

    hostile_names = [
        "D:payload.exe",
        "C:test.txt",
        "../secret.txt",
        "..\\escape.dll",
        "CON",
        "NUL.tar.gz",
        "PRN",
        "COM1",
        "innocent.txt:hidden.exe",
        "bad<char>.txt",
        "pipe|file",
        "trailing.",
        "space ",
    ]

    for idx, bad_name in enumerate(hostile_names):
        vault_file = tmp_path / f"hostile_{idx}.vault"
        out_file = tmp_path / f"decrypted_{idx}.bin"
        raw_plain = _pack_raw_name(bad_name)

        _craft_adversarial_v3_vault(
            vault_file,
            fingerprint,
            raw_plain,
            password=password,
        )

        # 1. peek_original_basename must fail closed with InvalidVaultError
        with pytest.raises(InvalidVaultError):
            peek_original_basename(fingerprint, vault_file, password)

        # 2. decrypt_file must fail closed with InvalidVaultError
        with pytest.raises(InvalidVaultError):
            decrypt_file(fingerprint, vault_file, out_file, password=password)

        # 3. Output file must not have been created
        assert not out_file.exists()

        # 4. No temporary staging files must remain
        assert list(tmp_path.glob("*.tmp")) == []


def test_adversarial_v3_vault_rejects_malformed_name_plaintexts(tmp_path: Path):
    """Forged v3 vaults with corrupt name layouts must fail closed."""
    fingerprint = "malformed-plain-fp"
    password = "malformed-password"

    # Case A: Non-zero padding
    bad_padding = bytearray(_pack_raw_name("valid.txt"))
    bad_padding[255] = 0xAA

    # Case B: Length prefix out of range (> 254)
    bad_len = bytearray(NAME_PLAINTEXT_SIZE)
    bad_len[0:2] = (NAME_PLAINTEXT_SIZE).to_bytes(2, "big")

    # Case C: Invalid UTF-8 sequence
    bad_utf8 = bytearray(NAME_PLAINTEXT_SIZE)
    bad_utf8[0:2] = (2).to_bytes(2, "big")
    bad_utf8[2:4] = b"\xff\xff"

    # Case D: Empty name (length 0)
    empty_name = bytearray(NAME_PLAINTEXT_SIZE)

    cases = [
        ("bad_padding", bytes(bad_padding)),
        ("bad_len", bytes(bad_len)),
        ("bad_utf8", bytes(bad_utf8)),
        ("empty_name", bytes(empty_name)),
    ]

    for label, raw_plain in cases:
        vault_file = tmp_path / f"corrupt_{label}.vault"
        out_file = tmp_path / f"decrypted_{label}.bin"

        _craft_adversarial_v3_vault(
            vault_file,
            fingerprint,
            raw_plain,
            password=password,
        )

        with pytest.raises(InvalidVaultError):
            peek_original_basename(fingerprint, vault_file, password)

        with pytest.raises(InvalidVaultError):
            decrypt_file(fingerprint, vault_file, out_file, password=password)

        assert not out_file.exists()
        assert list(tmp_path.glob("*.tmp")) == []


def test_adversarial_v3_vault_rejects_tampered_name_record(tmp_path: Path):
    """Tampering with the sealed name record ciphertext must trigger AuthenticationError."""
    fingerprint = "tampered-record-fp"
    password = "tampered-password"

    vault_file = tmp_path / "tampered_record.vault"
    out_file = tmp_path / "decrypted_tampered.bin"
    raw_plain = _pack_raw_name("legitimate.pdf")

    _craft_adversarial_v3_vault(
        vault_file,
        fingerprint,
        raw_plain,
        password=password,
        tamper_tag=True,
    )

    with pytest.raises(AuthenticationError):
        peek_original_basename(fingerprint, vault_file, password)

    with pytest.raises(AuthenticationError):
        decrypt_file(fingerprint, vault_file, out_file, password=password)

    assert not out_file.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_adversarial_v3_vault_rejects_truncated_name_record(tmp_path: Path):
    """Truncated header inside the name record must raise InvalidVaultError."""
    fingerprint = "truncated-record-fp"
    vault_file = tmp_path / "truncated_record.vault"
    out_file = tmp_path / "decrypted_truncated.bin"

    # Write a valid header + name nonce, but only 10 bytes of name record (needs 272)
    salt = generate_salt(SALT_SIZE)
    file_nonce = os.urandom(FILE_NONCE_SIZE)
    base_header = _pack_header(
        salt,
        file_nonce,
        DEFAULT_TIME_COST,
        DEFAULT_MEMORY_COST,
        DEFAULT_PARALLELISM,
        version=3,
    )
    name_nonce = os.urandom(NAME_NONCE_SIZE)
    truncated_record = os.urandom(10)

    vault_file.write_bytes(base_header + name_nonce + truncated_record)

    with pytest.raises(InvalidVaultError):
        peek_original_basename(fingerprint, vault_file)

    with pytest.raises(InvalidVaultError):
        decrypt_file(fingerprint, vault_file, out_file)

    assert not out_file.exists()


def test_decrypt_rejects_hard_link_to_vault(tmp_path: Path):
    """Decrypting where output is a hard link to the vault file must fail closed."""
    fingerprint = "test-fp"
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"content to encrypt")
    vault_file = tmp_path / "data.vault"
    encrypt_file(fingerprint, plain, vault_file)

    hard_link_out = tmp_path / "output.txt"
    try:
        os.link(vault_file, hard_link_out)
    except OSError:
        pytest.skip("Filesystem does not support hard links")

    with pytest.raises(DecryptionError, match="Input and output must be different files"):
        decrypt_file(fingerprint, vault_file, hard_link_out)


def test_encrypt_rejects_symlinks(tmp_path: Path):
    """Encrypting must reject symbolic links for both input and output."""
    fingerprint = "test-fp"
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"data")
    vault_file = tmp_path / "data.vault"

    # Input is symlink, output is not
    def is_symlink_input(self: Path) -> bool:
        return self == plain

    with patch.object(Path, "is_symlink", is_symlink_input):
        with pytest.raises(EncryptionError, match="Symbolic links are not supported"):
            encrypt_file(fingerprint, plain, vault_file)

    # Output is symlink, input is not
    def is_symlink_output(self: Path) -> bool:
        return self == vault_file

    with patch.object(Path, "is_symlink", is_symlink_output):
        with pytest.raises(EncryptionError, match="Symbolic links are not supported"):
            encrypt_file(fingerprint, plain, vault_file)


def test_decrypt_rejects_symlinks(tmp_path: Path):
    """Decrypting must reject symbolic links for both input and output."""
    fingerprint = "test-fp"
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"data")
    vault_file = tmp_path / "data.vault"
    encrypt_file(fingerprint, plain, vault_file)
    out_file = tmp_path / "decrypted.txt"

    # Vault input is symlink, output is not
    def is_symlink_vault(self: Path) -> bool:
        return self == vault_file

    with patch.object(Path, "is_symlink", is_symlink_vault):
        with pytest.raises(DecryptionError, match="Symbolic links are not supported"):
            decrypt_file(fingerprint, vault_file, out_file)

    # Output is symlink, vault is not
    def is_symlink_out(self: Path) -> bool:
        return self == out_file

    with patch.object(Path, "is_symlink", is_symlink_out):
        with pytest.raises(DecryptionError, match="Symbolic links are not supported"):
            decrypt_file(fingerprint, vault_file, out_file)


def test_peek_original_basename_rejects_symlinks(tmp_path: Path):
    """peek_original_basename must reject symbolic links fail-closed."""
    fingerprint = "test-fp"
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"data")
    vault_file = tmp_path / "data.vault"
    encrypt_file(fingerprint, plain, vault_file)

    with patch.object(Path, "is_symlink", return_value=True):
        with pytest.raises(DecryptionError, match="Symbolic links are not supported"):
            peek_original_basename(fingerprint, vault_file)


def test_peek_vault_format_rejects_symlinks(tmp_path: Path):
    """peek_vault_format must return supported=False when candidate is a symlink."""
    vault = tmp_path / "data.vault"
    vault.write_bytes(b"dummy")

    with patch.object(Path, "is_symlink", return_value=True):
        info = peek_vault_format(vault)

    assert info["ok"] is False
    assert info["supported"] is False
    assert "Symbolic links are not supported" in info["error"]


def test_encrypt_rejects_real_junction(tmp_path: Path):
    """Encrypting must reject real Windows junctions."""
    if sys.platform != "win32":
        pytest.skip("Windows junctions only supported on win32")

    import _winapi

    fingerprint = "test-fp"
    target = tmp_path / "target_dir"
    target.mkdir()
    junc = tmp_path / "junc_dir"
    _winapi.CreateJunction(str(target), str(junc))

    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"data")
    vault = tmp_path / "vault.bin"

    with pytest.raises(EncryptionError, match="Symbolic links are not supported"):
        encrypt_file(fingerprint, junc, vault)

    with pytest.raises(EncryptionError, match="Symbolic links are not supported"):
        encrypt_file(fingerprint, plain, junc)


def test_decrypt_rejects_real_junction(tmp_path: Path):
    """Decrypting must reject real Windows junctions."""
    if sys.platform != "win32":
        pytest.skip("Windows junctions only supported on win32")

    import _winapi

    fingerprint = "test-fp"
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"data")
    vault = tmp_path / "vault.bin"
    encrypt_file(fingerprint, plain, vault)

    target = tmp_path / "target_dir"
    target.mkdir()
    junc = tmp_path / "junc_dir"
    _winapi.CreateJunction(str(target), str(junc))

    out_file = tmp_path / "decrypted.txt"

    with pytest.raises(DecryptionError, match="Symbolic links are not supported"):
        decrypt_file(fingerprint, junc, out_file)

    with pytest.raises(DecryptionError, match="Symbolic links are not supported"):
        decrypt_file(fingerprint, vault, junc)


def test_validate_basename_rejects_unicode_bidi_and_format_chars():
    """_validate_basename must reject BiDi overrides, directional isolates, and formatting chars."""
    adversarial_names = [
        "photo\u202egpj.exe",   # RLO (Right-to-Left Override)
        "report\u202dfdp.exe",  # LRO (Left-to-Right Override)
        "doc\u202aembed.pdf",   # LRE (Left-to-Right Embedding)
        "file\u202bembed.pdf",  # RLE (Right-to-Left Embedding)
        "data\u202cpop.pdf",    # PDF (Pop Directional Formatting)
        "scan\u2066iso.pdf",    # LRI (Left-to-Right Isolate)
        "scan\u2067iso.pdf",    # RLI (Right-to-Left Isolate)
        "scan\u2068iso.pdf",    # FSI (First Strong Isolate)
        "scan\u2069iso.pdf",    # PDI (Pop Directional Isolate)
        "secret\u200b.txt",     # Zero-width space
        "secret\u200c.txt",     # Zero-width non-joiner
        "secret\u200d.txt",     # Zero-width joiner
        "\ufeffbom.txt",        # Zero-width no-break space / BOM
        "soft\u00adhyphen.txt", # Soft hyphen
        "word\u2060joiner.txt", # Word joiner
        "arabic\u061cmark.txt", # Arabic Letter Mark
    ]
    for name in adversarial_names:
        with pytest.raises(EncryptionError, match="contains control, bidirectional, or formatting characters"):
            _validate_basename(name, for_encryption=True)
        with pytest.raises(InvalidVaultError, match="contains control, bidirectional, or formatting characters"):
            _validate_basename(name, for_encryption=False)


def test_validate_basename_accepts_valid_international_names():
    """_validate_basename must accept legitimate international unicode filenames."""
    legitimate_names = [
        "dokument_żółć_gęślą_jaźń.pdf",
        "äöü_rechnung.docx",
        "résumé_français.odt",
        "españa_año_2026.xlsx",
        "report (v1.2) [final].tar.gz",
    ]
    for name in legitimate_names:
        _validate_basename(name, for_encryption=True)
        _validate_basename(name, for_encryption=False)


def test_crypto_rejects_network_and_unc_paths(tmp_path: Path):
    """Core crypto functions must reject UNC, network, and raw device paths."""
    unc_path = Path(r"\\evil-server\share\file.vault")
    local_file = tmp_path / "test.txt"
    local_file.write_bytes(b"data")
    fingerprint = "test-fp"

    res = peek_vault_format(unc_path)
    assert res["ok"] is False
    assert "Network and UNC paths are not supported" in res["error"]

    with pytest.raises(DecryptionError, match="Network and UNC paths are not supported"):
        peek_original_basename(fingerprint, unc_path)

    with pytest.raises(EncryptionError, match="Network and UNC paths are not supported"):
        encrypt_file(fingerprint, unc_path, tmp_path / "out.vault")
    with pytest.raises(EncryptionError, match="Network and UNC paths are not supported"):
        encrypt_file(fingerprint, local_file, unc_path)

    with pytest.raises(DecryptionError, match="Network and UNC paths are not supported"):
        decrypt_file(fingerprint, unc_path, tmp_path / "out.txt")
    with pytest.raises(DecryptionError, match="Network and UNC paths are not supported"):
        decrypt_file(fingerprint, local_file, unc_path)





