"""Tests for the cryptographic module.

Verifies the integrity of the AES-256-GCM implementation, header protection
via AAD, and the security of the file structure.
"""

from pathlib import Path
from unittest.mock import patch

import pytest
from usb_vault.crypto import BUFFER_SIZE, decrypt_file, encrypt_file
from usb_vault.exceptions import DecryptionError, EncryptionError


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


def test_decrypt_rejects_file_with_missing_salt(tmp_path: Path):
    """Invalid vault payloads with a truncated header must fail safely."""
    encrypted_file = tmp_path / "broken.vault"
    out_file = tmp_path / "out.txt"
    encrypted_file.write_bytes(b"short")

    with pytest.raises(DecryptionError) as exc_info:
        decrypt_file("fp", encrypted_file, out_file)

    assert "salt missing" in str(exc_info.value)

    encrypted_file.write_bytes(b"a" * 15)

    with pytest.raises(DecryptionError) as exc_info:
        decrypt_file("fp", encrypted_file, out_file)

    assert "salt missing" in str(exc_info.value)
    assert not out_file.exists()


def test_decrypt_rejects_file_with_missing_nonce(tmp_path: Path):
    """Vault files missing nonce bytes must fail safely."""
    encrypted_file = tmp_path / "broken.vault"
    out_file = tmp_path / "out.txt"
    encrypted_file.write_bytes((b"a" * 16) + b"b")

    with pytest.raises(DecryptionError) as exc_info:
        decrypt_file("fp", encrypted_file, out_file)

    assert "nonce missing" in str(exc_info.value)
    assert not out_file.exists()


def test_encrypt_wraps_input_read_errors(tmp_path: Path):
    """Read failures must be wrapped as EncryptionError, not leaked exceptions."""
    input_file = tmp_path / "plain.txt"
    output_file = tmp_path / "data.vault"
    input_file.write_bytes(b"data")

    with patch("pathlib.Path.open", side_effect=OSError("read blocked")):
        with pytest.raises(EncryptionError) as exc_info:
            encrypt_file("fp", input_file, output_file)

    assert "Encryption Error" in str(exc_info.value)


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

    assert "An error occurred during decryption" in str(exc_info.value)


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
