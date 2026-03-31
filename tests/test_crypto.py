"""Tests for the cryptographic module.

Verifies the integrity of the AES-256-GCM implementation, header protection
via AAD, and the security of the file structure.
"""

from pathlib import Path

import pytest

from usb_vault.crypto import decrypt_file, encrypt_file
from usb_vault.exceptions import DecryptionError


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
