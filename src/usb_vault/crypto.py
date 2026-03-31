"""Cryptographic module for file encryption and decryption.

This module provides the core cryptographic operations for the USB Vault
application, utilizing AES-256-GCM for authenticated encryption.
"""

import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import DecryptionError, EncryptionError
from .key_derivation import derive_key, generate_salt


def encrypt_file(fingerprint: str, input_file: Path, output_file: Path) -> None:
    """Encrypts a file using AES-256-GCM.

    Process:
    1. Generates a 16-byte random salt (os.urandom).
    2. Derives a 32-byte key using Argon2id from the USB fingerprint and salt.
    3. Generates a 12-byte unique nonce (os.urandom) for AES-GCM.
    4. Creates AAD (Additional Authenticated Data) from the concatenation of salt
       and nonce to protect the file header from manipulation.
    5. Encrypts the file content, generating a 16-byte Tag (MAC) at the end.
    6. Writes the resulting file structure:
       [Salt(16)] | [Nonce(12)] | [Ciphertext] | [Tag(16)].

    Args:
        fingerprint: USB fingerprint (unique identifier) of the hardware key.
        input_file: Path to the input file.
        output_file: Path to the output file.

    Raises:
        EncryptionError: If an error occurs during the encryption process.
    """
    key = b""
    try:
        salt = generate_salt(16)
        nonce = os.urandom(12)

        key = derive_key(fingerprint, salt)
        aesgcm = AESGCM(key)

        aad = salt + nonce
        data = input_file.read_bytes()
        encrypted_data = aesgcm.encrypt(nonce, data, aad)

        with output_file.open("wb") as f:
            f.write(salt)
            f.write(nonce)
            f.write(encrypted_data)

    except Exception as e:
        raise EncryptionError(f"Encryption Error: {str(e)}") from e
    finally:
        if key:
            # Overwrite key in memory for security
            key = b"\x00" * len(key)
            del key


def decrypt_file(fingerprint: str, input_file: Path, output_file: Path) -> None:
    """Decrypts and authenticates a .vault file.

    Process:
    1. Reads the salt (16 bytes) and nonce (12 bytes) from the header.
    2. Derives the key using Argon2id with the read salt.
    3. Recreates the AAD from the salt and nonce to verify their integrity.
    4. Decrypts the ciphertext and verifies the authentication Tag at the end.

    Args:
        fingerprint: The fingerprint of the USB key required for decryption.
        input_file: Path to the encrypted .vault file.
        output_file: Path for the decrypted data.

    Raises:
        DecryptionError: If an error occurs during decryption (e.g., invalid
            tag, corrupted header, wrong key).
    """
    key = b""
    try:
        with input_file.open("rb") as f:
            salt = f.read(16)
            if len(salt) != 16:
                raise DecryptionError("Invalid file size: salt missing.")

            nonce = f.read(12)
            if len(nonce) != 12:
                raise DecryptionError("Invalid file size: nonce missing.")

            aad = salt + nonce
            encrypted_data = f.read()

        key = derive_key(fingerprint, salt)
        aesgcm = AESGCM(key)

        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, aad)

        output_file.write_bytes(decrypted_data)

    except InvalidTag as e:
        raise DecryptionError(
            "Authentication failed (wrong USB key or file has been tampered with)."
        ) from e
    except Exception as e:
        if isinstance(e, DecryptionError):
            raise
        raise DecryptionError(f"An error occurred during decryption: {str(e)}") from e
    finally:
        if key:
            # Overwrite key in memory for security
            key = b"\x00" * len(key)
            del key
