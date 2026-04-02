"""Cryptographic module for file encryption and decryption.

This module provides the core cryptographic operations for the USB Vault
application, utilizing AES-256-GCM for authenticated encryption.
"""

import os
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import DecryptionError, EncryptionError
from .key_derivation import derive_key, generate_salt

BUFFER_SIZE = 64 * 1024


def _build_secret(fingerprint: str, password: str | None = None) -> str:
    """Combine hardware fingerprint with optional user password."""
    pwd = password or ""
    return f"{fingerprint}\x00{pwd}"


def encrypt_file(
    fingerprint: str,
    input_file: Path,
    output_file: Path,
    password: str | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> None:
    """Encrypts a file using AES-256-GCM.

    Process:
    1. Generates a random 16-byte salt and an 8-byte file nonce.
    2. Combines the hardware fingerprint and optional password into a secure secret.
    3. Derives a 32-byte symmetric key using Argon2id from the secret and salt.
    4. Writes the salt and file nonce to the header of a temporary output file.
    5. Reads the input file in 64KB chunks.
    6. Encrypts each chunk utilizing a unique nonce (file_nonce + 4-byte counter) and
       Additional Authenticated Data (AAD: salt + nonce + a 1-byte final chunk flag).
    7. Atomically replaces the destination file with the completed temporary file.
    8. Securely zeroes out the derived key in memory.

    Args:
        fingerprint: The hardware identifier of the USB device.
        input_file: Path to the target plaintext file.
        output_file: Path where the encrypted vault file will be written.
        password: Optional user password combined with the USB fingerprint.
        progress_callback: Optional callback to track encryption progress.

    Raises:
        EncryptionError: If any internal or file operation fails.
    """
    key = bytearray()
    temp_output_file = output_file.with_name(f"{output_file.name}.tmp")

    try:
        total_size = input_file.stat().st_size
        processed_size = 0

        salt = generate_salt(16)
        file_nonce = os.urandom(8)

        secret = _build_secret(fingerprint, password)
        key = derive_key(secret, salt)
        aesgcm = AESGCM(key)

        with input_file.open("rb") as f_in, temp_output_file.open("wb") as f_out:
            f_out.write(salt)
            f_out.write(file_nonce)

            chunk_counter = 0
            while True:
                chunk = f_in.read(BUFFER_SIZE)
                is_final = len(chunk) < BUFFER_SIZE

                processed_size += len(chunk)
                if progress_callback:
                    progress_callback(processed_size, total_size)

                nonce = file_nonce + chunk_counter.to_bytes(4, "big")
                # AAD includes a 1-byte flag to mathematically mark the final chunk
                aad = salt + nonce + (b"\x01" if is_final else b"\x00")
                enc_chunk = aesgcm.encrypt(nonce, chunk, aad)
                f_out.write(enc_chunk)

                if is_final:
                    break

                chunk_counter += 1

        temp_output_file.replace(output_file)

    except Exception as e:
        if temp_output_file.exists():
            temp_output_file.unlink(missing_ok=True)
        if isinstance(e, EncryptionError):
            raise
        raise EncryptionError(f"Encryption Error: {str(e)}") from e
    finally:
        if key:
            # Wipe the bytearray from memory
            for i in range(len(key)):
                key[i] = 0
            del key


def decrypt_file(
    fingerprint: str,
    input_file: Path,
    output_file: Path,
    password: str | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> None:
    """Decrypts and authenticates a .vault file.

    Process:
    1. Reads the 16-byte salt and 8-byte file nonce from the file header.
    2. Combines the hardware fingerprint and optional password into a secure secret.
    3. Derives the 32-byte symmetric key using Argon2id from the secret and salt.
    4. Reads the ciphertext in chunks of 64KB plus the 16-byte authentication tag.
    5. Recreates the exact unique nonce and AAD for each chunk to verify its integrity.
    6. Decrypts the chunk and writes the plaintext into a temporary output file.
    7. Verifies there is no trailing garbage data after the mathematically final chunk.
    8. Atomically replaces the destination file with the completed temporary file.
    9. Securely zeroes out the derived key in memory.

    Args:
        fingerprint: The hardware identifier of the USB device.
        input_file: Path to the `.vault` file.
        output_file: Path where the plaintext will be restored.
        password: Optional user password combined with the USB fingerprint.
        progress_callback: Optional callback to track decryption progress.

    Raises:
        DecryptionError: If authentication fails, the file is corrupt, or I/O fails.
    """
    key = bytearray()
    temp_output_file = output_file.with_name(f"{output_file.name}.tmp")

    try:
        total_size = input_file.stat().st_size
        processed_size = 24  # 16 (salt) + 8 (nonce)

        with input_file.open("rb") as f_in, temp_output_file.open("wb") as f_out:
            salt = f_in.read(16)
            if len(salt) != 16:
                raise DecryptionError("Invalid file size: salt missing.")

            file_nonce = f_in.read(8)
            if len(file_nonce) != 8:
                raise DecryptionError("Invalid file size: nonce missing.")

            secret = _build_secret(fingerprint, password)
            key = derive_key(secret, salt)
            aesgcm = AESGCM(key)

            chunk_counter = 0
            while True:
                enc_chunk = f_in.read(BUFFER_SIZE + 16)
                if not enc_chunk:
                    raise DecryptionError(
                        "Truncated file: missing final authenticated chunk."
                    )

                processed_size += len(enc_chunk)
                if progress_callback:
                    progress_callback(min(processed_size, total_size), total_size)

                is_final = len(enc_chunk) < (BUFFER_SIZE + 16)

                nonce = file_nonce + chunk_counter.to_bytes(4, "big")
                aad = salt + nonce + (b"\x01" if is_final else b"\x00")

                decrypted_chunk = aesgcm.decrypt(nonce, enc_chunk, aad)
                f_out.write(decrypted_chunk)

                if is_final:
                    if f_in.read(1):
                        raise DecryptionError(
                            "File integrity failure: trailing garbage byte(s) outside of authenticated chunk boundary."
                        )
                    break

                chunk_counter += 1

        temp_output_file.replace(output_file)

    except InvalidTag as e:
        if temp_output_file.exists():
            temp_output_file.unlink(missing_ok=True)
        raise DecryptionError(
            "Authentication failed (wrong USB key or file has been tampered with)."
        ) from e
    except Exception as e:
        if temp_output_file.exists():
            temp_output_file.unlink(missing_ok=True)
        if isinstance(e, DecryptionError):
            raise
        raise DecryptionError(f"An error occurred during decryption: {str(e)}") from e
    finally:
        if key:
            # Wipe the bytearray from memory
            for i in range(len(key)):
                key[i] = 0
            del key
