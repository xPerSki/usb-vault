"""Cryptographic module for file encryption and decryption.

This module provides the core cryptographic operations for the USB Vault
application, using AES-256-GCM for authenticated encryption with a chunked,
streaming layout so large files can be processed with bounded memory.

File format (version 2)::

    magic        9 bytes   b"USB-VAULT"
    version      1 byte    format version
    time_cost    4 bytes   Argon2id iterations          (big-endian)
    memory_cost  4 bytes   Argon2id memory in KiB        (big-endian)
    parallelism  4 bytes   Argon2id lanes               (big-endian)
    salt         16 bytes  Argon2id salt
    file_nonce   8 bytes   random per-file nonce prefix
    body         N chunks  AES-256-GCM ciphertext + 16-byte tag per chunk

Each chunk uses a unique 12-byte nonce (`file_nonce` || 4-byte counter).
Authenticated metadata binds the header and final-chunk marker, so changing
the header, truncating the file, or appending data makes decryption fail.

Every call locks its destination via `usb_vault.vault_lock` and sweeps
any staging temp files orphaned by a previously crashed run targeting the
same destination, before writing its own temp file and atomically publishing
it.
"""

import ctypes
import logging
import os
import tempfile
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import (
    AuthenticationError,
    DecryptionError,
    EncryptionError,
    IntegrityError,
    InvalidVaultError,
    KeyDerivationError,
    VaultLockError,
)
from .key_derivation import (
    DEFAULT_MEMORY_COST,
    DEFAULT_PARALLELISM,
    DEFAULT_TIME_COST,
    derive_key,
    generate_salt,
)
from .vault_lock import TEMP_SUFFIX, VaultLock, cleanup_orphaned_temps

logger = logging.getLogger(__name__)

BUFFER_SIZE = 64 * 1024
GCM_TAG_SIZE = 16
MAX_CHUNK_COUNT = 0xFFFFFFFF

VAULT_MAGIC = b"USB-VAULT"
FORMAT_VERSION = 2

SALT_SIZE = 16
FILE_NONCE_SIZE = 8
# magic + version + (time_cost, memory_cost, parallelism) + salt + file_nonce
VAULT_HEADER_SIZE = len(VAULT_MAGIC) + 1 + 12 + SALT_SIZE + FILE_NONCE_SIZE


def _build_secret(
    fingerprint: str, password: str | bytes | bytearray | None = None
) -> bytearray:
    """Combine the hardware fingerprint with an optional user password.

    The result is assembled directly into a single `bytearray` to avoid
    leaving multiple immutable intermediate `bytes` copies of the secret on
    the Python heap that cannot later be wiped.

    Args:
        fingerprint: The hardware identifier of the USB device.
        password: Optional user password as text or raw bytes.

    Returns:
        A mutable `bytearray` containing `fingerprint || 0x00 || password`.
    """
    out = bytearray()
    out.extend(fingerprint.encode("utf-8"))
    out.append(0x00)
    if password:
        if isinstance(password, str):
            out.extend(password.encode("utf-8"))
        else:
            out.extend(password)
    return out


def _wipe_buffers(*buffers: bytearray) -> None:
    """Best-effort zero-fill of mutable byte buffers via `memset`.

    Uses `ctypes.memset` over the buffer's backing storage rather than a
    Python loop, which is faster and is not defeated by CPython's small-int
    caching. This is a defence-in-depth measure only: it cannot reach copies of
    the data made elsewhere (e.g. inside the Argon2 C backend) and is not a
    guarantee on a managed runtime.

    Args:
        *buffers: The `bytearray` buffers to overwrite with zero bytes.
    """
    for buf in buffers:
        if not buf:
            continue
        ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))


def wipe_secret(*buffers: bytearray) -> None:
    """Zero mutable passphrase buffers owned by a caller.

    Args:
        *buffers: The `bytearray` buffers to overwrite with zero bytes.
    """
    _wipe_buffers(*buffers)


def _same_file(first: Path, second: Path) -> bool:
    """Return whether two paths identify the same file.

    Handles direct path equality, symlinks, and existing hard links.
    """
    try:
        if first.resolve(strict=False) == second.resolve(strict=False):
            return True
        return second.exists() and first.samefile(second)
    except OSError:
        return False


def _report_progress(
    callback: Callable[[int, int], None] | None,
    processed: int,
    total: int,
) -> None:
    """Report progress without letting presentation code abort encryption."""
    if callback is None:
        return
    try:
        callback(processed, total)
    except Exception as e:
        logger.warning(
            "Progress callback failed; continuing operation (%s).",
            type(e).__name__,
        )


def _remove_temp_file(path: Path | None) -> OSError | None:
    """Try to remove a staging file and return any cleanup error."""
    if path is None:
        return None
    try:
        path.unlink(missing_ok=True)
    except OSError as e:
        logger.warning("Could not remove staging file (errno=%s).", e.errno)
        return e
    return None


def _fsync_directory(path: Path) -> None:
    """Flush a directory entry to disk so an atomic rename survives a crash.

    No-op on platforms (such as Windows) that do not support opening and
    fsyncing a directory.

    Args:
        path: The directory whose metadata should be flushed.
    """
    if os.name != "posix":
        return
    dir_fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _pack_header(
    salt: bytes,
    file_nonce: bytes,
    time_cost: int,
    memory_cost: int,
    parallelism: int,
) -> bytes:
    """Serialise the vault header into its on-disk byte layout.

    Args:
        salt: The Argon2id salt.
        file_nonce: The random per-file nonce prefix.
        time_cost: Argon2id iteration count.
        memory_cost: Argon2id memory cost in KiB.
        parallelism: Argon2id lane count.

    Returns:
        The packed header bytes.
    """
    return (
        VAULT_MAGIC
        + FORMAT_VERSION.to_bytes(1, "big")
        + time_cost.to_bytes(4, "big")
        + memory_cost.to_bytes(4, "big")
        + parallelism.to_bytes(4, "big")
        + salt
        + file_nonce
    )


def encrypt_file(
    fingerprint: str,
    input_file: Path,
    output_file: Path,
    password: str | bytes | bytearray | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> None:
    """Encrypt a file using AES-256-GCM.

    Process:
        1. Generates a random salt and file nonce and records the Argon2id
           parameters in the header.
        2. Combines the hardware fingerprint and optional password into a
           wipeable secret and derives a 32-byte key with Argon2id.
        3. Takes an exclusive lock on the destination so a concurrent operation
           cannot target the same output, then sweeps any leftover temp
           files from a previous crashed run targeting this destination.
        4. Writes the header to a uniquely named, exclusively created temporary
           file in the destination directory.
        5. Encrypts the input in 64 KiB chunks, each with a unique nonce and
           AAD binding the salt, nonce and final-chunk flag (plus the full
           header on the first chunk).
        6. Flushes and fsyncs the temp file, then atomically replaces the
           destination, fsyncing the parent directory on POSIX.
        7. Zeroes the derived key and secret in memory, and releases the lock.

    Args:
        fingerprint: The hardware identifier of the USB device.
        input_file: Path to the target plaintext file.
        output_file: Path where the encrypted vault file will be written.
        password: Optional user password combined with the USB fingerprint.
        progress_callback: Optional callback `(processed, total)` in plaintext
            bytes to track encryption progress.

    Raises:
        VaultLockError: If another operation is already writing to
            `output_file`.
        EncryptionError: If any internal or file operation fails.
    """
    key = bytearray()
    secret = bytearray()
    temp_output_file: Path | None = None
    lock = VaultLock(output_file)

    try:
        if not fingerprint.strip():
            raise EncryptionError("USB fingerprint is missing.")
        if _same_file(input_file, output_file):
            raise EncryptionError("Input and output must be different files.")

        lock.acquire()
        cleanup_orphaned_temps(output_file)

        total_size = input_file.stat().st_size
        processed_size = 0

        salt = generate_salt(SALT_SIZE)
        file_nonce = os.urandom(FILE_NONCE_SIZE)
        header = _pack_header(
            salt,
            file_nonce,
            DEFAULT_TIME_COST,
            DEFAULT_MEMORY_COST,
            DEFAULT_PARALLELISM,
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

        # mkstemp creates the file with O_EXCL and mode 0o600, defeating
        # symlink/pre-created-file races in an attacker-writable directory and
        # avoiding collisions between concurrent runs.
        fd, tmp_name = tempfile.mkstemp(
            dir=str(output_file.parent),
            prefix=f"{output_file.name}.",
            suffix=TEMP_SUFFIX,
        )
        temp_output_file = Path(tmp_name)

        with os.fdopen(fd, "wb") as f_out, input_file.open("rb") as f_in:
            f_out.write(header)

            chunk_counter = 0
            while True:
                chunk = f_in.read(BUFFER_SIZE)
                is_final = len(chunk) < BUFFER_SIZE

                processed_size += len(chunk)
                _report_progress(progress_callback, processed_size, total_size)

                if chunk_counter > MAX_CHUNK_COUNT:
                    raise EncryptionError(
                        "File too large: exceeds maximum supported size."
                    )

                nonce = file_nonce + chunk_counter.to_bytes(4, "big")
                aad = salt + nonce + (b"\x01" if is_final else b"\x00")
                if chunk_counter == 0:
                    aad = header + aad
                f_out.write(aesgcm.encrypt(nonce, chunk, aad))

                if is_final:
                    break

                chunk_counter += 1

            f_out.flush()
            os.fsync(f_out.fileno())

        temp_output_file.replace(output_file)
        _fsync_directory(output_file.parent)
        temp_output_file = None

    except VaultLockError:
        raise
    except EncryptionError:
        raise
    except OSError as e:
        logger.error("File I/O error during encryption (errno=%s).", e.errno)
        raise EncryptionError("Encryption failed due to a file system error.") from e
    except Exception as e:
        logger.error("Unexpected encryption error (%s).", type(e).__name__)
        raise EncryptionError("Encryption failed due to an internal error.") from e
    finally:
        cleanup_error = _remove_temp_file(temp_output_file)
        _wipe_buffers(secret, key)
        lock.release()
        if cleanup_error is not None:
            raise EncryptionError(
                "Encryption failed and its staging file could not be removed."
            ) from cleanup_error


def decrypt_file(
    fingerprint: str,
    input_file: Path,
    output_file: Path,
    password: str | bytes | bytearray | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> None:
    """Decrypt and authenticate a `.vault` file.

    Process:
        1. Takes an exclusive lock on the destination so a concurrent operation
           cannot target the same output, then sweeps any leftover temp
           files from a previous crashed run targeting this destination.
        2. Validates the magic header and format version.
        3. Reads the Argon2id parameters, salt and file nonce from the header.
        4. Combines the hardware fingerprint and optional password into a
           secret and derives the key with the header's Argon2id parameters.
        5. Decrypts each chunk, reconstructing its unique nonce and AAD (the
           first chunk also binds the full header), into a uniquely named,
           exclusively created temporary file.
        6. Rejects any trailing data after the authenticated final chunk.
        7. Flushes and fsyncs the temp file, then atomically replaces the
           destination, fsyncing the parent directory on POSIX.
        8. Zeroes the derived key and secret in memory, and releases the lock.

    Args:
        fingerprint: The hardware identifier of the USB device.
        input_file: Path to the `.vault` file.
        output_file: Path where the plaintext will be restored.
        password: Optional user password combined with the USB fingerprint.
        progress_callback: Optional callback `(processed, total)` in
            ciphertext bytes to track decryption progress.

    Raises:
        VaultLockError: If another operation is already writing to
            `output_file`.
        InvalidVaultError: If the file is not a vault or uses an unsupported
            version, or the header is truncated.
        AuthenticationError: If authentication fails (wrong USB/password or
            tampering).
        IntegrityError: If the ciphertext is truncated or has trailing data.
        DecryptionError: If any other I/O or internal operation fails.
    """
    key = bytearray()
    secret = bytearray()
    temp_output_file: Path | None = None
    lock = VaultLock(output_file)

    try:
        if not fingerprint.strip():
            raise DecryptionError("USB fingerprint is missing.")
        if _same_file(input_file, output_file):
            raise DecryptionError("Input and output must be different files.")

        lock.acquire()
        cleanup_orphaned_temps(output_file)

        total_size = input_file.stat().st_size
        processed_size = VAULT_HEADER_SIZE

        fd, tmp_name = tempfile.mkstemp(
            dir=str(output_file.parent),
            prefix=f"{output_file.name}.",
            suffix=TEMP_SUFFIX,
        )
        temp_output_file = Path(tmp_name)

        with os.fdopen(fd, "wb") as f_out, input_file.open("rb") as f_in:
            magic = f_in.read(len(VAULT_MAGIC))
            if magic != VAULT_MAGIC:
                raise InvalidVaultError(
                    "Not a valid vault file: missing or corrupt header."
                )

            version_byte = f_in.read(1)
            if len(version_byte) != 1:
                raise InvalidVaultError(
                    "Not a valid vault file: format version byte missing "
                    "(truncated or corrupt header). This app supports vault "
                    f"format version {FORMAT_VERSION}."
                )
            file_format_version = version_byte[0]
            if file_format_version != FORMAT_VERSION:
                raise InvalidVaultError(
                    "Vault format version mismatch: this file uses format "
                    f"version {file_format_version}; this app supports format "
                    f"version {FORMAT_VERSION}."
                )

            params = f_in.read(12)
            if len(params) != 12:
                raise InvalidVaultError(
                    "Not a valid vault file: Argon2 parameters missing."
                )
            time_cost = int.from_bytes(params[0:4], "big")
            memory_cost = int.from_bytes(params[4:8], "big")
            parallelism = int.from_bytes(params[8:12], "big")

            salt = f_in.read(SALT_SIZE)
            if len(salt) != SALT_SIZE:
                raise InvalidVaultError("Invalid file size: salt missing.")

            file_nonce = f_in.read(FILE_NONCE_SIZE)
            if len(file_nonce) != FILE_NONCE_SIZE:
                raise InvalidVaultError("Invalid file size: nonce missing.")

            header = _pack_header(salt, file_nonce, time_cost, memory_cost, parallelism)

            secret = _build_secret(fingerprint, password)
            key = derive_key(
                secret,
                salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
            )
            aesgcm = AESGCM(key)

            chunk_counter = 0
            while True:
                enc_chunk = f_in.read(BUFFER_SIZE + GCM_TAG_SIZE)
                if not enc_chunk:
                    raise IntegrityError(
                        "Truncated file: missing final authenticated chunk."
                    )

                processed_size += len(enc_chunk)
                _report_progress(
                    progress_callback,
                    min(processed_size, total_size),
                    total_size,
                )

                is_final = len(enc_chunk) < (BUFFER_SIZE + GCM_TAG_SIZE)

                if chunk_counter > MAX_CHUNK_COUNT:
                    raise IntegrityError(
                        "Vault exceeds the maximum supported chunk count."
                    )
                nonce = file_nonce + chunk_counter.to_bytes(4, "big")
                aad = salt + nonce + (b"\x01" if is_final else b"\x00")
                if chunk_counter == 0:
                    aad = header + aad

                f_out.write(aesgcm.decrypt(nonce, enc_chunk, aad))

                if is_final:
                    if f_in.read(1):
                        raise IntegrityError(
                            "File integrity failure: trailing data outside of "
                            "the authenticated chunk boundary."
                        )
                    break

                chunk_counter += 1

            f_out.flush()
            os.fsync(f_out.fileno())

        temp_output_file.replace(output_file)
        _fsync_directory(output_file.parent)
        temp_output_file = None

    except InvalidTag as e:
        logger.debug("AES-GCM authentication failed during decryption.")
        raise AuthenticationError(
            "Authentication failed (wrong USB key or file has been tampered with)."
        ) from e
    except KeyDerivationError as e:
        raise InvalidVaultError(
            "Vault Argon2 parameters are invalid or unsupported."
        ) from e
    except VaultLockError:
        raise
    except DecryptionError:
        raise
    except OSError as e:
        logger.error("File I/O error during decryption (errno=%s).", e.errno)
        raise DecryptionError("Decryption failed due to a file system error.") from e
    except Exception as e:
        logger.error("Unexpected decryption error (%s).", type(e).__name__)
        raise DecryptionError("Decryption failed due to an internal error.") from e
    finally:
        cleanup_error = _remove_temp_file(temp_output_file)
        _wipe_buffers(secret, key)
        lock.release()
        if cleanup_error is not None:
            raise DecryptionError(
                "Decryption failed and temporary plaintext could not be removed. "
                "Close programs using the destination folder and retry."
            ) from cleanup_error
