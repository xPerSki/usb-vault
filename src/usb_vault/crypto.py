"""Cryptographic module for file encryption and decryption.

This module provides the core cryptographic operations for the USB Vault
application, using AES-256-GCM for authenticated encryption with a chunked,
streaming layout so large files can be processed with bounded memory.

File format (version 3)::

    magic        9 bytes   b"USB-VAULT"
    version      1 byte    format version
    time_cost    4 bytes   Argon2id iterations          (big-endian)
    memory_cost  4 bytes   Argon2id memory in KiB        (big-endian)
    parallelism  4 bytes   Argon2id lanes               (big-endian)
    salt         16 bytes  Argon2id salt
    file_nonce   8 bytes   random per-file nonce prefix
    name_nonce   12 bytes  AES-GCM nonce for the name record
    name_record  272 bytes AES-GCM(256-byte padded basename || tag)
    body         N chunks  AES-256-GCM ciphertext + 16-byte tag per chunk

Version 2 vaults omit `name_nonce` / `name_record` and remain decryptable.

Each body chunk uses a unique 12-byte nonce (`file_nonce` || 4-byte counter).
Authenticated metadata binds the public prefix and final-chunk marker, so
changing the header, truncating the file, or appending data makes decryption
fail.

Every call locks its destination via `usb_vault.vault_lock` and sweeps
any staging temp files orphaned by a previously crashed run targeting the
same destination, before writing its own temp file and atomically publishing
it.
"""

from __future__ import annotations

import ctypes
import logging
import os
import secrets
import shutil
import sys
import tempfile
import unicodedata
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import (
    AuthenticationError,
    DecryptionError,
    EncryptionError,
    IntegrityError,
    InvalidVaultError,
    KeyDerivationError,
    OperationCancelled,
    VaultLockError,
)
from .key_derivation import (
    DEFAULT_MEMORY_COST,
    DEFAULT_PARALLELISM,
    DEFAULT_TIME_COST,
    derive_key,
    generate_salt,
)
from .vault_lock import (
    TEMP_SUFFIX,
    VaultLock,
    _is_link,
    _is_network_or_device_path,
    cleanup_orphaned_temps,
)

logger = logging.getLogger(__name__)

BUFFER_SIZE = 64 * 1024
GCM_TAG_SIZE = 16
MAX_CHUNK_COUNT = 0xFFFFFFFF
MAX_QUEUE_FILES = 100

VAULT_MAGIC = b"USB-VAULT"
FORMAT_VERSION = 3
SUPPORTED_FORMAT_VERSIONS = frozenset({2, 3})

SALT_SIZE = 16
FILE_NONCE_SIZE = 8
NAME_NONCE_SIZE = 12
NAME_PLAINTEXT_SIZE = 256
NAME_RECORD_SIZE = NAME_PLAINTEXT_SIZE + GCM_TAG_SIZE
NAME_AAD_PREFIX = b"USB-VAULT\x00name\x00"
# magic + version + (time_cost, memory_cost, parallelism) + salt + file_nonce
VAULT_HEADER_SIZE = len(VAULT_MAGIC) + 1 + 12 + SALT_SIZE + FILE_NONCE_SIZE
V3_PUBLIC_PREFIX_SIZE = VAULT_HEADER_SIZE + NAME_NONCE_SIZE + NAME_RECORD_SIZE


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


def _raise_if_cancelled(cancel_check: Callable[[], bool] | None) -> None:
    """Abort between chunks when the caller has requested cancellation.

    Args:
        cancel_check: Optional zero-arg predicate; `True` means stop now.

    Raises:
        OperationCancelled: When cancellation was requested.
    """
    if cancel_check is None:
        return
    try:
        requested = bool(cancel_check())
    except Exception as e:
        logger.warning(
            "Cancel check failed; continuing operation (%s).",
            type(e).__name__,
        )
        return
    if requested:
        raise OperationCancelled("Cancelled.")


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
    version: int = FORMAT_VERSION,
) -> bytes:
    """Serialise the vault base header into its on-disk byte layout.

    Args:
        salt: The Argon2id salt.
        file_nonce: The random per-file nonce prefix.
        time_cost: Argon2id iteration count.
        memory_cost: Argon2id memory cost in KiB.
        parallelism: Argon2id lane count.
        version: Format version byte to embed (must match the on-disk file).

    Returns:
        The packed base header bytes (version 2 size; no name fields).
    """
    return (
        VAULT_MAGIC
        + version.to_bytes(1, "big")
        + time_cost.to_bytes(4, "big")
        + memory_cost.to_bytes(4, "big")
        + parallelism.to_bytes(4, "big")
        + salt
        + file_nonce
    )


def _name_aad(
    version: int, salt: bytes, file_nonce: bytes, name_nonce: bytes
) -> bytes:
    """Build AAD for the sealed basename record."""
    return (
        NAME_AAD_PREFIX
        + version.to_bytes(1, "big")
        + salt
        + file_nonce
        + name_nonce
    )


_FORBIDDEN_BASENAME_CHARS = frozenset('<>:"/\\|?*\0')
_RESERVED_DOS_NAMES = frozenset({
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
    "CONIN$",
    "CONOUT$",
})
_FORBIDDEN_BIDI_FORMAT_CHARS = frozenset({
    "\u200e", "\u200f",  # LRM, RLM
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # LRE, RLE, PDF, LRO, RLO
    "\u2066", "\u2067", "\u2068", "\u2069",  # LRI, RLI, FSI, PDI
    "\u200b", "\u200c", "\u200d", "\ufeff",  # ZWSP, ZWNJ, ZWJ, BOM
    "\u00ad", "\u2060",  # Soft hyphen, word joiner
    "\u061c",  # ALM (Arabic Letter Mark)
})
_FORBIDDEN_UNICODE_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})


def _validate_basename(basename: str, *, for_encryption: bool) -> None:
    """Reject empty, dotted, reserved, or path-like basenames.

    Args:
        basename: Candidate original filename.
        for_encryption: Selects EncryptionError vs InvalidVaultError.

    Raises:
        EncryptionError: When `for_encryption` is True and the name is bad.
        InvalidVaultError: When `for_encryption` is False and the name is bad.
    """
    error_cls: type[Exception] = (
        EncryptionError if for_encryption else InvalidVaultError
    )
    if not isinstance(basename, str) or not basename:
        raise error_cls("Invalid basename for vault name record: empty name.")

    # Reject leading/trailing whitespace or trailing dots
    if basename != basename.strip() or basename.endswith("."):
        raise error_cls(
            "Invalid basename for vault name record: illegal whitespace or trailing dot."
        )

    # Reject path navigators
    if basename in {".", ".."} or basename.startswith(".."):
        raise error_cls(
            "Invalid basename for vault name record: directory traversal symbol."
        )

    # Reject path separators, colons (drive letters / ADS), and invalid filesystem characters
    if any(ch in _FORBIDDEN_BASENAME_CHARS for ch in basename):
        raise error_cls(
            "Invalid basename for vault name record: contains forbidden characters."
        )

    # Reject control characters (0x00 - 0x1F), Unicode BiDi overrides, and formatting controls
    if any(
        ord(ch) < 32
        or ch in _FORBIDDEN_BIDI_FORMAT_CHARS
        or unicodedata.category(ch) in _FORBIDDEN_UNICODE_CATEGORIES
        for ch in basename
    ):
        raise error_cls(
            "Invalid basename for vault name record: contains control, bidirectional, or formatting characters."
        )

    # Reject Windows reserved device names (e.g. NUL, CON, COM1.txt, aux.dat)
    stem = basename.split(".")[0].strip().upper()
    if stem in _RESERVED_DOS_NAMES or basename.strip().upper() in _RESERVED_DOS_NAMES:
        raise error_cls(
            "Invalid basename for vault name record: uses reserved device name."
        )


def _encode_basename(basename: str) -> bytes:
    """Pack a basename into the fixed 256-byte name plaintext.

    Layout: 2-byte big-endian UTF-8 length + UTF-8 bytes + zero padding.

    Args:
        basename: Original file name (``Path.name``).

    Returns:
        Exactly ``NAME_PLAINTEXT_SIZE`` bytes.

    Raises:
        EncryptionError: If the basename is empty, path-like, or too long.
    """
    _validate_basename(basename, for_encryption=True)
    encoded = basename.encode("utf-8")
    max_utf8 = NAME_PLAINTEXT_SIZE - 2
    if len(encoded) > max_utf8:
        raise EncryptionError("Basename too long for vault name record.")
    plain = bytearray(NAME_PLAINTEXT_SIZE)
    plain[0:2] = len(encoded).to_bytes(2, "big")
    plain[2 : 2 + len(encoded)] = encoded
    return bytes(plain)


def _decode_basename(plain: bytes) -> str:
    """Unpack and validate a 256-byte name plaintext.

    Args:
        plain: Decrypted name plaintext.

    Returns:
        The original basename string.

    Raises:
        InvalidVaultError: If the record is malformed or contains a bad name.
    """
    if len(plain) != NAME_PLAINTEXT_SIZE:
        raise InvalidVaultError("Invalid vault name record: wrong plaintext size.")
    length = int.from_bytes(plain[0:2], "big")
    max_utf8 = NAME_PLAINTEXT_SIZE - 2
    if length > max_utf8:
        raise InvalidVaultError("Invalid vault name record: length out of range.")
    if any(plain[2 + length :]):
        raise InvalidVaultError("Invalid vault name record: non-zero padding.")
    try:
        basename = bytes(plain[2 : 2 + length]).decode("utf-8")
    except UnicodeDecodeError as e:
        raise InvalidVaultError(
            "Invalid vault name record: basename is not valid UTF-8."
        ) from e
    _validate_basename(basename, for_encryption=False)
    return basename


def allocate_stealth_vault_path(
    directory: Path, max_attempts: int = 64
) -> Path:
    """Pick an unused random ``*.vault`` path under ``directory``.

    Args:
        directory: Destination folder for the stealth vault file.
        max_attempts: How many random names to try before giving up.

    Returns:
        A path of the form ``<16 hex chars>.vault`` that does not yet exist.

    Raises:
        EncryptionError: If every attempt collides with an existing path.
    """
    for _ in range(max_attempts):
        candidate = directory / f"{secrets.token_hex(8)}.vault"
        if not candidate.exists():
            return candidate
    raise EncryptionError(
        "Could not allocate a unique stealth vault filename."
    )


def estimate_output_bytes(plaintext_size: int) -> int:
    """Estimate the on-disk size of a freshly encrypted (v3) vault.

    Accounts for the v3 public prefix, plaintext payload, and one GCM tag
    per streaming chunk (including the mandatory final chunk).

    Args:
        plaintext_size: Size of the input file in bytes (non-negative).

    Returns:
        Estimated ciphertext file size in bytes.
    """
    if plaintext_size < 0:
        raise EncryptionError("Plaintext size cannot be negative.")
    num_chunks = (plaintext_size // BUFFER_SIZE) + 1
    return (
        V3_PUBLIC_PREFIX_SIZE
        + plaintext_size
        + num_chunks * GCM_TAG_SIZE
    )


def ensure_disk_space(directory: Path, needed_bytes: int) -> None:
    """Require that ``directory``'s volume has at least ``needed_bytes`` free.

    Args:
        directory: Any path on the target volume (typically the output folder).
        needed_bytes: Minimum free bytes required.

    Raises:
        EncryptionError: If free space is insufficient or cannot be queried.
    """
    if needed_bytes < 0:
        raise EncryptionError("Needed disk space cannot be negative.")
    try:
        free = shutil.disk_usage(directory).free
    except OSError as e:
        raise EncryptionError(
            "Could not determine free disk space for the output directory."
        ) from e
    if free < needed_bytes:
        raise EncryptionError(
            "Not enough free disk space for the output."
        )


def peek_vault_format(path: Path) -> dict[str, Any]:
    """Read only the vault magic + format version (no key derivation).

    Used to flag incompatible / non-vault files when they are
    added to the decrypt queue, before any passphrase or USB work starts.

    Args:
        path: Candidate vault file.

    Returns:
        A dict with:
        - `ok`: `True` when magic + version byte were readable.
        - `version`: Integer format version, or `None` on hard failure.
        - `supported`: Whether this app can decrypt that version.
        - `error`: Human-readable reason when not usable, else `None`.
    """
    if _is_link(path):
        return {
            "ok": False,
            "version": None,
            "supported": False,
            "error": "Symbolic links are not supported.",
        }
    if _is_network_or_device_path(path):
        return {
            "ok": False,
            "version": None,
            "supported": False,
            "error": "Network and UNC paths are not supported.",
        }
    try:
        with path.open("rb") as f_in:
            magic = f_in.read(len(VAULT_MAGIC))
            if magic != VAULT_MAGIC:
                return {
                    "ok": False,
                    "version": None,
                    "supported": False,
                    "error": "Not a vault file.",
                }
            version_byte = f_in.read(1)
            if len(version_byte) != 1:
                return {
                    "ok": False,
                    "version": None,
                    "supported": False,
                    "error": "Truncated or corrupt vault header.",
                }
            version = version_byte[0]
    except OSError:
        return {
            "ok": False,
            "version": None,
            "supported": False,
            "error": "Could not read the file.",
        }

    if version in SUPPORTED_FORMAT_VERSIONS:
        return {
            "ok": True,
            "version": version,
            "supported": True,
            "error": None,
        }

    max_supported = max(SUPPORTED_FORMAT_VERSIONS)
    if version > max_supported:
        error = (
            f"Vault format v{version} needs a newer app "
            f"(this app supports up to v{max_supported})."
        )
    else:
        supported_list = ", ".join(
            f"v{v}" for v in sorted(SUPPORTED_FORMAT_VERSIONS)
        )
        error = (
            f"Vault format v{version} is not supported "
            f"(this app supports {supported_list})."
        )
    return {
        "ok": True,
        "version": version,
        "supported": False,
        "error": error,
    }


def peek_original_basename(
    fingerprint: str,
    input_file: Path,
    password: str | bytes | bytearray | None = None,
) -> str | None:
    """Return the sealed original basename from a vault, if present.

    Version 2 vaults have no name record, so this returns ``None``. Version 3
    vaults decrypt and return the authenticated basename without writing the
    body plaintext.

    Args:
        fingerprint: The hardware identifier of the USB device.
        input_file: Path to the ``.vault`` file.
        password: Optional user password combined with the USB fingerprint.

    Returns:
        The original basename for v3, or ``None`` for v2.

    Raises:
        InvalidVaultError: If the file is not a supported vault or the name
            record is truncated/malformed.
        AuthenticationError: If name decryption fails authentication.
        DecryptionError: If fingerprint is missing or another I/O error occurs.
        KeyDerivationError: Propagated as InvalidVaultError for bad Argon2
            parameters (via the same path as ``decrypt_file``).
    """
    key = bytearray()
    secret = bytearray()
    try:
        if _is_link(input_file):
            raise DecryptionError(
                "Symbolic links are not supported. Source must be a regular file."
            )
        if _is_network_or_device_path(input_file):
            raise DecryptionError(
                "Network and UNC paths are not supported. Source must be a local regular file."
            )
        if not fingerprint.strip():
            raise DecryptionError("USB fingerprint is missing.")

        with input_file.open("rb") as f_in:
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
                    f"format versions {sorted(SUPPORTED_FORMAT_VERSIONS)}."
                )
            file_format_version = version_byte[0]
            if file_format_version not in SUPPORTED_FORMAT_VERSIONS:
                raise InvalidVaultError(
                    "Vault format version mismatch: this file uses format "
                    f"version {file_format_version}; this app supports format "
                    f"versions {sorted(SUPPORTED_FORMAT_VERSIONS)}."
                )
            if file_format_version == 2:
                return None

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

            name_nonce = f_in.read(NAME_NONCE_SIZE)
            if len(name_nonce) != NAME_NONCE_SIZE:
                raise InvalidVaultError(
                    "Invalid file size: name nonce missing."
                )
            name_record = f_in.read(NAME_RECORD_SIZE)
            if len(name_record) != NAME_RECORD_SIZE:
                raise InvalidVaultError(
                    "Invalid file size: name record missing."
                )

            secret = _build_secret(fingerprint, password)
            key = derive_key(
                secret,
                salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
            )
            aesgcm = AESGCM(key)
            name_plain = aesgcm.decrypt(
                name_nonce,
                name_record,
                _name_aad(file_format_version, salt, file_nonce, name_nonce),
            )
            return _decode_basename(name_plain)

    except InvalidTag as e:
        logger.debug("AES-GCM authentication failed while peeking basename.")
        raise AuthenticationError(
            "Authentication failed (wrong USB key or file has been tampered with)."
        ) from e
    except KeyDerivationError as e:
        raise InvalidVaultError(
            "Vault Argon2 parameters are invalid or unsupported."
        ) from e
    except DecryptionError:
        raise
    except OSError as e:
        logger.error("File I/O error while peeking basename (errno=%s).", e.errno)
        raise DecryptionError("Decryption failed due to a file system error.") from e
    except Exception as e:
        logger.error("Unexpected peek error (%s).", type(e).__name__)
        raise DecryptionError("Decryption failed due to an internal error.") from e
    finally:
        _wipe_buffers(secret, key)


def encrypt_file(
    fingerprint: str,
    input_file: Path,
    output_file: Path,
    password: str | bytes | bytearray | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> None:
    """Encrypt a file using AES-256-GCM (format version 3).

    Process:
        1. Generates a random salt and file nonce and records the Argon2id
           parameters in the header.
        2. Combines the hardware fingerprint and optional password into a
           wipeable secret and derives a 32-byte key with Argon2id.
        3. Seals ``input_file.name`` into the v3 name record.
        4. Takes an exclusive lock on the destination so a concurrent operation
           cannot target the same output, then sweeps any leftover temp
           files from a previous crashed run targeting this destination.
        5. Writes the public prefix to a uniquely named, exclusively created
           temporary file in the destination directory.
        6. Encrypts the input in 64 KiB chunks, each with a unique nonce and
           AAD binding the salt, nonce and final-chunk flag (plus the full
           public prefix on the first chunk).
        7. Flushes and fsyncs the temp file, then atomically replaces the
           destination, fsyncing the parent directory on POSIX.
        8. Zeroes the derived key and secret in memory, and releases the lock.

    Args:
        fingerprint: The hardware identifier of the USB device.
        input_file: Path to the target plaintext file.
        output_file: Path where the encrypted vault file will be written.
        password: Optional user password combined with the USB fingerprint.
        progress_callback: Optional callback `(processed, total)` in plaintext
            bytes to track encryption progress.
        cancel_check: Optional predicate polled between chunks; when it
            returns `True`, staging temps are removed, the lock is released,
            and `OperationCancelled` is raised. The destination is not
            replaced.

    Raises:
        VaultLockError: If another operation is already writing to
            `output_file`.
        OperationCancelled: If `cancel_check` requested a stop mid-write.
        EncryptionError: If any internal or file operation fails.
    """
    key = bytearray()
    secret = bytearray()
    temp_output_file: Path | None = None
    lock = VaultLock(output_file)

    try:
        if _is_link(input_file) or _is_link(output_file):
            raise EncryptionError(
                "Symbolic links are not supported. Source and destination must be regular files."
            )
        if _is_network_or_device_path(input_file) or _is_network_or_device_path(output_file):
            raise EncryptionError(
                "Network and UNC paths are not supported. Source and destination must be local regular files."
            )
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
        name_nonce = os.urandom(NAME_NONCE_SIZE)
        base_header = _pack_header(
            salt,
            file_nonce,
            DEFAULT_TIME_COST,
            DEFAULT_MEMORY_COST,
            DEFAULT_PARALLELISM,
            version=FORMAT_VERSION,
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

        name_plain = _encode_basename(input_file.name)
        name_record = aesgcm.encrypt(
            name_nonce,
            name_plain,
            _name_aad(FORMAT_VERSION, salt, file_nonce, name_nonce),
        )
        public_prefix = base_header + name_nonce + name_record

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
            f_out.write(public_prefix)

            chunk_counter = 0
            while True:
                _raise_if_cancelled(cancel_check)
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
                    aad = public_prefix + aad
                f_out.write(aesgcm.encrypt(nonce, chunk, aad))

                if is_final:
                    break

                chunk_counter += 1

            f_out.flush()
            os.fsync(f_out.fileno())

        temp_output_file.replace(output_file)
        _fsync_directory(output_file.parent)
        temp_output_file = None

    except OperationCancelled:
        raise
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
    cancel_check: Callable[[], bool] | None = None,
) -> None:
    """Decrypt and authenticate a `.vault` file (format versions 2 and 3).

    Process:
        1. Takes an exclusive lock on the destination so a concurrent operation
           cannot target the same output, then sweeps any leftover temp
           files from a previous crashed run targeting this destination.
        2. Validates the magic header and format version.
        3. Reads the Argon2id parameters, salt and file nonce from the header.
        4. For v3, reads and authenticates the sealed basename (discarded here;
           use ``peek_original_basename`` to recover it).
        5. Combines the hardware fingerprint and optional password into a
           secret and derives the key with the header's Argon2id parameters.
        6. Decrypts each chunk, reconstructing its unique nonce and AAD (the
           first chunk also binds the full public prefix), into a uniquely
           named, exclusively created temporary file.
        7. Rejects any trailing data after the authenticated final chunk.
        8. Flushes and fsyncs the temp file, then atomically replaces the
           destination, fsyncing the parent directory on POSIX.
        9. Zeroes the derived key and secret in memory, and releases the lock.

    Args:
        fingerprint: The hardware identifier of the USB device.
        input_file: Path to the `.vault` file.
        output_file: Path where the plaintext will be restored.
        password: Optional user password combined with the USB fingerprint.
        progress_callback: Optional callback `(processed, total)` in
            ciphertext bytes to track decryption progress.
        cancel_check: Optional predicate polled between chunks; when it
            returns `True`, staging temps are removed, the lock is released,
            and `OperationCancelled` is raised. The destination is not
            replaced.

    Raises:
        VaultLockError: If another operation is already writing to
            `output_file`.
        OperationCancelled: If `cancel_check` requested a stop mid-write.
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
        if _is_link(input_file) or _is_link(output_file):
            raise DecryptionError(
                "Symbolic links are not supported. Source and destination must be regular files."
            )
        if _is_network_or_device_path(input_file) or _is_network_or_device_path(output_file):
            raise DecryptionError(
                "Network and UNC paths are not supported. Source and destination must be local regular files."
            )
        if not fingerprint.strip():
            raise DecryptionError("USB fingerprint is missing.")
        if _same_file(input_file, output_file):
            raise DecryptionError("Input and output must be different files.")

        lock.acquire()
        cleanup_orphaned_temps(output_file)

        total_size = input_file.stat().st_size

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
                    f"format versions {sorted(SUPPORTED_FORMAT_VERSIONS)}."
                )
            file_format_version = version_byte[0]
            if file_format_version not in SUPPORTED_FORMAT_VERSIONS:
                raise InvalidVaultError(
                    "Vault format version mismatch: this file uses format "
                    f"version {file_format_version}; this app supports format "
                    f"versions {sorted(SUPPORTED_FORMAT_VERSIONS)}."
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

            base_header = _pack_header(
                salt,
                file_nonce,
                time_cost,
                memory_cost,
                parallelism,
                version=file_format_version,
            )
            public_prefix = base_header

            if file_format_version == 3:
                name_nonce = f_in.read(NAME_NONCE_SIZE)
                if len(name_nonce) != NAME_NONCE_SIZE:
                    raise InvalidVaultError(
                        "Invalid file size: name nonce missing."
                    )
                name_record = f_in.read(NAME_RECORD_SIZE)
                if len(name_record) != NAME_RECORD_SIZE:
                    raise InvalidVaultError(
                        "Invalid file size: name record missing."
                    )
                public_prefix = base_header + name_nonce + name_record
                processed_size = V3_PUBLIC_PREFIX_SIZE
            else:
                name_nonce = b""
                name_record = b""
                processed_size = VAULT_HEADER_SIZE

            secret = _build_secret(fingerprint, password)
            key = derive_key(
                secret,
                salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
            )
            aesgcm = AESGCM(key)

            if file_format_version == 3:
                # Authenticate the name record before trusting the body AAD
                # binding; discard the basename (callers use peek separately).
                name_plain = aesgcm.decrypt(
                    name_nonce,
                    name_record,
                    _name_aad(
                        file_format_version, salt, file_nonce, name_nonce
                    ),
                )
                _decode_basename(name_plain)

            chunk_counter = 0
            while True:
                _raise_if_cancelled(cancel_check)
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
                    aad = public_prefix + aad

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
    except OperationCancelled:
        raise
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
