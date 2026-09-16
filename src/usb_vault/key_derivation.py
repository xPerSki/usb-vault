"""Derive encryption keys with Argon2id.

Argon2id makes password guesses expensive, but it does not make a public USB
identifier secret. Strong protection therefore requires a passphrase in
addition to the USB fingerprint.

Vault files store their Argon2 settings so future releases can raise the
defaults without breaking existing version-2 vaults. Strict upper bounds stop
a corrupt or malicious header from requesting unreasonable CPU or memory.
"""

import logging
import secrets

import argon2

from .exceptions import KeyDerivationError

logger = logging.getLogger(__name__)

MIN_SALT_LENGTH = 16

# Defaults recorded in each vault header. Version-2 files keep using their
# stored values if these defaults increase in a later release.
DEFAULT_TIME_COST = 3
DEFAULT_MEMORY_COST = 65536  # 64 MiB
DEFAULT_PARALLELISM = 1
KEY_LENGTH = 32

# Bounds for values read from vault headers. They prevent a corrupt file from
# requesting excessive resources before AES-GCM can authenticate it.
MAX_TIME_COST = 10
MAX_MEMORY_COST = 512 * 1024  # 512 MiB
MAX_PARALLELISM = 4
MIN_MEMORY_COST = 8
MIN_HASH_LENGTH = 16
MAX_HASH_LENGTH = 64


def generate_salt(n: int = MIN_SALT_LENGTH) -> bytes:
    """Generate a cryptographically secure random salt.

    Args:
        n: The length of the salt in bytes. Defaults to 16.

    Returns:
        A random salt.

    Raises:
        KeyDerivationError: If `n` is below the 16-byte OWASP minimum.
    """
    if isinstance(n, bool) or not isinstance(n, int):
        raise KeyDerivationError("Salt length must be an integer.")
    if n < MIN_SALT_LENGTH:
        raise KeyDerivationError(
            f"Salt length must be at least {MIN_SALT_LENGTH} bytes."
        )
    return secrets.token_bytes(n)


def _validate_argon2_params(
    time_cost: int,
    memory_cost: int,
    parallelism: int,
    hash_len: int,
) -> None:
    """Reject Argon2 parameters that are invalid or exceed DoS caps.

    Args:
        time_cost: Argon2 iteration count.
        memory_cost: Argon2 memory usage in KiB.
        parallelism: Argon2 lane count.
        hash_len: Derived key length in bytes.

    Raises:
        KeyDerivationError: If any parameter is out of the allowed range.
    """
    values = (time_cost, memory_cost, parallelism, hash_len)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        raise KeyDerivationError("Argon2 parameters must be integers.")
    if not (1 <= time_cost <= MAX_TIME_COST):
        raise KeyDerivationError(
            f"Argon2 time_cost must be between 1 and {MAX_TIME_COST}."
        )
    if not (MIN_MEMORY_COST <= memory_cost <= MAX_MEMORY_COST):
        raise KeyDerivationError(
            f"Argon2 memory_cost must be between {MIN_MEMORY_COST} and "
            f"{MAX_MEMORY_COST} KiB."
        )
    if not (1 <= parallelism <= MAX_PARALLELISM):
        raise KeyDerivationError(
            f"Argon2 parallelism must be between 1 and {MAX_PARALLELISM}."
        )
    if memory_cost < 8 * parallelism:
        raise KeyDerivationError(
            "Argon2 memory_cost must be at least 8 KiB per parallel lane."
        )
    if not (MIN_HASH_LENGTH <= hash_len <= MAX_HASH_LENGTH):
        raise KeyDerivationError(
            f"Derived key length must be between {MIN_HASH_LENGTH} and "
            f"{MAX_HASH_LENGTH} bytes."
        )


def derive_key(
    secret: bytes | bytearray,
    salt: bytes,
    *,
    time_cost: int = DEFAULT_TIME_COST,
    memory_cost: int = DEFAULT_MEMORY_COST,
    parallelism: int = DEFAULT_PARALLELISM,
    hash_len: int = KEY_LENGTH,
) -> bytearray:
    """Derive a symmetric key using Argon2id.

    Args:
        secret: Pre-built secret bytes.
        salt: Random bytes from `generate_salt` (>= 16 bytes).
        time_cost: Argon2 number of iterations.
        memory_cost: Argon2 memory usage in KiB.
        parallelism: Argon2 number of parallel lanes.
        hash_len: Length of the derived key in bytes. Defaults to 32 (AES-256).

    Returns:
        The derived key as a mutable `bytearray` so the caller can zero it
        after use.

    Raises:
        KeyDerivationError: If the salt or Argon2 parameters are invalid.

    Note:
        `argon2-cffi` copies the secret into memory managed by its native
        backend. Returning a mutable buffer supports best-effort wiping, but
        cannot guarantee that every internal copy is erased.
    """
    if len(salt) < MIN_SALT_LENGTH:
        raise KeyDerivationError(f"Salt must be at least {MIN_SALT_LENGTH} bytes.")
    _validate_argon2_params(time_cost, memory_cost, parallelism, hash_len)

    try:
        raw = argon2.low_level.hash_secret_raw(
            secret=bytes(secret),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=argon2.low_level.Type.ID,
        )
    except argon2.exceptions.Argon2Error as e:
        logger.error("Argon2id key derivation failed: %s", e)
        raise KeyDerivationError("Key derivation failed.") from e

    return bytearray(raw)
