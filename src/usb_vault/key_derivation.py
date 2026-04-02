"""Key derivation module.

Transforms a USB device fingerprint into a 256-bit AES-compatible key
using Argon2id. Raw device identifiers are low entropy and cannot be
used directly as cryptographic keys. Argon2id stretches and hardens
the input making brute force computationally infeasible.
"""

import os

import argon2


def generate_salt(n: int = 16) -> bytes:
    """Generates a cryptographically secure random salt.

    Args:
        n (int): The length of the salt in bytes. Defaults to 16.

    Returns:
        bytes: A random salt generated using os.urandom.

    Note:
        OWASP minimum recommendation for salt length is 16 bytes
        Change it only if you know what you are doing
    """
    return os.urandom(n)


def derive_key(fingerprint: str, salt: bytes) -> bytearray:
    """Derives a 256-bit cryptographic key from a USB fingerprint using Argon2id.

    Args:
        fingerprint: USB unique ID string from usb_detector
        salt: Random bytes from generate_salt()

    Returns:
        32 raw bytes suitable for use as an AES-256 key, enclosed in a mutable bytearray.

    Note:
        Default parameters use recommended OWASP values
    """
    secret = argon2.low_level.hash_secret_raw(
        secret=fingerprint.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=argon2.low_level.Type.ID,
    )
    return bytearray(secret)
