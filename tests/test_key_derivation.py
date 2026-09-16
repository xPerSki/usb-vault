"""Tests for the key derivation module.

Verifies the Argon2id implementation, ensuring determinism, sensitivity to
input changes (salt/password), and adherence to the specified security parameters.
"""

import base64

import pytest
from usb_vault.exceptions import KeyDerivationError
from usb_vault.key_derivation import (
    MAX_HASH_LENGTH,
    MAX_MEMORY_COST,
    MAX_PARALLELISM,
    MAX_TIME_COST,
    derive_key,
    generate_salt,
)

KNOWN_PASSWORD = b"password"
KNOWN_SALT = b"\x00" * 16
KNOWN_KEY = b"1PV+ERo3ioHiBupB92WzqmZFs0NNMFsoP/V1BHOiXOE="


def test_derive_key_is_deterministic():
    """
    Tests that the KDF is deterministic.
    For the same password and salt, the key must be identical.
    """
    key1 = derive_key(KNOWN_PASSWORD, KNOWN_SALT)
    key2 = derive_key(KNOWN_PASSWORD, KNOWN_SALT)
    assert key1 == key2


def test_derive_key_known_vector():
    """
    Tests the KDF against a known test vector.
    This verifies the underlying cryptographic algorithm is correct.
    """
    derived_key = derive_key(KNOWN_PASSWORD, KNOWN_SALT)
    assert base64.b64encode(derived_key) == KNOWN_KEY


def test_generate_salt():
    """
    Tests that generate_salt returns unpredictable 16-byte outputs.
    """
    salt1 = generate_salt()
    salt2 = generate_salt()
    assert len(salt1) == 16
    assert len(salt2) == 16
    assert salt1 != salt2


def test_derive_key_salt_matters():
    """
    Tests that using a different salt produces a different key.
    """
    different_salt = b"\x01" * 16
    key1 = derive_key(KNOWN_PASSWORD, KNOWN_SALT)
    key2 = derive_key(KNOWN_PASSWORD, different_salt)
    assert key1 != key2


def test_derive_key_password_matters():
    """
    Tests that using a different password produces a different key.
    """
    different_password = b"password123"
    key1 = derive_key(KNOWN_PASSWORD, KNOWN_SALT)
    key2 = derive_key(different_password, KNOWN_SALT)
    assert key1 != key2


def test_derive_key_rejects_short_salt():
    """A salt below the 16-byte minimum must be rejected."""
    with pytest.raises(KeyDerivationError):
        derive_key(KNOWN_PASSWORD, b"\x00" * 8)


def test_generate_salt_rejects_short_length():
    """Requesting a salt shorter than 16 bytes must be rejected."""
    with pytest.raises(KeyDerivationError):
        generate_salt(8)


def test_generate_salt_rejects_non_integer_length():
    """Boolean and non-integer lengths must fail as domain errors."""
    with pytest.raises(KeyDerivationError, match="integer"):
        generate_salt(True)


def test_derive_key_params_matter():
    """Changing the Argon2 cost parameters must change the derived key."""
    key1 = derive_key(KNOWN_PASSWORD, KNOWN_SALT, time_cost=3)
    key2 = derive_key(KNOWN_PASSWORD, KNOWN_SALT, time_cost=4)
    assert key1 != key2


def test_derive_key_rejects_time_cost_above_cap():
    """time_cost above MAX_TIME_COST must fail before Argon2 runs."""
    with pytest.raises(KeyDerivationError, match="time_cost"):
        derive_key(KNOWN_PASSWORD, KNOWN_SALT, time_cost=MAX_TIME_COST + 1)


def test_derive_key_rejects_memory_cost_above_cap():
    """memory_cost above MAX_MEMORY_COST must fail before Argon2 runs."""
    with pytest.raises(KeyDerivationError, match="memory_cost"):
        derive_key(KNOWN_PASSWORD, KNOWN_SALT, memory_cost=MAX_MEMORY_COST + 1)


def test_derive_key_accepts_parallelism_at_cap():
    """parallelism equal to MAX_PARALLELISM must still be accepted."""
    key = derive_key(KNOWN_PASSWORD, KNOWN_SALT, parallelism=MAX_PARALLELISM)
    assert len(key) == 32


def test_derive_key_rejects_too_little_memory_for_lanes():
    """Argon2 requires at least 8 KiB for each parallel lane."""
    with pytest.raises(KeyDerivationError, match="8 KiB per parallel lane"):
        derive_key(KNOWN_PASSWORD, KNOWN_SALT, memory_cost=8, parallelism=2)


def test_derive_key_rejects_excessive_hash_length():
    """Unbounded output allocation must be rejected before Argon2 runs."""
    with pytest.raises(KeyDerivationError, match="key length"):
        derive_key(KNOWN_PASSWORD, KNOWN_SALT, hash_len=MAX_HASH_LENGTH + 1)


def test_derive_key_rejects_non_integer_parameters():
    """Bad caller types must become predictable domain errors."""
    with pytest.raises(KeyDerivationError, match="integers"):
        derive_key(KNOWN_PASSWORD, KNOWN_SALT, time_cost=True)


@pytest.mark.parametrize("parallelism", [0, MAX_PARALLELISM + 1, 8])
def test_derive_key_rejects_parallelism_out_of_range(parallelism: int):
    """parallelism outside 1..MAX_PARALLELISM must be rejected."""
    with pytest.raises(KeyDerivationError, match="parallelism"):
        derive_key(KNOWN_PASSWORD, KNOWN_SALT, parallelism=parallelism)
