"""Tests for the key derivation module.

Verifies the Argon2id implementation, ensuring determinism, sensitivity to
input changes (salt/password), and adherence to the specified security parameters.
"""

import base64

from usb_vault.key_derivation import derive_key, generate_salt

KNOWN_PASSWORD = "password"
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
    different_password = "password123"
    key1 = derive_key(KNOWN_PASSWORD, KNOWN_SALT)
    key2 = derive_key(different_password, KNOWN_SALT)
    assert key1 != key2
