"""Application-specific errors raised by USB Vault.

Callers may catch `USBVaultError` for every expected failure or catch a
subclass when they need a more specific response.
"""

__all__ = [
    "USBVaultError",
    "NoUSBDeviceError",
    "KeyDerivationError",
    "EncryptionError",
    "DecryptionError",
    "InvalidVaultError",
    "AuthenticationError",
    "IntegrityError",
    "VaultLockError",
]


class USBVaultError(Exception):
    """Base exception for all application-specific errors."""


class NoUSBDeviceError(USBVaultError):
    """Raised when no suitable USB storage device is detected."""


class KeyDerivationError(USBVaultError):
    """Raised when key derivation fails or receives invalid parameters."""


class EncryptionError(USBVaultError):
    """Raised when encryption cannot finish safely."""


class DecryptionError(USBVaultError):
    """Raised when decryption cannot finish safely."""


class InvalidVaultError(DecryptionError):
    """Raised when a file is not a recognisable vault.

    Covers a wrong/missing magic header, an unsupported format version, or a
    header that is truncated before the salt and nonce can be read.
    """


class AuthenticationError(DecryptionError):
    """Raised when authenticated decryption fails.

    Indicates the wrong USB device, the wrong password, or that the ciphertext
    has been tampered with. Maps to :class:`cryptography.exceptions.InvalidTag`.
    """


class IntegrityError(DecryptionError):
    """Raised when the ciphertext structure is internally inconsistent.

    Covers truncation (a missing final chunk), trailing data after the
    authenticated final chunk, or a chunk counter that overflows the format.
    """


class VaultLockError(USBVaultError):
    """Raised when another operation already owns the output lock."""
