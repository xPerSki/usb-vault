class USBVaultError(Exception):
    """Base exception for all application-specific errors."""


class NoUSBDeviceError(USBVaultError):
    """Raised when no suitable USB storage device is detected."""


class EncryptionError(USBVaultError):
    """Raised when an error occurs during the encryption process."""


class DecryptionError(USBVaultError):
    """Raised when an error occurs during the decryption process."""
