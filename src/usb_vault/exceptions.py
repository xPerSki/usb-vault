class USBVaultError(Exception):
    """Raised when there is any error within the vault."""


class NoUSBDeviceError(USBVaultError):
    """Raised when no USB storage device is detected."""


class EncryptionError(USBVaultError):
    """Raised when an error occurs during the encryption process."""


class DecryptionError(USBVaultError):
    """Raised when an error occurs during the decryption process."""
