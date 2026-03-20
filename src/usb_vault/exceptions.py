class USBVaultError(Exception):
    """Raised when there is any error within the vault"""


class NoUSBDeviceError(USBVaultError):
    """Raised when no USB storage device is detected"""
