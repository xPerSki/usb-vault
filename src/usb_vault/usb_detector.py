"""USB Detection Module.

Handles hardware enumeration and fingerprinting of USB storage devices
on Windows systems using the WMI (Windows Management Instrumentation) interface.
"""

import hashlib

import wmi

from usb_vault.exceptions import NoUSBDeviceError, USBVaultError


def get_device_fingerprint(device: dict) -> str:
    """Generates a stable, unique cryptographic fingerprint for a USB device.

    Combines immutable hardware identifiers into SHA-256 hash. This ensures
    that the derived key is strictly bound to the physical hardware's silicon,
    rather than volatile attributes like mounting paths or drive letters.

    This relies exclusively on:
    - PNPDeviceID: Inherently incorporates Vendor ID, Product ID, Firmware Revision,
      and the Serial Number in a standardized string format.
    - Model: Provides a stable generic string fallback (e.g. product name).

    Using these two fields avoids redundancy and potential issues with generic
    devices that fail to expose a clean secondary SerialNumber field to the OS.

    Args:
        device (dict): A dictionary containing USB device attributes.

    Returns:
        str: A stable hex-encoded SHA-256 fingerprint.
    """
    components = [
        str(device.get("PNPDeviceID", "")).strip(),
        str(device.get("Model", "")).strip(),
    ]
    raw_fingerprint = "||".join(components)
    return hashlib.sha256(raw_fingerprint.encode("utf-8")).hexdigest()


def list_usb_storage_devices() -> list[dict]:
    """Lists all connected USB storage devices and their hardware identifiers.

    Returns:
        list[dict]: A list of dictionaries where each dictionary contains hardware
                    information about the device.

    Raises:
        USBVaultError: If there is an error communicating with the WMI service.
        NoUSBDeviceError: If no USB storage devices are currently connected.
    """
    try:
        c = wmi.WMI()
        drives = c.Win32_DiskDrive(InterfaceType="USB")
    except Exception as e:
        raise USBVaultError("WMI communication error") from e

    if not drives:
        raise NoUSBDeviceError("No USB storage devices detected.")

    results = []
    for drive in drives:
        # Prioritize more descriptive names like Model or Caption.
        # Fall back to a generic description if they are not available.
        friendly_name = drive.Model or drive.Caption or drive.Description or "USB Drive"

        template = {
            "DeviceID": drive.DeviceID,
            "PNPDeviceID": drive.PNPDeviceID,
            "SerialNumber": drive.SerialNumber,
            "Description": drive.Description,
            "Model": drive.Model,
            "Caption": drive.Caption,
            "FriendlyName": friendly_name,
        }
        results.append(template)

    return results
