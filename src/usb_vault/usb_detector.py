"""USB Detection Module.

Handles hardware enumeration and fingerprinting of USB storage devices
on Windows systems using the WMI (Windows Management Instrumentation) interface.
"""

import wmi

from usb_vault.exceptions import NoUSBDeviceError, USBVaultError


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
