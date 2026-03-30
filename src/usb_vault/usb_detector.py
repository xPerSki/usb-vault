"""USB Detection Module.

Handles hardware enumeration and fingerprinting of USB storage devices
on Windows systems using the WMI (Windows Management Instrumentation) interface.
"""

import logging

import wmi

from usb_vault.exceptions import NoUSBDeviceError, USBVaultError

log = logging.getLogger(__name__)


def list_usb_storage_devices() -> list[dict]:
    """Lists all connected USB storage devices and their hardware identifiers.

    Returns:
        list[dict]: A list of dictionaries where each dictionary contains:
            - DeviceID: The physical drive identifier.
            - PNPDeviceID: The PNP device identifier (used for fingerprinting).
            - SerialNumber: The hardware serial number.
            - Description: The device description.

    Raises:
        USBVaultError: If there is an error communicating with the WMI service.
        NoUSBDeviceError: If no USB storage devices are currently connected.

    """
    try:
        c = wmi.WMI()
        drives = c.Win32_DiskDrive(InterfaceType="USB")
    except Exception as e:
        raise USBVaultError("Error encountered") from e

    if not drives:
        log.warning("No USB devices detected")
        raise NoUSBDeviceError("No USB devices detected")

    results = []
    for drive in drives:
        template = {
            "DeviceID": drive.DeviceID,
            "PNPDeviceID": drive.PNPDeviceID,
            "SerialNumber": drive.SerialNumber,
            "Description": drive.Description,
        }
        log.debug(template)
        results.append(template)

    return results


if __name__ == "__main__":
    print(list_usb_storage_devices())
