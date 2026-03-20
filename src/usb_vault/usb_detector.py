import logging
import wmi
from usb_vault.exceptions import USBVaultError, NoUSBDeviceError

log = logging.getLogger(__name__)


def list_usb_storage_devices() -> list[dict]:
    try:
        c = wmi.WMI()
        drives = c.Win32_DiskDrive(InterfaceType="USB")
    except Exception as e:
        raise USBVaultError("Error encountered") from e

    if not drives:
        log.warning("No disk drives detected")
        raise NoUSBDeviceError("No USB devices detected")

    results = []
    for drive in drives:
        template = {
            "DeviceID": drive.DeviceID,
            "PNPDeviceID": drive.PNPDeviceID,
            "SerialNumber": drive.SerialNumber,
            "Description": drive.Description
        }
        log.debug(template)
        results.append(template)

    return results
