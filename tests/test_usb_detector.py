"""Tests for USB detection error handling and mapping behavior."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from usb_vault.exceptions import NoUSBDeviceError, USBVaultError
from usb_vault.usb_detector import list_usb_storage_devices


def test_list_usb_storage_devices_wraps_wmi_failures():
    """WMI-level failures should be converted into domain-specific USBVaultError."""
    with patch("usb_vault.usb_detector.wmi.WMI", side_effect=RuntimeError("wmi down")):
        with pytest.raises(USBVaultError) as exc_info:
            list_usb_storage_devices()

    assert "WMI communication error" in str(exc_info.value)


def test_list_usb_storage_devices_raises_when_empty():
    """An empty USB drive list should raise NoUSBDeviceError."""
    fake_wmi = SimpleNamespace(Win32_DiskDrive=lambda **_: [])

    with patch("usb_vault.usb_detector.wmi.WMI", return_value=fake_wmi):
        with pytest.raises(NoUSBDeviceError) as exc_info:
            list_usb_storage_devices()

    assert "No USB storage devices detected." in str(exc_info.value)


def test_list_usb_storage_devices_uses_friendly_name_fallback():
    """FriendlyName should fall back to Description when Model/Caption are missing."""
    drive = SimpleNamespace(
        DeviceID="D1",
        PNPDeviceID="PNP1",
        SerialNumber="S1",
        Description="Mass Storage Device",
        Model=None,
        Caption=None,
    )
    fake_wmi = SimpleNamespace(Win32_DiskDrive=lambda **_: [drive])

    with patch("usb_vault.usb_detector.wmi.WMI", return_value=fake_wmi):
        devices = list_usb_storage_devices()

    assert len(devices) == 1
    assert devices[0]["FriendlyName"] == "Mass Storage Device"
    assert devices[0]["PNPDeviceID"] == "PNP1"
