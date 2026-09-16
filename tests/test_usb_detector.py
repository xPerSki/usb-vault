"""Tests for USB detection error handling and mapping behavior."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
import pythoncom
import wmi
from usb_vault.exceptions import NoUSBDeviceError, USBVaultError
from usb_vault.usb_detector import (
    _RPC_E_CHANGED_MODE,
    get_device_fingerprint,
    list_usb_storage_devices,
)


def test_list_usb_storage_devices_wraps_wmi_failures():
    """WMI-level failures should be converted into domain-specific USBVaultError."""
    with patch("usb_vault.usb_detector.wmi.WMI", side_effect=wmi.x_wmi("wmi down")):
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


def test_list_usb_storage_devices_manages_com_on_calling_thread():
    """Every WMI query must initialize and release COM on its own thread."""
    fake_wmi = SimpleNamespace(Win32_DiskDrive=lambda **_: [])
    worker = object()

    with (
        patch("usb_vault.usb_detector.threading.current_thread", return_value=worker),
        patch("usb_vault.usb_detector.threading.main_thread", return_value=object()),
        patch("usb_vault.usb_detector.pythoncom.CoInitialize") as initialize,
        patch("usb_vault.usb_detector.pythoncom.CoUninitialize") as uninitialize,
        patch("usb_vault.usb_detector.wmi.WMI", return_value=fake_wmi),
        pytest.raises(NoUSBDeviceError),
    ):
        list_usb_storage_devices()

    initialize.assert_called_once_with()
    uninitialize.assert_called_once_with()


def test_main_thread_leaves_pythoncom_lifecycle_untouched():
    """pythoncom itself owns COM setup and teardown on Python's main thread."""
    main = object()
    fake_wmi = SimpleNamespace(Win32_DiskDrive=lambda **_: [])

    with (
        patch("usb_vault.usb_detector.threading.current_thread", return_value=main),
        patch("usb_vault.usb_detector.threading.main_thread", return_value=main),
        patch("usb_vault.usb_detector.pythoncom.CoInitialize") as initialize,
        patch("usb_vault.usb_detector.pythoncom.CoUninitialize") as uninitialize,
        patch("usb_vault.usb_detector.wmi.WMI", return_value=fake_wmi),
        pytest.raises(NoUSBDeviceError),
    ):
        list_usb_storage_devices()

    initialize.assert_not_called()
    uninitialize.assert_not_called()


def test_com_changed_mode_uses_existing_apartment():
    """An existing COM apartment is usable and must not be uninitialized."""
    changed_mode = pythoncom.com_error(
        _RPC_E_CHANGED_MODE,
        "COM apartment already selected",
        None,
        None,
    )
    fake_wmi = SimpleNamespace(Win32_DiskDrive=lambda **_: [])
    worker = object()

    with (
        patch("usb_vault.usb_detector.threading.current_thread", return_value=worker),
        patch("usb_vault.usb_detector.threading.main_thread", return_value=object()),
        patch(
            "usb_vault.usb_detector.pythoncom.CoInitialize",
            side_effect=changed_mode,
        ),
        patch("usb_vault.usb_detector.pythoncom.CoUninitialize") as uninitialize,
        patch("usb_vault.usb_detector.wmi.WMI", return_value=fake_wmi),
        pytest.raises(NoUSBDeviceError),
    ):
        list_usb_storage_devices()

    uninitialize.assert_not_called()


def test_get_device_fingerprint_is_case_insensitive():
    """PNPDeviceID casing differences must not change the fingerprint."""
    lower = {"PNPDeviceID": "usbstor\\disk&ven_x", "Model": "Generic"}
    upper = {"PNPDeviceID": "USBSTOR\\DISK&VEN_X", "Model": "GENERIC"}
    assert get_device_fingerprint(lower) == get_device_fingerprint(upper)


def test_get_device_fingerprint_rejects_missing_identifier():
    """A device without a PNPDeviceID must raise instead of hashing an empty
    string into a globally constant key."""
    with pytest.raises(USBVaultError):
        get_device_fingerprint({"PNPDeviceID": "   ", "Model": "Generic"})
