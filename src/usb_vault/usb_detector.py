"""Discover USB storage devices and derive repeatable fingerprints.

Windows exposes these identifiers to local software, so a fingerprint
identifies a USB device but is not a secret. Use a passphrase for strong
confidentiality.
"""

import contextlib
import hashlib
import logging
import threading
from collections.abc import Iterator
from typing import Protocol, TypedDict

from .exceptions import NoUSBDeviceError, USBVaultError

logger = logging.getLogger(__name__)
_RPC_E_CHANGED_MODE = -2147417850

# `wmi` (and its `pywin32` dependency) is Windows-only. Importing it lazily and
# guarding the failure keeps the whole package importable on Linux/macOS - for
# example so the test suite can run and mock this module on any platform.
try:
    import wmi
except ImportError:  # pragma: no cover - platform-dependent
    wmi = None  # type: ignore[assignment]

try:
    import pythoncom
except ImportError:  # pragma: no cover - platform-dependent
    pythoncom = None  # type: ignore[assignment]


@contextlib.contextmanager
def _com_initialized() -> Iterator[None]:
    """Initialise COM for the duration of the block on the calling thread.

    WMI uses COM, which must be initialised separately on every thread. Keeping
    that detail here lets CLI and GUI callers use the same public function.

    Yields:
        None, with COM usable on the current thread.
    """
    if pythoncom is None:  # pragma: no cover - platform-dependent
        yield
        return

    # Importing pythoncom initializes Python's main thread and owns its
    # shutdown. Balancing that initialization here releases COM before
    # pywin32's cached WMI objects, causing noisy IUnknown errors at exit.
    if threading.current_thread() is threading.main_thread():
        yield
        return

    initialized = False
    try:
        pythoncom.CoInitialize()
        initialized = True
    except pythoncom.com_error as e:
        # A thread that already uses another COM apartment model can still use
        # WMI. Any other initialization failure is real and must not be hidden.
        if e.hresult != _RPC_E_CHANGED_MODE:
            raise USBVaultError("Could not initialize Windows device services.") from e

    try:
        yield
    finally:
        if initialized:
            pythoncom.CoUninitialize()


class _WmiDiskDrive(Protocol):
    """Fields read from WMI's dynamic `Win32_DiskDrive` object."""

    DeviceID: str | None
    PNPDeviceID: str | None
    SerialNumber: str | None
    Description: str | None
    Model: str | None
    Caption: str | None


class UsbDevice(TypedDict):
    """Structured description of a connected USB storage device."""

    DeviceID: str | None
    PNPDeviceID: str | None
    SerialNumber: str | None
    Description: str | None
    Model: str | None
    Caption: str | None
    FriendlyName: str


def get_device_fingerprint(device: UsbDevice) -> str:
    """Generate a stable fingerprint for a USB device.

    The fingerprint uses identifiers that normally remain stable across drive
    letter changes. It is an identifier, not a hardware-protected secret.

    Args:
        device: A `UsbDevice` describing the selected device.

    Returns:
        A SHA-256 fingerprint encoded as lowercase hexadecimal.

    Raises:
        USBVaultError: If the device has no usable `PNPDeviceID`.
    """
    pnp_device_id = str(device.get("PNPDeviceID") or "").strip().upper()
    model = str(device.get("Model") or "").strip().upper()

    if not pnp_device_id:
        logger.debug("Device is missing a PNPDeviceID; cannot fingerprint.")
        raise USBVaultError(
            "Selected device exposes no hardware identifier (PNPDeviceID)."
        )

    # Keep this exact separator for version-2 vault compatibility.
    raw_fingerprint = "||".join([pnp_device_id, model])
    return hashlib.sha256(raw_fingerprint.encode("utf-8")).hexdigest()


def list_usb_storage_devices() -> list[UsbDevice]:
    """List connected USB storage devices and their identifiers.

    Returns:
        A list of `UsbDevice` entries describing each connected device.

    Raises:
        USBVaultError: If WMI is unavailable or cannot be queried.
        NoUSBDeviceError: If no USB storage devices are currently connected.
    """
    if wmi is None:
        raise USBVaultError(
            "USB enumeration is only supported on Windows with the 'wmi' "
            "package installed."
        )

    with _com_initialized():
        return _query_usb_drives()


def _query_usb_drives() -> list[UsbDevice]:
    """Read USB disk drives from WMI into plain Python records.

    Must be called with COM initialised on the current thread

    Returns:
        A list of `UsbDevice` entries.

    Raises:
        USBVaultError: On WMI communication failure.
        NoUSBDeviceError: If no USB storage devices are connected.
    """
    connection = None
    drives = None
    try:
        connection = wmi.WMI()
        drives = connection.Win32_DiskDrive(InterfaceType="USB")

        if not drives:
            raise NoUSBDeviceError("No USB storage devices detected.")

        # Convert COM objects to plain values before COM is uninitialised.
        return [_map_drive(drive) for drive in drives]
    except wmi.x_wmi as e:
        logger.error("WMI communication error during USB enumeration: %s", e)
        raise USBVaultError("WMI communication error") from e
    finally:
        # Release COM references before _com_initialized exits.
        drives = None
        connection = None


def _map_drive(drive: _WmiDiskDrive) -> UsbDevice:
    """Convert a WMI `Win32_DiskDrive` instance into a plain record.

    Args:
        drive: A live WMI COM object for one disk drive.

    Returns:
        A `UsbDevice` holding only immutable Python values.
    """
    # Prefer the most descriptive name, falling back to generic fields.
    friendly_name = drive.Model or drive.Caption or drive.Description or "USB Drive"

    if not drive.PNPDeviceID:
        logger.debug("USB drive %r reported a blank PNPDeviceID.", friendly_name)

    return UsbDevice(
        DeviceID=drive.DeviceID,
        PNPDeviceID=drive.PNPDeviceID,
        SerialNumber=drive.SerialNumber,
        Description=drive.Description,
        Model=drive.Model,
        Caption=drive.Caption,
        FriendlyName=friendly_name,
    )
