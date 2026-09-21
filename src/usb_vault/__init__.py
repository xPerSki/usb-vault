"""USB Vault package."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

__version__ = "0.3.0"


def get_version() -> str:
    """Return the installed distribution version, or the package constant.

    Prefers `importlib.metadata` when the wheel/editable install is present
    so an environment that somehow disagrees with the source tree still
    reports what was installed. Falls back to `__version__` for source
    checkouts and frozen executables that ship without `*.dist-info`.

    Returns:
        A string such as `"0.1.0"`.
    """
    try:
        return version("usb-vault")
    except PackageNotFoundError:
        return __version__
