"""Functional tests for the Command Line Interface (CLI)."""

import os
from unittest.mock import patch

from click.testing import CliRunner
from usb_vault.cli import cli
from usb_vault.exceptions import NoUSBDeviceError

# Define a fake USB device that our mock function will return.
# This makes the tests independent of any real hardware.
FAKE_USB_DEVICE = {
    "FriendlyName": "Test USB Stick",
    "SerialNumber": "12345ABCDE",
    "PNPDeviceID": "USBSTOR\\DISK&VEN_TEST&PROD_USB_STICK&REV_1.0\\12345ABCDE&0",
}


@patch("usb_vault.cli.list_usb_storage_devices")
def test_cli_encrypt_decrypt_roundtrip(mock_list_usb):
    """
    Tests the full CLI encrypt and decrypt command roundtrip.
    This simulates a user running the program, selecting a device,
    encrypting a file, and then decrypting it.
    """
    mock_list_usb.return_value = [FAKE_USB_DEVICE]

    runner = CliRunner()

    original_content = b"CLI roundtrip test data"
    with runner.isolated_filesystem():
        with open("test.txt", "wb") as f:
            f.write(original_content)

        encrypt_result = runner.invoke(
            cli,
            ["encrypt", "test.txt", "test.vault"],
            input="1\ntestpassword\ntestpassword\n",
        )

        assert encrypt_result.exit_code == 0, encrypt_result.output
        assert "Successfully encrypted" in encrypt_result.output
        assert os.path.exists("test.vault")

        decrypt_result = runner.invoke(
            cli,
            ["decrypt", "test.vault", "decrypted.txt"],
            input="1\ntestpassword\ny\n",
        )

        assert decrypt_result.exit_code == 0, decrypt_result.output
        assert "Successfully decrypted" in decrypt_result.output
        assert os.path.exists("decrypted.txt")

        with open("decrypted.txt", "rb") as f:
            decrypted_content = f.read()

        assert decrypted_content == original_content


@patch("usb_vault.cli.list_usb_storage_devices")
def test_cli_no_usb_devices(mock_list_usb):
    """
    Tests that the CLI handles the case where no USB devices are found.
    """
    mock_list_usb.side_effect = NoUSBDeviceError("No devices")

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("in.txt", "wb") as f:
            f.write(b"dummy")

        result = runner.invoke(cli, ["encrypt", "in.txt", "out.vault"])

    assert result.exit_code != 0, "Exit code should be non-zero for this error."
    assert "No USB devices detected" in result.output


@patch("usb_vault.cli.list_usb_storage_devices")
def test_cli_encrypt_no_output_path_confirm(mock_list_usb):
    """Tests that encrypt suggests a default output and proceeds on confirmation."""
    mock_list_usb.return_value = [FAKE_USB_DEVICE]
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("data.txt", "wb") as f:
            f.write(b"some data")

        result = runner.invoke(
            cli,
            ["encrypt", "data.txt"],
            input="y\n1\ntestpassword\ntestpassword\n",
        )

        assert result.exit_code == 0, result.output
        assert "Successfully encrypted" in result.output
        assert os.path.exists("data.txt.vault")


@patch("usb_vault.cli.list_usb_storage_devices")
def test_cli_encrypt_no_output_path_cancel(mock_list_usb):
    """Tests that encrypt command aborts if user declines the suggested output."""
    mock_list_usb.return_value = [FAKE_USB_DEVICE]
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("data.txt", "wb") as f:
            f.write(b"some data")

        result = runner.invoke(
            cli,
            ["encrypt", "data.txt"],
            input="n\n",
        )

        assert result.exit_code == 0
        assert "Operation cancelled" in result.output
        assert not os.path.exists("data.txt.vault")


@patch("usb_vault.cli.list_usb_storage_devices")
def test_cli_decrypt_no_output_path_confirm(mock_list_usb):
    """Tests that decrypt suggests a default output and proceeds on confirmation."""
    mock_list_usb.return_value = [FAKE_USB_DEVICE]
    runner = CliRunner()
    original_content = b"secret"
    with runner.isolated_filesystem():
        with open("original.txt", "wb") as f:
            f.write(original_content)
        encrypt_result = runner.invoke(
            cli,
            ["encrypt", "original.txt", "data.txt.vault"],
            input="1\ntestpassword\ntestpassword\n",
        )
        assert encrypt_result.exit_code == 0

        result = runner.invoke(
            cli,
            ["decrypt", "data.txt.vault"],
            input="y\n1\ntestpassword\n",
        )

        assert result.exit_code == 0, result.output
        assert "Successfully decrypted" in result.output
        assert os.path.exists("data.txt")
        with open("data.txt", "rb") as f:
            assert f.read() == original_content


@patch("usb_vault.cli.list_usb_storage_devices")
def test_cli_decrypt_no_output_path_invalid_extension(mock_list_usb):
    """Tests that decrypt fails if no output is given and
    input file is not a .vault file."""
    mock_list_usb.return_value = [FAKE_USB_DEVICE]
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("data.txt", "wb") as f:
            f.write(b"not a vault")

        result = runner.invoke(
            cli,
            ["decrypt", "data.txt"],
            input="y\n",
        )

        assert result.exit_code == 1
        assert "Cannot determine default output name" in result.output
