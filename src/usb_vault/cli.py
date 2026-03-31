"""Command-line interface for USB Vault.

This module provides the main entry point for the usb-vault application,
offering commands to encrypt and decrypt files using a hardware-bound key
derived from a connected USB device.
"""

import sys
from pathlib import Path

import click

from .crypto import decrypt_file, encrypt_file
from .exceptions import NoUSBDeviceError, USBVaultError
from .usb_detector import list_usb_storage_devices


def _select_usb_device() -> str:
    """Interactively prompts the user to select a USB device.

    Displays a list of connected USB storage devices, using the FriendlyName,
    and allows the user to pick one or refresh the list.

    Returns:
        str: The PNPDeviceID of the selected USB device, to be used as a fingerprint.

    Raises:
        NoUSBDeviceError: If the user exits the selection without picking a device.
    """
    while True:
        try:
            devices = list_usb_storage_devices()
            click.echo("Available USB devices:")
            for i, device in enumerate(devices, 1):
                friendly_name = device.get("FriendlyName", "Unknown USB Device")
                serial_number = device.get("SerialNumber", "No Serial")

                click.echo(f" {i}: {friendly_name} (Serial: {serial_number})")

            click.echo(
                "\nSelect a device (1-N), press Enter to refresh, "
                "or type 'q' to quit."
            )

            choice = click.prompt(
                "Your choice", type=str, default="", show_default=False
            )

            if choice.lower() == "q":
                click.echo("Exiting...")
                sys.exit(0)

            if choice == "" or choice == "0":
                click.echo("Refreshing...")
                continue

            try:
                choice_index = int(choice) - 1
                if 0 <= choice_index < len(devices):
                    selected_device = devices[choice_index]
                    fingerprint = selected_device["PNPDeviceID"]

                    click.secho(
                        f"Selected "
                        f"'{selected_device.get('FriendlyName', 'USB Device')}'.",
                        fg="green",
                    )
                    return fingerprint
                else:
                    click.secho("Invalid selection. Please try again.", fg="yellow")
            except ValueError:
                click.secho("Invalid input. Please enter a number.", fg="yellow")

        except NoUSBDeviceError:
            click.secho(
                "No USB devices detected. "
                "Please connect a device and press Enter to refresh.",
                fg="yellow",
            )
            click.prompt("", default="", show_default=False)


@click.group()
def cli() -> None:
    """A hardware-bound file encryption tool for Windows."""


@cli.command()
@click.argument(
    "input_file",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
)
@click.argument(
    "output_file",
    type=click.Path(dir_okay=False, resolve_path=True),
    required=False,
)
def encrypt(input_file: str, output_file: str | None = None) -> None:
    """Encrypt a file using a key derived from a connected USB device."""
    try:
        in_path = Path(input_file)

        if output_file is None:
            out_path = in_path.with_name(f"{in_path.name}.vault")
            if not click.confirm(
                f"Output file not specified. "
                f"Do you want to save to '{out_path.name}'?"
            ):
                click.secho("Operation cancelled.", fg="yellow")
                sys.exit(0)
        else:
            out_path = Path(output_file)

        if out_path.suffix != ".vault":
            out_path = out_path.with_suffix(".vault")
            click.secho(
                f"Warning: Output file did not have .vault extension. "
                f"Saving to {out_path}",
                fg="yellow",
            )

        if out_path.exists():
            if not click.confirm(
                f"Output file '{out_path}' already exists. Do you want to overwrite it?"
            ):
                click.secho("Operation cancelled.", fg="yellow")
                sys.exit(0)

        fingerprint = _select_usb_device()

        encrypt_file(
            fingerprint=fingerprint,
            input_file=in_path,
            output_file=out_path,
        )

        click.secho(
            f"Successfully encrypted '{in_path.name}' to '{out_path.name}'", fg="green"
        )

    except USBVaultError as e:
        click.secho(f"Encryption failed: {e}", fg="red")
        sys.exit(1)


@cli.command()
@click.argument(
    "input_file",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
)
@click.argument(
    "output_file",
    type=click.Path(dir_okay=False, resolve_path=True),
    required=False,
)
def decrypt(input_file: str, output_file: str | None = None) -> None:
    """Decrypt a .vault file using a key from the original USB device."""
    try:
        in_path = Path(input_file)

        if output_file is None:
            if in_path.suffix == ".vault":
                out_path = in_path.with_suffix("")
                if not click.confirm(
                    f"Output file not specified. "
                    f"Do you want to save to '{out_path.name}'?"
                ):
                    click.secho("Operation cancelled.", fg="yellow")
                    sys.exit(0)
            else:
                click.secho(
                    "Error: Output file not specified and input file does not "
                    "have .vault extension. Cannot determine default output name.",
                    fg="red",
                )
                sys.exit(1)
        else:
            out_path = Path(output_file)

        if in_path.suffix != ".vault":
            click.secho(
                "Warning: Input file does not have a .vault extension.", fg="yellow"
            )

        if out_path.exists():
            if not click.confirm(
                f"Output file '{out_path}' already exists. Do you want to overwrite it?"
            ):
                click.secho("Operation cancelled.", fg="yellow")
                sys.exit(0)

        fingerprint = _select_usb_device()

        decrypt_file(
            fingerprint=fingerprint,
            input_file=in_path,
            output_file=out_path,
        )

        click.secho(
            f"Successfully decrypted '{in_path.name}' to '{out_path.name}'", fg="green"
        )

    except USBVaultError as e:
        click.secho(f"Decryption failed: {e}", fg="red")
        sys.exit(1)


if __name__ == "__main__":
    cli()
