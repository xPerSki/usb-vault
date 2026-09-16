"""Command-line interface for USB Vault.

Provides interactive encrypt and decrypt commands for Windows.
"""

import logging
from pathlib import Path

import click
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
)

from .crypto import decrypt_file, encrypt_file, wipe_secret
from .exceptions import NoUSBDeviceError, USBVaultError
from .usb_detector import get_device_fingerprint, list_usb_storage_devices

logger = logging.getLogger(__name__)


def _is_file_readable(filepath: Path) -> bool:
    """Check for read access.

    Args:
        filepath: The path to the file to check.

    Returns:
        True if the file is readable, False otherwise.
    """
    try:
        with filepath.open("rb"):
            return True
    except OSError:
        return False


def _is_file_writable(filepath: Path) -> bool:
    """Check for write access.

    Args:
        filepath: The path to the file to check.

    Returns:
        True if the file is writable, False otherwise.
    """
    if not filepath.exists():
        return True
    try:
        with filepath.open("ab"):
            return True
    except OSError:
        return False


def _select_usb_device() -> str:
    """Prompt until the user selects a usable USB device or quits.

    Returns:
        The selected device's SHA-256 fingerprint.

    Raises:
        click.exceptions.Exit: If the user quits without selecting a device.
    """
    while True:
        try:
            devices = list_usb_storage_devices()
            click.echo("Available USB devices:")
            for i, device in enumerate(devices, 1):
                friendly_name = device.get("FriendlyName", "Unknown USB Device")
                serial_number = str(device.get("SerialNumber") or "")
                serial_hint = (
                    f"{serial_number[:4]}…{serial_number[-4:]}"
                    if len(serial_number) > 8
                    else (serial_number or "unavailable")
                )

                click.echo(f" {i}: {friendly_name} (Serial: {serial_hint})")

            click.echo(
                "\nSelect a device (1-N), press Enter to refresh, "
                "or type 'q' to quit."
            )

            choice = click.prompt(
                "Your choice", type=str, default="", show_default=False
            )

            if choice.lower() == "q":
                click.echo("Exiting...")
                raise click.exceptions.Exit(0)

            if choice == "" or choice == "0":
                click.echo("Refreshing...")
                continue

            try:
                choice_index = int(choice) - 1
                if 0 <= choice_index < len(devices):
                    selected_device = devices[choice_index]
                    try:
                        fingerprint = get_device_fingerprint(selected_device)
                    except USBVaultError:
                        click.secho(
                            "Error: Selected device has no hardware identifiers.",
                            fg="red",
                        )
                        continue

                    click.secho(
                        f"Selected "
                        f"'{selected_device.get('FriendlyName', 'USB Device')}'.",
                        fg="green",
                    )
                    return str(fingerprint)
                else:
                    click.secho("Invalid selection. Please try again.", fg="yellow")
            except ValueError:
                click.secho("Invalid input. Please enter a number.", fg="yellow")

        except NoUSBDeviceError:
            click.secho(
                "No USB devices detected. "
                "Please connect a device and press Enter to refresh, or 'q' to quit.",
                fg="yellow",
            )
            result = click.prompt("Your choice", default="", show_default=False)
            if result.lower() == "q":
                click.echo("Exiting...")
                raise click.exceptions.Exit(0)


@click.group()
def cli() -> None:
    """Encrypt files with a USB fingerprint and optional passphrase."""


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
@click.option(
    "--password",
    is_flag=True,
    help="Prompt for an optional passphrase without echoing it.",
)
def encrypt(
    input_file: str,
    output_file: str | None = None,
    password: bool = False,
) -> None:
    """Encrypt a file using a key derived from a connected USB device."""
    pwd = bytearray()
    try:
        in_path = Path(input_file)

        if not _is_file_readable(in_path):
            click.secho(
                f"Error: Input file '{in_path.name}' is currently open or unreadable. "
                "Close it and try again.",
                fg="red",
            )
            raise click.exceptions.Exit(1)

        if output_file is None:
            out_path = in_path.with_name(f"{in_path.name}.vault")
            if not click.confirm(
                f"Output file not specified. "
                f"Do you want to save to '{out_path.name}'?"
            ):
                click.secho("Operation cancelled.", fg="yellow")
                raise click.exceptions.Exit(0)
        else:
            out_path = Path(output_file)

        if out_path.suffix.lower() != ".vault":
            out_path = out_path.with_suffix(".vault")
            click.secho(
                f"Warning: Output file did not have .vault extension. "
                f"Saving to {out_path}",
                fg="yellow",
            )

        if out_path.exists():
            if not _is_file_writable(out_path):
                click.secho(
                    f"Error: Output file '{out_path.name}' is currently open or unwritable. "
                    "Close it and try again.",
                    fg="red",
                )
                raise click.exceptions.Exit(1)

            if not click.confirm(
                f"Output file '{out_path}' already exists. Do you want to overwrite it?"
            ):
                click.secho("Operation cancelled.", fg="yellow")
                raise click.exceptions.Exit(0)

        fingerprint = _select_usb_device()

        if password:
            raw_password = click.prompt(
                "Passphrase", hide_input=True, confirmation_prompt=True
            )
            pwd.extend(raw_password.encode("utf-8"))
            is_short = len(raw_password) < 8
            del raw_password
            if is_short:
                click.secho(
                    "Warning: Passphrase is shorter than 8 characters. "
                    "Consider using a stronger passphrase.",
                    fg="yellow",
                )
        else:
            click.secho(
                "Warning: USB identifiers are not secret and may be copied "
                "from this computer. Use --password for strong protection.",
                fg="yellow",
            )

        with Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "•",
            DownloadColumn(),
            "•",
            TimeRemainingColumn(),
        ) as progress:
            task = progress.add_task(
                f"Encrypting {in_path.name}", total=in_path.stat().st_size
            )

            def update_progress(processed: int, total: int) -> None:
                progress.update(task, completed=processed, total=total)

            encrypt_file(
                fingerprint=fingerprint,
                input_file=in_path,
                output_file=out_path,
                password=pwd or None,
                progress_callback=update_progress,
            )

        click.secho(
            f"Successfully encrypted '{in_path.name}' to '{out_path.name}'", fg="green"
        )

    except click.exceptions.Exit:
        raise
    except click.exceptions.Abort:
        raise
    except USBVaultError as e:
        click.secho(f"Encryption failed: {e}", fg="red")
        raise click.exceptions.Exit(1)
    except OSError as e:
        click.secho(f"File system error: {e.strerror}", fg="red")
        raise click.exceptions.Exit(1)
    except Exception as e:
        logger.error("Unexpected CLI encryption failure (%s).", type(e).__name__)
        click.secho("An unexpected error occurred.", fg="red")
        raise click.exceptions.Exit(1)
    finally:
        wipe_secret(pwd)


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
@click.option(
    "--password",
    is_flag=True,
    help="Prompt for an optional passphrase without echoing it.",
)
def decrypt(
    input_file: str,
    output_file: str | None = None,
    password: bool = False,
) -> None:
    """Decrypt a .vault file using a key from the original USB device."""
    pwd = bytearray()
    try:
        in_path = Path(input_file)

        if not _is_file_readable(in_path):
            click.secho(
                f"Error: Input file '{in_path.name}' is currently open or unreadable. "
                "Close it and try again.",
                fg="red",
            )
            raise click.exceptions.Exit(1)

        if output_file is None:
            if in_path.suffix.lower() == ".vault":
                out_path = in_path.with_suffix("")
                if not click.confirm(
                    f"Output file not specified. "
                    f"Do you want to save to '{out_path.name}'?"
                ):
                    click.secho("Operation cancelled.", fg="yellow")
                    raise click.exceptions.Exit(0)
            else:
                click.secho(
                    "Error: Output file not specified and input file does not "
                    "have .vault extension. Cannot determine default output name.",
                    fg="red",
                )
                raise click.exceptions.Exit(1)
        else:
            out_path = Path(output_file)

        if in_path.suffix.lower() != ".vault":
            click.secho(
                "Warning: Input file does not have a .vault extension.", fg="yellow"
            )

        if out_path.exists():
            if not _is_file_writable(out_path):
                click.secho(
                    f"Error: Output file '{out_path.name}' is currently open or unwritable. "
                    "Close it and try again.",
                    fg="red",
                )
                raise click.exceptions.Exit(1)

            if not click.confirm(
                f"Output file '{out_path}' already exists. Do you want to overwrite it?"
            ):
                click.secho("Operation cancelled.", fg="yellow")
                raise click.exceptions.Exit(0)

        fingerprint = _select_usb_device()

        if password:
            raw_password = click.prompt("Passphrase", hide_input=True)
            pwd.extend(raw_password.encode("utf-8"))
            del raw_password

        with Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "•",
            DownloadColumn(),
            "•",
            TimeRemainingColumn(),
        ) as progress:
            task = progress.add_task(
                f"Decrypting {in_path.name}", total=in_path.stat().st_size
            )

            def update_progress(processed: int, total: int) -> None:
                progress.update(task, completed=processed, total=total)

            decrypt_file(
                fingerprint=fingerprint,
                input_file=in_path,
                output_file=out_path,
                password=pwd or None,
                progress_callback=update_progress,
            )

        click.secho(
            f"Successfully decrypted '{in_path.name}' to '{out_path.name}'", fg="green"
        )

    except click.exceptions.Exit:
        raise
    except click.exceptions.Abort:
        raise
    except USBVaultError as e:
        click.secho(f"Decryption failed: {e}", fg="red")
        raise click.exceptions.Exit(1)
    except OSError as e:
        click.secho(f"File system error: {e.strerror}", fg="red")
        raise click.exceptions.Exit(1)
    except Exception as e:
        logger.error("Unexpected CLI decryption failure (%s).", type(e).__name__)
        click.secho("An unexpected error occurred.", fg="red")
        raise click.exceptions.Exit(1)
    finally:
        wipe_secret(pwd)


if __name__ == "__main__":
    cli()
