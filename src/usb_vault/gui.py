"""GUI module for USB Vault application.

This module provides the graphical user interface for the usb-vault tool
using customtkinter. It handles file selection, USB device interaction,
and threading for cryptographic operations to ensure UI responsiveness.
"""

import os
import sys

# Nuitka standalone path fix for customtkinter assets
if hasattr(sys, "_MEIPASS"):  # PyInstaller compat
    os.environ["CUSTOMTKINTER_DIR"] = sys._MEIPASS

import threading
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk  # type: ignore
from PIL import Image, UnidentifiedImageError

from usb_vault.crypto import (
    decrypt_file,
    encrypt_file,
)
from usb_vault.exceptions import (
    DecryptionError,
    EncryptionError,
    NoUSBDeviceError,
    USBVaultError,
)
from usb_vault.usb_detector import get_device_fingerprint, list_usb_storage_devices

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class USBVaultGUI(ctk.CTk):
    """Main Graphical User Interface class for USB Vault."""

    ACCENT_COLOR = "#5E5CE6"
    ACCENT_HOVER = "#4B49B8"
    TEXT_PRIMARY = "#FFFFFF"
    TEXT_SECONDARY = "#8E8E93"
    PANEL_BG = "#1C1C1E"
    PANEL_HOVER = "#2C2C2E"
    ERROR_COLOR = "#FF453A"
    SUCCESS_COLOR = "#32D74B"
    BORDER_NORMAL = "#38383A"

    FONT_FAMILY = "Segoe UI"

    def __init__(self) -> None:
        """Initialize the main application window, variables, and components."""
        super().__init__()
        self.title("USB-Vault")

        icon_path = Path(__file__).parent / "icons" / "icon.ico"
        if icon_path.exists():
            self.iconbitmap(icon_path)

        self.geometry("750x420")
        self.resizable(False, False)

        self.attributes("-alpha", 0.97)
        self.configure(fg_color="#000000")

        self.file_path: str | None = None
        self.preview_image: ctk.CTkImage | None = None
        self.empty_image = ctk.CTkImage(
            light_image=Image.new("RGBA", (1, 1), (0, 0, 0, 0)), size=(1, 1)
        )

        self.icon_lock: ctk.CTkImage | None = None
        self.icon_lock_open: ctk.CTkImage | None = None
        self.icon_file_lock: ctk.CTkImage | None = None
        self.icon_file: ctk.CTkImage | None = None
        self.icon_shield_check: ctk.CTkImage | None = None
        self.icon_shield_alert: ctk.CTkImage | None = None
        self.icon_usb: ctk.CTkImage | None = None
        self.icon_eye: ctk.CTkImage | None = None
        self.icon_eye_off: ctk.CTkImage | None = None

        self.left_panel: ctk.CTkFrame = None  # type: ignore
        self.title_label: ctk.CTkLabel = None  # type: ignore
        self.subtitle_label: ctk.CTkLabel = None  # type: ignore
        self.mode_var: ctk.StringVar = None  # type: ignore
        self.mode_selector: ctk.CTkSegmentedButton = None  # type: ignore
        self.action_button: ctk.CTkButton = None  # type: ignore
        self.right_panel: ctk.CTkFrame = None  # type: ignore
        self.drop_zone: ctk.CTkButton = None  # type: ignore

        self.load_icons()
        self.setup_ui()

    def load_icons(self) -> None:
        """Load custom icons from the icons folder."""
        icons_dir = Path(__file__).parent / "icons"
        if not icons_dir.exists():
            icons_dir = Path.cwd() / "icons"

        def get_img(name: str, size: tuple[int, int]) -> ctk.CTkImage:
            """Load a single image safely, returning an empty placeholder on failure."""
            path = icons_dir / name
            if path.exists():
                try:
                    return ctk.CTkImage(Image.open(path), size=size)
                except (IOError, UnidentifiedImageError):
                    pass
            return self.empty_image

        self.icon_lock = get_img("lock.png", (20, 20))
        self.icon_lock_open = get_img("lock-open.png", (20, 20))
        self.icon_file_lock = get_img("file-lock.png", (64, 64))
        self.icon_file = get_img("file-text.png", (64, 64))
        self.icon_shield_check = get_img("shield-check.png", (64, 64))
        self.icon_shield_alert = get_img("shield-alert.png", (64, 64))
        self.icon_usb = get_img("usb.png", (48, 48))
        self.icon_eye = get_img("eye.png", (18, 18))
        self.icon_eye_off = get_img("eye-off.png", (18, 18))

    def setup_ui(self) -> None:
        """Configure the layout and inject UI widgets."""
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.left_panel = ctk.CTkFrame(
            self, width=290, corner_radius=0, fg_color="transparent"
        )
        self.left_panel.grid(row=0, column=0, padx=35, pady=45, sticky="nsew")
        self.left_panel.grid_propagate(False)

        self.title_label = ctk.CTkLabel(
            self.left_panel,
            text="USB-Vault",
            font=(self.FONT_FAMILY, 28, "bold"),
            text_color=self.TEXT_PRIMARY,
        )
        self.title_label.pack(anchor="w", pady=(0, 2))

        self.subtitle_label = ctk.CTkLabel(
            self.left_panel,
            text="Hardware-bound encryption",
            font=(self.FONT_FAMILY, 12),
            text_color=self.TEXT_SECONDARY,
        )
        self.subtitle_label.pack(anchor="w", pady=(0, 40))

        self.mode_var = ctk.StringVar(value="Encrypt")
        self.mode_selector = ctk.CTkSegmentedButton(
            self.left_panel,
            values=["Encrypt", "Decrypt"],
            variable=self.mode_var,
            command=self.on_mode_change,
            font=(self.FONT_FAMILY, 13, "bold"),
            fg_color=self.PANEL_BG,
            selected_color="#3A3A3C",
            selected_hover_color="#4A4A4C",
            unselected_color=self.PANEL_BG,
            unselected_hover_color=self.PANEL_HOVER,
            height=38,
            corner_radius=8,
        )
        self.mode_selector.pack(fill="x", pady=(0, 40))

        self.action_button = ctk.CTkButton(
            self.left_panel,
            text="Encrypt",
            image=self.icon_lock,
            font=(self.FONT_FAMILY, 14, "bold"),
            text_color="white",
            fg_color=self.ACCENT_COLOR,
            hover_color=self.ACCENT_HOVER,
            height=48,
            corner_radius=12,
            command=self.execute_crypto,
        )
        self.action_button.pack(fill="x")

        self.right_panel = ctk.CTkFrame(self, corner_radius=20, fg_color="transparent")
        self.right_panel.grid(row=0, column=1, padx=(0, 35), pady=45, sticky="nsew")
        self.right_panel.grid_rowconfigure(0, weight=1)
        self.right_panel.grid_columnconfigure(0, weight=1)

        self.drop_zone = ctk.CTkButton(
            self.right_panel,
            text="\nClick to select a file",
            image=self.empty_image,
            font=(self.FONT_FAMILY, 14),
            text_color=self.TEXT_SECONDARY,
            fg_color=self.PANEL_BG,
            hover_color=self.PANEL_HOVER,
            border_width=2,
            border_color=self.BORDER_NORMAL,
            corner_radius=20,
            command=self.select_file,
            compound="top",
        )
        self.drop_zone.grid(row=0, column=0, sticky="nsew")

    def on_mode_change(self, new_mode: str) -> None:
        """Update button text and icon when operation mode changes."""
        if new_mode == "Encrypt":
            self.action_button.configure(text="Encrypt", image=self.icon_lock)
        else:
            self.action_button.configure(text="Decrypt", image=self.icon_lock_open)

    def reset_drop_zone(self) -> None:
        """Reset the right panel to its default pristine state."""
        self.file_path = None
        self.preview_image = None
        self.drop_zone.configure(
            image=self.empty_image,
            text="\nClick to select a file",
            text_color=self.TEXT_SECONDARY,
            border_color=self.BORDER_NORMAL,
            fg_color=self.PANEL_BG,
        )

    def select_file(self) -> None:
        """Open a file explorer dialog and update UI based on selection."""
        path = filedialog.askopenfilename(title="Select file for USB-Vault")
        if path:
            self.file_path = path
            selected_path = Path(path)
            filename = selected_path.name
            ext = selected_path.suffix.lower()

            self.drop_zone.configure(image=self.empty_image)

            selection_bg = "#222230"

            if ext == ".vault":
                self.drop_zone.configure(
                    image=self.icon_file_lock,
                    text=f"\nSelected Encrypted File:\n{filename}",
                    text_color=self.TEXT_PRIMARY,
                    border_color=self.ACCENT_COLOR,
                    fg_color=selection_bg,
                )
            elif ext in [".png", ".jpg", ".jpeg", ".webp", ".bmp"]:
                try:
                    pil_image = Image.open(path)
                    self.preview_image = ctk.CTkImage(
                        light_image=pil_image, dark_image=pil_image, size=(140, 140)
                    )
                    self.drop_zone.configure(
                        image=self.preview_image,
                        text=f"\nSelected Image:\n{filename}",
                        text_color=self.TEXT_PRIMARY,
                        border_color=self.ACCENT_COLOR,
                        fg_color=selection_bg,
                    )
                except (IOError, UnidentifiedImageError):
                    self._set_standard_file_view(filename, selection_bg)
            else:
                self._set_standard_file_view(filename, selection_bg)
        elif not self.file_path:
            self.reset_drop_zone()

    def _set_standard_file_view(self, filename: str, bg_color: str) -> None:
        """Configure drop zone appearance for generic files."""
        self.drop_zone.configure(
            image=self.icon_file,
            text=f"\nSelected File:\n{filename}",
            text_color=self.TEXT_PRIMARY,
            border_color=self.ACCENT_COLOR,
            fg_color=bg_color,
        )

    def flash_color(self, color: str, step: int = 0) -> None:
        """Animate the drop zone border color without blocking the main loop."""
        max_steps = 5
        if step > max_steps:
            if self.drop_zone.cget("border_color") == color:
                self.drop_zone.configure(border_color=self.BORDER_NORMAL)
            return

        current_color = color if step % 2 == 0 else self.BORDER_NORMAL
        self.drop_zone.configure(border_color=current_color)
        self.after(120, self.flash_color, color, step + 1)

    @staticmethod
    def is_file_readable(filepath: str) -> bool:
        """Verify if the system permits read access to the target file."""
        try:
            with Path(filepath).open("rb"):
                return True
        except OSError:
            return False

    @staticmethod
    def is_file_writable(filepath: str) -> bool:
        """Verify if the system permits write/append access to the target file."""
        if not Path(filepath).exists():
            return True
        try:
            with Path(filepath).open("ab"):
                return True
        except OSError:
            return False

    def execute_crypto(self) -> None:
        """Validate state, paths, and constraints before triggering crypto execution."""
        if not self.file_path:
            self.flash_color(self.ERROR_COLOR)
            self.drop_zone.configure(
                image=self.icon_shield_alert,
                text="\n\nPlease select a file first!",
                text_color=self.ERROR_COLOR,
            )
            return

        if not self.is_file_readable(self.file_path):
            self.flash_color(self.ERROR_COLOR)
            self.drop_zone.configure(
                image=self.icon_shield_alert,
                text="\n\nInput file is currently open.\nClose it and try again.",
                text_color=self.ERROR_COLOR,
            )
            return

        in_path = Path(self.file_path)
        mode = self.mode_var.get()
        if mode == "Encrypt":
            out_path = in_path.with_name(f"{in_path.name}.vault")
        else:
            if in_path.suffix == ".vault":
                out_path = in_path.with_suffix("")
            else:
                out_path = in_path.with_name(f"{in_path.name}.decrypted")

        if out_path.exists():
            replace = messagebox.askyesno(
                "File Already Exists",
                f"The file '{out_path.name}' already exists.\nDo you want to replace it?",
            )
            if not replace:
                return

            if not self.is_file_writable(str(out_path)):
                self.flash_color(self.ERROR_COLOR)
                self.drop_zone.configure(
                    image=self.icon_shield_alert,
                    text="\n\nCannot replace file.\nIt is currently opened by another program.",
                    text_color=self.ERROR_COLOR,
                )
                return

        confirmed, password = self._prompt_optional_password()
        if not confirmed:
            return

        if password and mode == "Encrypt":
            confirmed_pass, confirmation_str = self._prompt_password(
                title="Confirm Password", subtitle="", button_label="Confirm"
            )
            if not confirmed_pass:
                return
            if password != confirmation_str:
                self.flash_color(self.ERROR_COLOR)
                self.drop_zone.configure(
                    image=self.icon_shield_alert,
                    text="\nCrypto Error:\nPasswords do not match.\n\n(Click to select another file)",
                    text_color=self.ERROR_COLOR,
                )
                self.reset_drop_zone_delayed(3000)
                return

        self.select_usb_device_dialog(out_path, password)

    def reset_drop_zone_delayed(self, ms: int) -> None:
        """Schedule a reset of the drop zone after a specific delay in milliseconds."""
        self.after(ms, self.reset_drop_zone)  # type: ignore

    def _prompt_optional_password(self) -> tuple[bool, str | None]:
        """Convenience wrapper for the optional password dialog."""
        return self._prompt_password(
            title="Optional Password",
            subtitle="Leave empty if none",
            button_label="Continue",
        )

    def _prompt_password(
        self, title: str, subtitle: str, button_label: str
    ) -> tuple[bool, str | None]:
        """Show a styled modal to capture password input.

        Returns:
            tuple[bool, str | None]: (confirmed, password). Password is None when
            the user confirms an empty field.
        """
        dialog = ctk.CTkToplevel(self)
        dialog.title(title)

        dialog_height = 220 if subtitle else 200
        dialog.geometry(f"430x{dialog_height}")
        dialog.resizable(False, False)
        dialog.configure(fg_color=self.PANEL_BG)
        dialog.transient(self)

        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 430) // 2
        y = self.winfo_y() + (self.winfo_height() - dialog_height) // 2
        dialog.geometry(f"430x{dialog_height}+{x}+{y}")

        dialog.grab_set()

        ctk.CTkLabel(
            dialog,
            text=title,
            font=(self.FONT_FAMILY, 18, "bold"),
            text_color=self.TEXT_PRIMARY,
        ).pack(pady=(22, 6 if subtitle else 14))

        if subtitle:
            ctk.CTkLabel(
                dialog,
                text=subtitle,
                font=(self.FONT_FAMILY, 12),
                text_color=self.TEXT_SECONDARY,
            ).pack(pady=(0, 14))

        password_row = ctk.CTkFrame(dialog, fg_color="transparent")
        password_row.pack()

        password_entry = ctk.CTkEntry(
            password_row,
            width=280,
            height=38,
            show="*",
            fg_color="#2C2C2E",
            border_color=self.BORDER_NORMAL,
            text_color=self.TEXT_PRIMARY,
        )
        password_entry.pack(side="left", padx=(0, 8))

        is_password_visible = {"value": False}

        def _toggle_visibility() -> None:
            is_password_visible["value"] = not is_password_visible["value"]
            show_char = "" if is_password_visible["value"] else "*"
            toggle_icon = (
                self.icon_eye if is_password_visible["value"] else self.icon_eye_off
            )
            password_entry.configure(show=show_char)
            toggle_btn.configure(image=toggle_icon)

        toggle_btn = ctk.CTkButton(
            password_row,
            text="",
            width=38,
            height=38,
            image=self.icon_eye_off,
            fg_color="#2C2E2E",
            hover_color="#3A3A3C",
            command=_toggle_visibility,
        )
        toggle_btn.pack(side="left")

        password_entry.focus()

        result: dict[str, bool | str | None] = {"confirmed": False, "password": None}

        def on_confirm() -> None:
            """Capture the entry value and close the dialog."""
            raw_password = password_entry.get()
            result["password"] = raw_password if raw_password else None
            result["confirmed"] = True
            dialog.destroy()

        def on_cancel() -> None:
            """Close the dialog without saving the password."""
            dialog.destroy()

        password_entry.bind("<Return>", on_confirm)

        buttons = ctk.CTkFrame(dialog, fg_color="transparent")
        buttons.pack(pady=(16 if subtitle else 20, 0))

        ctk.CTkButton(
            buttons,
            text="Cancel",
            width=110,
            fg_color="#2C2E2E",
            hover_color="#3A3A3C",
            command=on_cancel,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            buttons,
            text=button_label,
            width=130,
            fg_color=self.ACCENT_COLOR,
            hover_color=self.ACCENT_HOVER,
            command=on_confirm,
        ).pack(side="left", padx=8)

        dialog.protocol("WM_DELETE_WINDOW", on_cancel)
        dialog.wait_window()
        confirmed = bool(result["confirmed"])
        password = result["password"]
        if isinstance(password, str) or password is None:
            return confirmed, password
        return confirmed, None

    def select_usb_device_dialog(self, out_path: Path, password: str | None) -> None:
        """Display a modal for selecting the physical USB key with refresh capabilities."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Select USB Key")
        dialog.geometry("450x260")
        dialog.resizable(False, False)
        dialog.configure(fg_color=self.PANEL_BG)
        dialog.transient(self)
        dialog.grab_set()

        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 450) // 2
        y = self.winfo_y() + (self.winfo_height() - 260) // 2
        dialog.geometry(f"+{x}+{y}")

        icon_label = ctk.CTkLabel(dialog, text="", image=self.icon_usb)
        icon_label.pack(pady=(15, 5))

        title_label = ctk.CTkLabel(
            dialog,
            text="Select your hardware key:",
            font=(self.FONT_FAMILY, 15, "bold"),
        )
        title_label.pack()

        dropdown_var = ctk.StringVar(value="")
        dropdown = ctk.CTkOptionMenu(
            dialog,
            values=["Scanning devices..."],
            variable=dropdown_var,
            width=350,
            font=(self.FONT_FAMILY, 13),
            fg_color="#2C2E2E",
            button_color="#3A3A3C",
            button_hover_color="#4A4A4C",
            dropdown_fg_color="#2C2C2E",
        )
        dropdown.pack(pady=10)

        buttons_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        buttons_frame.pack(pady=(10, 0))

        current_devices = []

        def on_refresh() -> None:
            """Re-scan for USB devices and update the dialog state."""
            nonlocal current_devices

            dropdown.configure(values=["Scanning devices..."], state="disabled")
            dropdown_var.set("Scanning devices...")
            confirm_btn.configure(state="disabled", fg_color="#4A4A4C")
            dialog.update()

            try:
                current_devices = list_usb_storage_devices()
                if not current_devices:
                    raise NoUSBDeviceError("No USB devices detected.")

                device_options = [
                    f"{d.get('FriendlyName', 'Unknown')} (Serial: {d.get('SerialNumber', 'No Serial')})"
                    for d in current_devices
                ]
                dropdown.configure(values=device_options, state="normal")
                dropdown_var.set(device_options[0])
                confirm_btn.configure(state="normal", fg_color=self.ACCENT_COLOR)

            except (NoUSBDeviceError, USBVaultError):
                current_devices = []
                dropdown.configure(values=["No devices detected"], state="disabled")
                dropdown_var.set("No devices detected")
                confirm_btn.configure(state="disabled", fg_color="#38383A")

        refresh_btn = ctk.CTkButton(
            buttons_frame,
            text="Refresh",
            command=on_refresh,
            font=(self.FONT_FAMILY, 13),
            fg_color="#2C2E2E",
            hover_color="#3A3A3C",
            width=100,
            height=35,
        )
        refresh_btn.pack(side="left", padx=10)

        def on_confirm() -> None:
            """Process selection and dispatch worker thread upon modal confirmation."""
            if not current_devices:
                return

            selected_str = dropdown_var.get()
            try:
                device_options = [
                    f"{d.get('FriendlyName', 'Unknown')} (Serial: {d.get('SerialNumber', 'No Serial')})"
                    for d in current_devices
                ]
                idx = device_options.index(selected_str)
                selected_device = current_devices[idx]
                fingerprint = get_device_fingerprint(selected_device)
                dialog.destroy()
                self.start_crypto_thread(fingerprint, out_path, password)
            except ValueError:
                pass

        confirm_btn = ctk.CTkButton(
            buttons_frame,
            text="Confirm",
            command=on_confirm,
            font=(self.FONT_FAMILY, 14, "bold"),
            fg_color=self.ACCENT_COLOR,
            hover_color=self.ACCENT_HOVER,
            width=150,
            height=35,
        )
        confirm_btn.pack(side="left", padx=10)
        on_refresh()

    def start_crypto_thread(
        self,
        fingerprint: str,
        out_path: Path,
        password: str | None,
    ) -> None:
        """Update UI to processing state and spawn a background crypto thread."""
        mode = self.mode_var.get()
        self.action_button.configure(
            state="disabled", text="PROCESSING...", image=self.empty_image
        )

        waiting_icon = self.icon_lock if mode == "Encrypt" else self.icon_lock_open
        self.drop_zone.configure(
            image=waiting_icon,
            text=f"\n\n{mode}ing...\nPlease wait.",
            text_color=self.TEXT_PRIMARY,
            border_color=self.ACCENT_COLOR,
        )

        thread = threading.Thread(
            target=self._run_crypto_task,
            args=(mode, fingerprint, self.file_path, out_path, password),
        )
        thread.start()

    def _run_crypto_task(
        self,
        mode: str,
        fingerprint: str,
        filepath: str,
        out_path: Path,
        password: str | None,
    ) -> None:
        """Execute heavy encryption/decryption synchronously in a worker thread."""
        in_path = Path(filepath)
        try:
            if mode == "Encrypt":
                encrypt_file(fingerprint, in_path, out_path, password=password)
                success_msg = f"Successfully encrypted to:\n{out_path.name}"
            else:
                decrypt_file(fingerprint, in_path, out_path, password=password)
                success_msg = f"Successfully decrypted to:\n{out_path.name}"

            self.after(0, self._crypto_success, success_msg)

        except (EncryptionError, DecryptionError) as e:
            self.after(0, self._crypto_error, str(e))
        except (IOError, OSError) as e:
            self.after(0, self._crypto_error, f"File system error: {e.strerror}")
        except Exception as e:
            self.after(
                0,
                self._crypto_error,
                f"An unexpected error occurred: {type(e).__name__}",
            )

    def _crypto_success(self, message: str) -> None:
        """Handle UI callback to represent a successful operation."""
        self.action_button.configure(state="normal")
        self.on_mode_change(self.mode_var.get())

        self.file_path = None
        self.preview_image = None

        self.drop_zone.configure(
            image=self.icon_shield_check,
            text=f"\n{message}\n\n(Click to select another file)",
            text_color=self.SUCCESS_COLOR,
            border_color=self.SUCCESS_COLOR,
            fg_color=self.PANEL_BG,
        )

    def _crypto_error(self, error_msg: str) -> None:
        """Handle UI callback to represent a failed operation."""
        self.action_button.configure(state="normal")
        self.on_mode_change(self.mode_var.get())
        self.flash_color(self.ERROR_COLOR)

        self.drop_zone.configure(
            image=self.icon_shield_alert,
            text=f"\nCrypto Error:\n{error_msg}\n\n(Click to select another file)",
            text_color=self.ERROR_COLOR,
            fg_color=self.PANEL_BG,
        )


if __name__ == "__main__":
    app = USBVaultGUI()
    app.mainloop()
