<p align="center">
  <img src="src/usb_vault/icons/icon.png" width="150" height="150" alt="USB-Vault Logo">
</p>
<h1 align="center">USB-Vault</h1>
<p align="center">
  <strong>Hardware-Bound File Encryption</strong>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/release/python-3110/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python Version"></a>
  <a href="https://www.gnu.org/licenses/gpl-3.0"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="License: GPL v3"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json" alt="Ruff"></a>
  <a href="https://github.com/pre-commit/pre-commit"><img src="https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit" alt="pre-commit"></a>
  <a href="https://www.microsoft.com/windows/"><img src="https://img.shields.io/badge/OS-Windows-blue?logo=windows&logoColor=white" alt="OS - Windows"></a>
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Encryption-AES--256--GCM-red.svg" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/KDF-Argon2id-orange.svg" alt="Argon2id">
  <img src="https://img.shields.io/badge/Fingerprint-SHA--256-yellow.svg" alt="SHA-256">
</p>

**Protect files with authenticated encryption derived from a selected USB
device fingerprint and, for stronger protection, an optional passphrase.
USB Vault processes files locally and never uploads their contents.**

---

## For Everyone: Your Personal Digital Safe

### What is `usb-vault`?

USB Vault derives an encryption key from:

1. **A USB-bound identifier:** a fingerprint calculated from identifiers
   reported by the selected USB storage device.
2. **An optional passphrase:** a secret known only to you and strongly
   recommended for sensitive files.

The USB fingerprint is an identifier, not a hardware-protected secret.
USB identifiers can potentially be read, copied, or emulated by a capable
attacker. A strong passphrase ensures that possession or reproduction of the
USB identifier alone is insufficient to decrypt the file.

### Why Should I Use It?

* **Offline-First Security**: Encryption and decryption happen locally. The
  application does not upload files, require an account, or send telemetry.
* **USB-Bound Access**: Vault files require the fingerprint of the USB device
  selected during encryption. Adding a passphrase protects against copied or
  spoofed USB identifiers.
* **Authenticated Encryption**: AES-256-GCM detects incorrect keys and
  modification of encrypted data.
* **Simple & Transparent**: The source code is public and can be independently
  reviewed.

### Important Recovery Notice

USB Vault has no recovery service, backdoor, account reset, or master key. If
the required USB fingerprint cannot be reproduced, or you forget the
passphrase, the encrypted data cannot be recovered.

Keep appropriate backups of important original files and protect your
passphrase independently of the USB device. Before deleting an original,
verify that the vault decrypts successfully with the intended USB device and
passphrase.

### How to Use It

You can use the application either by downloading the portable `USB-Vault.exe`
from the [official releases page](https://github.com/xperski/usb-vault/releases),
or by installing the Python package from source.

**Portable desktop application:**

1. Download `USB-Vault.exe` from the official releases page.
2. Optionally verify its SHA-256 fingerprint.
3. Run the executable. USB Vault itself requires no installation. It uses the
   Microsoft Edge WebView2 Runtime, which is included with current Windows
   installations.


In the desktop application:

1. Open the **Encrypt** or **Decrypt** tab.
2. Drop a file into the window or select it using the file picker.
3. Select the required USB storage device.
4. Enter the optional passphrase. The same passphrase must be supplied during
   decryption.
5. Start the operation and wait for it to finish. Do not disconnect the USB
   device or close the application during an active operation.

Encryption creates a new file ending in `.vault`; it does not delete the
original. Decryption restores the original filename when possible and does not
delete the vault.

**To install the package from source (CLI and desktop access):**

```sh
# From a local clone of the repository
pip install .
```
This installs the dependencies and makes the `usb-vault` command globally available in your terminal.

To launch the desktop interface from a source installation:

```sh
usb-vault-webui
```

### Verify a Windows Download

Each release publishes the SHA-256 fingerprint of its final executable. A
matching fingerprint confirms that your downloaded file is byte-for-byte
identical to the published build.

1. Download `USB-Vault.exe`.
2. Open PowerShell in the folder containing the file.
3. Run:

    ```powershell
    Get-FileHash .\USB-Vault.exe -Algorithm SHA256
    ```

4. Compare the complete value in the `Hash` column with the SHA-256 value on
   the corresponding
   [GitHub release](https://github.com/xperski/usb-vault/releases) or the
   official [USB Vault website](https://usbvault.app/changelogs).

Compare all 64 hexadecimal characters; letter casing does not matter
(`A-F` and `a-f` represent the same value). Do not run the file if any
character differs. Delete it and download it again from an official source.

#### To Encrypt a File:

1.  Open your terminal or command prompt.
2.  Plug in your chosen USB drive.
3.  Type the following command and press Enter:
    ```sh
    usb-vault encrypt "C:\Users\YourName\Documents\my_secret_plan.txt"
    ```
    Optional passphrase:
    ```sh
    usb-vault encrypt "C:\Users\YourName\Documents\my_secret_plan.txt" --password
    ```
    (The program will prompt without echoing the passphrase.)
4.  The program will ask you to select your USB drive from a list.
5.  A new encrypted file will be created:
    `my_secret_plan.txt.vault`. Confirm that it can be decrypted and that you
    have an appropriate backup before deleting the original.

#### To Decrypt a File:

1.  Open your terminal or command prompt.
2.  Plug in the **same** USB drive you used to encrypt.
3.  Type the following command and press Enter:
    ```sh
    usb-vault decrypt "C:\Users\YourName\Documents\my_secret_plan.txt.vault"
    ```
    If you used an optional passphrase during encryption:
    ```sh
    usb-vault decrypt "C:\Users\YourName\Documents\my_secret_plan.txt.vault" --password
    ```
    (The program will prompt without echoing the passphrase.)
4.  The program will ask you to select the USB drive from a list.
5.  Your original file, `my_secret_plan.txt`, will be restored.

---

## For Developers

`usb-vault` is a Python application built with security and code quality as top priorities.

### Security Principles

* **Key Derivation**: Argon2id derives a 256-bit key from the USB fingerprint
  and optional passphrase using a unique random salt stored in each vault.
* **Encryption**: Files use AES-256-GCM authenticated encryption. Each chunk
  has a unique nonce and authentication tag; authenticated metadata detects
  altered headers, truncation, and appended data.
* **USB Fingerprint + Optional Passphrase**: The fingerprint is calculated
  from the USB mass-storage device's `PNPDeviceID` and model. It is an
  identifier rather than a secret, so a strong passphrase is recommended.
* **Chunked Processing**: Files are processed with bounded memory and written
  through a temporary file before the completed output is published.
* **Operation Locking**: Destination locks prevent concurrent operations from
  writing to the same output path.

### Architecture

The application is structured into clearly separated modules to ensure maintainability and security:

*   **`cli.py`**: The command-line interface entry point, handling user inputs, prompts, and progress bars.
*   **`crypto.py`**: The core cryptography engine. Handles AES-256-GCM chunked streaming, file I/O, and header verification.
*   **`key_derivation.py`**: Manages Argon2id key derivation, combining the hardware fingerprint, optional passphrase, and random salt.
*   **`usb_detector.py`**: Interfaces with Windows WMI to detect connected USB mass storage devices and extract stable hardware identifiers.
*   **`vault_lock.py`**: Prevents conflicting operations and manages cleanup of interrupted temporary files.

### Known Limitations

* **Windows-Only**: USB detection currently relies on Windows Management
  Instrumentation (WMI).
* **USB Identifiers Are Not Secrets**: Hardware identifiers may be copied or
  emulated. USB-only mode should not be treated as equivalent to a secret
  cryptographic hardware token.
* **No Recovery Mechanism**: Losing access to the required fingerprint or
  passphrase makes decryption impossible.
* **In-Memory Secrets**: Key material and passphrases exist temporarily in
  process memory. Buffers are cleared on a best-effort basis, but Python and
  native dependencies may create copies that cannot be guaranteed erased.

### Security Notes

USB Vault is built with practical security defaults, but no software can
guarantee safety in every environment. Use an updated, trusted computer;
protect the USB device; use a unique, strong passphrase for sensitive data;
maintain tested backups; and obtain builds only from official sources.

### Project Setup

1.  **Prerequisites**: Windows 10/11, Python 3.11+, and the Microsoft Edge
    WebView2 Runtime (included with current Windows installations).

2.  **Clone the repository**:
    ```sh
    git clone https://github.com/xperski/usb-vault.git
    cd usb-vault
    ```

3.  **Create and activate a virtual environment**:
    ```sh
    python -m venv .venv
    .venv\Scripts\activate
    ```

4.  **Install the application and development dependencies**:
    ```sh
    pip install -e ".[dev]"
    ```

5.  **Install pre-commit hooks** (for code linting and formatting):
    ```sh
    pre-commit install
    ```

### Running Tests

To ensure everything is working correctly, run the full test suite:

```sh
pytest
```
