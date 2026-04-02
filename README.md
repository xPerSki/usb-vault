# usb-vault: Hardware-Bound File Encryption

**Protect your files with a hardware-bound key and an optional password factor. `usb-vault` encrypts sensitive documents, photos, and data so access requires your selected USB device, with optional extra user secret.**

---

## For Everyone: Your Personal Digital Safe

### What is `usb-vault`?

Think of it like a physical safe for your digital files. `usb-vault` requires a unique "key" to open your files:

1.  **A Physical Key**: Your specific USB flash drive.

Without the selected USB drive, your files remain encrypted and computationally infeasible without the physical device. For stronger protection, use the optional password factor.

### Why Should I Use It?

*   **Offline-First Security**: Your files are encrypted locally on your computer. No cloud uploads, no accounts, and no telemetry are required by the core tool.
*   **Hardware-Bound Protection**: If someone steals your laptop, they still can't access your vaulted files without your specific USB drive. This adds a powerful layer of physical security.
*   **Simple & Transparent**: The program is designed to be straightforward. Because the code is open-source, its security properties can be independently reviewed.

### How to Use It

You can use the application either by downloading the `usb-vault.exe` standalone executable from the project's releases page, or by installing the Python package directly.

**To install the package via Python (CLI access):**
```sh
# From a local clone of the repository
pip install .
```
This installs the dependencies and makes the `usb-vault` command globally available in your terminal.

#### To Encrypt a File:

1.  Open your terminal or command prompt.
2.  Plug in your chosen USB drive.
3.  Type the following command and press Enter:
    ```sh
    usb-vault encrypt "C:\Users\YourName\Documents\my_secret_plan.txt"
    ```
    Optional second factor:
    ```sh
    usb-vault encrypt "C:\Users\YourName\Documents\my_secret_plan.txt" --password
    ```
    (The program will securely prompt you for the password.)
4.  The program will ask you to select your USB drive from a list.
5.  A new, encrypted file will be created: `my_secret_plan.txt.vault`. You can now safely delete the original.

#### To Decrypt a File:

1.  Open your terminal or command prompt.
2.  Plug in the **same** USB drive you used to encrypt.
3.  Type the following command and press Enter:
    ```sh
    usb-vault decrypt "C:\Users\YourName\Documents\my_secret_plan.txt.vault"
    ```
    If you used an optional password during encryption:
    ```sh
    usb-vault decrypt "C:\Users\YourName\Documents\my_secret_plan.txt.vault" --password
    ```
    (The program will securely prompt you for the password.)
4.  The program will ask you to select the USB drive from a list.
5.  Your original file, `my_secret_plan.txt`, will be restored.

---

## For Developers

`usb-vault` is a Python application built with security and code quality as top priorities.

### Security Principles

*   **Key Derivation**: We use `Argon2id`, the winner of the Password Hashing Competition, to derive the encryption key directly from the unique hardware fingerprint of your chosen USB device.
*   **Encryption**: All files are encrypted using `AES-256` in `GCM` mode, which provides both confidentiality and integrity (protection against tampering).
*   **Hardware Fingerprint + Optional Password**: The `PNPDeviceID` of the USB Mass Storage device is used as a hardware factor. You can additionally provide a password for stronger resistance against spoofing and offline guessing.
*   **Chunked Processing**: Encryption and decryption process files in chunks to improve stability on larger files.

### Architecture

The application is structured into clearly separated modules to ensure maintainability and security:

*   **`cli.py`**: The command-line interface entry point, handling user inputs, prompts, and progress bars.
*   **`gui.py`**: The graphical user interface, built with `customtkinter`, providing an intuitive visual experience.
*   **`crypto.py`**: The core cryptography engine. Handles AES-256-GCM chunked streaming, file I/O, and header verification.
*   **`key_derivation.py`**: Manages the Argon2id key derivation, securely combining the hardware fingerprint, optional password, and random salt.
*   **`usb_detector.py`**: Interfaces with Windows WMI to detect connected USB mass storage devices and extract stable hardware identifiers.

### Known Limitations

*   **Windows-Only**: Currently relies on Windows Management Instrumentation (WMI) infrastructure for USB detection.
*   **Hardware Spoofing**: USB serial numbers and hardware strings can theoretically be read and cloned at the hardware firmware level by a sophisticated attacker. Using the optional password neutralizes this threat.
*   **In-Memory Keys**: The derived symmetric encryption key exists temporarily in RAM during active file processing.

### Security Notes

`usb-vault` is built with care and practical security defaults, but no software can guarantee perfect safety in every environment. Use updated systems, protect physical devices, and prefer USB + password mode for sensitive data.

### Project Setup

1.  **Prerequisites**: Python 3.11+

2.  **Clone the repository**:
    ```sh
    git clone https://github.com/your-username/usb-vault.git
    cd usb-vault
    ```

3.  **Create and activate a virtual environment**:
    ```sh
    python -m venv .venv
    # On Windows
    .venv\Scripts\activate
    # On macOS/Linux
    source .venv/bin/activate
    ```

4.  **Install dependencies**:
    ```sh
    pip install -r requirements.txt
    pip install -e .
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
