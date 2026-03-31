# usb-vault: Hardware-Bound File Encryption

**Secure your files with a key you can hold in your hand. `usb-vault` locks your sensitive documents, photos, and data, requiring only your specific USB stick to unlock them.**

---

## For Everyone: Your Personal Digital Safe

### What is `usb-vault`?

Think of it like a physical safe for your digital files. `usb-vault` requires a unique "key" to open your files:

1.  **A Physical Key**: Your specific USB flash drive.

Without this exact USB drive, your files remain securely encrypted and unreadable.

### Why Should I Use It?

*   **True Offline Security**: Your files are encrypted on your computer and stay on your computer. No cloud uploads, no accounts, no data collection. Your privacy is absolute.
*   **Hardware-Bound Protection**: If someone steals your laptop, they still can't access your vaulted files without your specific USB drive. This adds a powerful layer of physical security.
*   **Simple & Transparent**: The program is designed to be straightforward. Because the code is open-source, its security can be independently verified by experts around the world.

### How to Use It

*(This assumes you have downloaded the `usb-vault.exe` application from the project's releases page.)*

#### To Encrypt a File:

1.  Open your terminal or command prompt.
2.  Plug in your chosen USB drive.
3.  Type the following command and press Enter:
    ```sh
    usb-vault encrypt "C:\Users\YourName\Documents\my_secret_plan.txt"
    ```
4.  The program will ask you to select your USB drive from a list.
5.  A new, encrypted file will be created: `my_secret_plan.txt.vault`. You can now safely delete the original.

#### To Decrypt a File:

1.  Open your terminal or command prompt.
2.  Plug in the **same** USB drive you used to encrypt.
3.  Type the following command and press Enter:
    ```sh
    usb-vault decrypt "C:\Users\YourName\Documents\my_secret_plan.txt.vault"
    ```
4.  The program will ask you to select the USB drive from a list.
5.  Your original file, `my_secret_plan.txt`, will be restored.

---

## For Developers

`usb-vault` is a Python application built with security and code quality as top priorities.

### Security Principles

*   **Key Derivation**: We use `Argon2id`, the winner of the Password Hashing Competition, to derive the encryption key directly from the unique hardware fingerprint of your chosen USB device.
*   **Encryption**: All files are encrypted using `AES-256` in `GCM` mode, which provides both confidentiality and integrity (protection against tampering).
*   **Hardware Fingerprint**: The unique `PNPDeviceID` of the USB Mass Storage device is used as the sole input for key derivation, physically binding the encryption to that specific device.

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
