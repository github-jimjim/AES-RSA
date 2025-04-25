# AES-RSA Folder Encryption Tool

## Overview
This tool provides fast, secure encryption of entire folders using a combination of RSA and AES. It consists of three main components:

- **genkey** – Generates your cryptographic keys.
- **main** – Encrypts your folders using the generated keys.
- **utils** – Provides password and key management utilities.

> The encryption pipeline uses a hybrid scheme: Each file gets a fresh 64-byte master key. The key is encrypted using RSA-OAEP (SHA-256), and then split in half:
> - First 32 bytes: AES-256 in CTR mode.
> - Second 32 bytes: ChaCha20.
> Files are processed in 64 KiB chunks and filenames are encrypted with ChaCha20 + random nonce. Everything runs in parallel using Rayon for high performance.

---

## What's New
This is a complete rewrite in a new language with an entirely new algorithm. Major improvements include:
- Efficient hybrid AES + ChaCha20 encryption
- RSA key support up to 8192 bits
- Parallel file processing using Rayon
- New UI and utility support for password management

---

## Getting Started

### Step 1: Generate Keys (`genkey`)

1. Navigate to the `genkey` folder:
    ```bash
    cd genkey
    cargo run --release
    ```
2. A window will open to guide you through key configuration.
3. Recommended RSA key length: **8192 bits** (secure but still performant).
4. Upon completion, the following files will be created in the `genkey` folder:
    - `priv.key` – your private key
    - `pub.key` – your public key
    - `key_length.txt` – stores the RSA key size

**Important:** Save these files securely.

---

### Step 2: Encrypt Files (`main`)

1. Copy the generated key files (`priv.key`, `pub.key`, and `key_length.txt`) into the `main` folder.
2. Run the encryption tool:
    ```bash
    cd ../main
    cargo run --release
    ```
3. Follow the terminal instructions.
4. After encryption, a `log` file will be generated in the working directory for verification.

> Note: Debug mode may slow down performance.

---

### Step 3: Manage Keys and Passwords (`utils`)

1. Run the Python utility script located in the `utils` folder.
2. Enter your **master password**:
   - If using for the first time, you may enter any password. **Remember it!**
3. The UI offers labeled buttons:
   - **Add Password** – Securely store keys for access.
   - **Recovery** – Recover lost `password.json` from a backup in your system temp directory.

#### Recovery Notes
- If you accidentally delete your password file:
  1. Run the Python script and enter any password.
  2. **DO NOT** add a new password.
  3. Click **Recovery** immediately.
  4. Close the app.
  5. Reopen with your original password to regain access.

> This recovery method is not highly secure – use it only in emergencies.

#### Adding Keys to Storage
Use the utility to store your keys encrypted with your master password:
1. Open the app and enter your password.
2. Click **Add Password**.
3. Enter a name for the key.
4. Choose **From File** and select your `priv.key` or `pub.key`.
5. Complete the process.

This lets you store your keys securely in e.g. Google Drive while keeping them encrypted locally.

---

## Summary
This project combines high-performance parallel encryption with strong security using AES, ChaCha20, and RSA. It includes helpful utilities for managing keys and recovering from mistakes. Remember to safeguard your master password and key files.

Enjoy secure and fast encryption!

