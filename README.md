# r-pass 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![PyQt5](https://img.shields.io/badge/UI-PyQt5-green.svg)](https://pypi.org/project/PyQt5/)
[![Security](https://img.shields.io/badge/Crypto-AES--256--GCM-red.svg)]()

> A secure, cross-platform, local password manager built with Python and PyQt5. 

r-pass is designed for users who prefer keeping their credentials offline and under their full control. It uses state-of-the-art cryptographic standards to ensure your vault remains impenetrable.

## Features

- **Modern Dark UI**: Sleek, rounded interface with native macOS styling
- **Offline By Design**: No cloud syncing, no external servers. Your vault stays on your local machine.
- **Modern Cryptography**: 
  - Key Derivation: Argon2id (memory-hard, side-channel resistant)
  - Encryption: AES-256 in GCM mode (Authenticated Encryption) ensures data confidentiality and integrity.
- **Cross-Platform**: Native feel and performance on Windows, macOS, and Linux.
- **Internationalization (i18n)**: Built-in support for English, Turkish, and Russian.
- **Quality of Life**: 
  - Integrated password generator with entropy calculation
  - Adjustable password length (8-128 characters)
  - Character type toggles (uppercase, lowercase, digits, symbols)
  - Automatic clipboard clearing (30 seconds)
  - Auto-lock on inactivity (15 minutes)
  - Secure vault backup and restore mechanism (.r-pass files)

## Tech Stack

- Core: Python 3.9+
- UI Framework: PyQt5
- Database: SQLite3 (Local file storage)
- Cryptography: PyCryptodome (AES-GCM), argon2-cffi (Key Derivation)

## Installation (Source) 🧑‍💻

If you prefer to run the application from source, follow these steps:

1. Clone the repository
`git clone https://github.com/rhymezip/r-passManager.git`
`cd r-passManager`

2. Create and activate a virtual environment
`python3 -m venv venv`
`source venv/bin/activate`  # On Windows use: venv\Scripts\activate

3. Install dependencies
`pip install -r requirements.txt`

4. Run the application
`python r-passManager.py`

## Pre-compiled Executables ⌨

Pre-compiled standalone binaries are available in the Releases section for all major operating systems. You do not need Python installed to run these.

- Windows (.exe): Compiled for standard Windows environments.
- macOS (.app): Compiled for macOS with native dark theme.
- Linux (.AppImage): Built on Arch Linux. 
  - Note: Because it is built on a rolling-release distribution, the AppImage requires relatively recent glibc versions. It may not run out-of-the-box on older LTS distributions (e.g., older Linux Mint or Debian stable releases).

## Usage 🖱

1. **Setup**: On the first launch, create a master password. This password acts as the key to your vault and cannot be recovered if lost.
2. **Adding Entries**: Click the `New` button to store credentials. Use the built-in generator (🔑) for secure passwords.
3. **Password Generator**: Click the key button to generate passwords with adjustable length and character options.
4. **Quick Actions**: Hover over any entry to quickly copy the password or edit the details.
5. **Backup/Restore**: Use the sidebar to securely export your encrypted vault, making it easy to migrate between devices.
6. **Language**: Switch between English, Turkish, and Russian directly from the sidebar.

## Roadmap 📍

- [ ] Native mobile companion apps
- [ ] Browser extension integration via native messaging
- [ ] Support for TOTP (Time-based One-Time Passwords)
- [ ] Hardware security key (YubiKey) support for 2FA unlocking
- [ ] Biometric unlock (Touch ID / Windows Hello)

## License 📜

MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
