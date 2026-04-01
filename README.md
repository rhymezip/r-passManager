# r-pass 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![PyQt5](https://img.shields.io/badge/UI-PyQt5-green.svg)](https://pypi.org/project/PyQt5/)
[![Security](https://img.shields.io/badge/Crypto-AES--256--GCM-red.svg)]()

> A secure, cross-platform, local password manager built with Python and PyQt5.

r-pass is designed for users who prefer keeping their credentials offline and under their full control. It uses state-of-the-art cryptographic standards to ensure your vault remains impenetrable.

## Features

- **Offline Storage**: All data stored locally in SQLite database
- **Modern Cryptography**:
  - Key Derivation: Argon2id (memory-hard, side-channel resistant)
  - Encryption: AES-256-GCM (Authenticated Encryption)
- **Modern Dark UI**: Sleek interface with rounded corners, card-based entry display
- **Password Generator**: Adjustable length (8-128), character type toggles, entropy calculation
- **Security Features**:
  - Auto-lock on inactivity (15 minutes)
  - Automatic clipboard clearing (30 seconds)
- **Backup/Restore**: Export encrypted vault to .r-pass files
- **Multi-language**: English, Turkish, Russian
- **Cross-Platform**: Native look on macOS, Linux, and Windows

## Tech Stack

- **Core**: Python 3.9+
- **UI Framework**: PyQt5
- **Database**: SQLite3
- **Cryptography**: PyCryptodome (AES-GCM), argon2-cffi (Argon2id)

## Installation (Source)

```bash
git clone https://github.com/rhymezip/r-passManager.git
cd r-passManager
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate    # Windows
pip install -r requirements.txt
python r-passManager.py
```

## Pre-compiled Executables

Pre-compiled binaries available in Releases:

- **macOS (.dmg)**: Compatible with Intel and Apple Silicon
- **Linux (.AppImage)**: Requires recent glibc
- **Windows (.exe)**: Standard installation

## Requirements

- Python 3.9+
- PyQt5
- pycryptodome
- argon2-cffi
- pyperclip (optional, for clipboard)

## Usage

1. **First Launch**: Create a master password to secure your vault
2. **Add Entry**: Click "New" to add credentials with name, URL, username, password, notes
3. **Generate Password**: Click the key icon (🔑) to generate secure passwords
4. **Quick Copy**: Hover over entries to copy username or password
5. **Backup**: Export your vault from the sidebar
6. **Language**: Switch languages directly from the sidebar

## Security

- Master password never stored, only derived key
- All entries encrypted with AES-256-GCM
- Key derived using Argon2id (64MB memory, 3 iterations)
- Clipboard auto-clears after 30 seconds
- Auto-locks after 15 minutes of inactivity

## License

MIT License - See LICENSE file
