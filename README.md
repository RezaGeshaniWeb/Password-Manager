# Password Manager CLI

A production-quality, secure command-line Password Manager built with **JavaScript** and **Node.js**. It stores credentials locally, encrypts sensitive fields, and protects access with a master password.

> **Origin:** This project was generated and implemented from the specifications in [`Prompt.txt`](./Prompt.txt). That file defines the full requirements, architecture, security rules, and CLI behavior used to build the application.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Requirements](#requirements)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [CLI Menu](#cli-menu)
- [Project Structure](#project-structure)
- [Architecture](#architecture)
- [Security](#security)
- [Data Storage](#data-storage)
- [Password Rules](#password-rules)
- [Error Handling](#error-handling)
- [Notes](#notes)

---

## Overview

This application runs entirely in the terminal. On first launch, you create a master password. On later launches, you authenticate with that password (maximum 3 attempts). After login, you can manage an encrypted credential vault: add, view, search, update, delete, generate passwords, and export data.

No third-party packages are used. Everything relies on Node.js built-in modules.

---

## Features

| Feature | Description |
| --- | --- |
| Master Password | Create, hash, and verify a master password; never stored in plain text |
| Login Protection | Up to 3 failed attempts; access denied after lockout |
| Credential Vault | Add, edit, delete, list, and search stored accounts |
| Encryption | AES-256-GCM for usernames, passwords, and notes |
| Password Generator | Cryptographically secure passwords with customizable options |
| Local Persistence | Automatic load/save between sessions |
| Export | Export vault data as JSON after master password verification |
| Session Timeout | Idle sessions expire and require re-authentication |
| Hidden Input | Master/password prompts do not echo characters |

### Credential Record Shape

Each stored credential includes:

- `id`
- `website`
- `username` *(encrypted at rest)*
- `password` *(encrypted at rest)*
- `notes` *(encrypted at rest)*
- `created_at`
- `updated_at`

---

## Tech Stack

- **Language:** JavaScript (ES2022+)
- **Runtime:** Node.js 20+
- **Modules used:** `fs`, `path`, `crypto`, `readline`, `os`, `process`, `util`
- **Dependencies:** none (no npm packages beyond Node itself)
- **Design:** Object-oriented ES6 classes with JSDoc

---

## Requirements

- [Node.js](https://nodejs.org/) **v20 or newer**
- A terminal that supports TTY input (for hidden password entry)

Check your Node version:

```bash
node -v
```

---

## Getting Started

1. Clone or open this repository.
2. Open a terminal in the project root (the same folder as `Prompt.txt` and `main.js`).
3. Start the application:

```bash
npm start
```

Or run directly:

```bash
node main.js
```

There is no `npm install` step because the project uses only built-in Node.js modules.

---

## Usage

### First Launch

1. The app asks you to create a **Master Password**.
2. Confirm the password.
3. Strength rules are validated before it is saved.
4. Only a salted hash is stored (never the plain password).

### Later Launches

1. Enter your Master Password.
2. You get up to **3 attempts**.
3. On success, the main menu appears.
4. On repeated failure, access is denied and the app exits.

### Typical Workflow

1. Add credentials (website, username, password, optional notes).
2. Optionally generate a strong password instead of typing one.
3. View or search accounts.
4. Update or delete entries as needed.
5. Export the vault when you need a JSON backup (master password required again).

---

## CLI Menu

```
1. Add Credential
2. View Credentials
3. Search Credential
4. Update Credential
5. Delete Credential
6. Generate Password
7. Export Vault
8. Exit
```

### Password Generator Options

When generating a password, you can choose:

- Length
- Include uppercase letters
- Include numbers
- Include symbols

Generation uses `crypto.randomInt` / cryptographically secure randomness.

---

## Project Structure

```
.
├── Prompt.txt              # Original build specification for this project
├── README.md               # This file
├── package.json            # Project metadata and start script
├── main.js                 # CLI entry point and user interface
├── masterPassword.js       # Master password hashing and verification
├── encryptionManager.js    # AES-256-GCM key handling, encrypt/decrypt
├── vaultManager.js         # Credential CRUD, search, persistence, export
├── passwordGenerator.js    # Secure password generation
├── credential.js           # Credential data model
└── storage/
    ├── master.json         # Salted master password hash (created at runtime)
    ├── vault.json          # Encrypted credential vault (created at runtime)
    └── key.key             # Encryption key file (created at runtime)
```

The `storage/` directory is created/used automatically. Sensitive files appear after the first successful setup and use.

---

## Architecture

The application follows a modular OOP design with clear separation of concerns:

| Class | File | Responsibilities |
| --- | --- | --- |
| `CLI` | `main.js` | Menus, prompts, session flow, user interaction |
| `MasterPasswordManager` | `masterPassword.js` | Create/verify master password, hashing, attempt tracking |
| `EncryptionManager` | `encryptionManager.js` | Generate/load keys, encrypt, decrypt |
| `VaultManager` | `vaultManager.js` | Add/update/delete/search credentials, save/load/export |
| `PasswordGenerator` | `passwordGenerator.js` | Generate secure passwords |
| `Credential` | `credential.js` | Represent a single credential record |

### High-Level Flow

```text
Start
  └─ Master password setup or login
       └─ Load encryption key + vault
            └─ Main menu loop
                 ├─ Credential operations
                 ├─ Password generator
                 ├─ Export (re-verify master password)
                 └─ Exit / session timeout → re-login
```

---

## Security

Security practices implemented in this project:

- **Master password hashing** with `crypto.scrypt` and a random salt
- **AES-256-GCM** encryption for sensitive vault fields
- **Secure key file** (`key.key`) generated with `crypto.randomBytes`
- **Hidden password input** (no character echo)
- **Login attempt limiting** (3 attempts)
- **Session timeout** after idle inactivity (re-authentication required)
- **Timing-safe password comparison** where applicable
- **Input validation** for empty/invalid fields and weak master passwords
- Sensitive values are not printed unnecessarily (passwords are revealed only on explicit request)

### What Is Encrypted

- Usernames
- Passwords
- Notes

Website values remain searchable in the vault listing/search flow; encrypted fields are decrypted in memory only after successful authentication.

---

## Data Storage

All data is stored locally under `storage/`:

| File | Purpose |
| --- | --- |
| `master.json` | Salt + password hash for the master password |
| `vault.json` | Credential records with encrypted sensitive fields |
| `key.key` | 256-bit encryption key used by AES-GCM |

Behavior:

- Automatic save after vault changes
- Automatic load on successful login
- Corruption / missing-file detection with clear error messages

### Export

- Format: **JSON**
- Requires master password verification before export
- Export files are written under `storage/` by default (or an absolute path you provide)

---

## Password Rules

The master password must satisfy all of the following:

- Minimum **12** characters
- At least one **uppercase** letter
- At least one **lowercase** letter
- At least one **number**
- At least one **special** character

---

## Error Handling

The application is designed not to crash on common failures. It handles:

- Missing storage files
- Corrupted JSON / key / vault data
- Invalid menu or field input
- Wrong master passwords
- Empty required fields

Errors are reported with clear messages, and the CLI continues when recovery is possible.

---

## Notes

- This is a **local offline** password manager. Protect your machine and the `storage/` folder.
- Losing the master password or deleting `key.key` can make vault data unrecoverable.
- Keep backups of exported JSON in a safe place.
- The authoritative product specification lives in [`Prompt.txt`](./Prompt.txt); this README documents the implemented result of that prompt.

---

## Quick Reference

```bash
# Run the app
npm start

# Or
node main.js
```

**Node.js:** 20+  
**Built from:** [`Prompt.txt`](./Prompt.txt)  
**Third-party packages:** none
