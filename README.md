# File_storage

A CLI file encryption tool with full key lifecycle management and role-based access control (RBAC).

## Features

- **AES-256-GCM encryption/decryption** of files with authenticated encryption
- **Key lifecycle management**: create, rotate, revoke, and expire encryption keys
- **HMAC-SHA256 integrity verification** to detect file tampering before decryption
- **Role-Based Access Control (RBAC)** with users, roles, and fine-grained permissions
- **Password-based authentication** using PBKDF2-SHA256 with 600,000 iterations
- **Audit logging** of all security-relevant operations (JSON-lines format)
- **Atomic file writes** to prevent data corruption on failures

## Requirements

- Python >= 3.10
- cryptography >= 42.0

## Installation

```bash
pip install -e .
```

For development (includes pytest):

```bash
pip install -e ".[dev]"
```

## Quick Start

### Encrypt a file

```bash
file_storage encrypt myfile.txt
```

This creates `myfile.txt.enc` and a new AES-256 key.

### Decrypt a file

```bash
file_storage decrypt myfile.txt.enc
```

### Initialize RBAC (optional)

```bash
file_storage init --admin-user admin --admin-password secret
```

Once initialized, all commands require `--user <username>`:

```bash
file_storage --user admin encrypt myfile.txt
```

## Commands

### File Operations

| Command | Description |
|---------|-------------|
| `encrypt <file> [-o OUTPUT] [--force] [--description DESC]` | Encrypt a file |
| `decrypt <file> [-o OUTPUT] [--force]` | Decrypt an encrypted file |

### Key Management

| Command | Description |
|---------|-------------|
| `keys list [--status active\|expired\|revoked\|all]` | List keys |
| `keys info <key_id>` | Show key details |
| `keys revoke <key_id>` | Revoke a key |
| `keys rotate <key_id>` | Rotate key (re-encrypts associated files) |
| `keys expire <key_id> --at <ISO 8601>` | Set key expiry |

### User Management (requires RBAC init)

| Command | Description |
|---------|-------------|
| `user create <username> --password <pass> --role <role>` | Create user |
| `user list` | List all users |
| `user info <username>` | Show user details |
| `user deactivate <username>` | Deactivate a user |
| `user set-expiry <username> --at <ISO 8601>` | Set access expiry |

### Role Management

| Command | Description |
|---------|-------------|
| `role list` | List all roles |
| `role info <name>` | Show role details and permissions |

### Default Roles

| Role | Description |
|------|-------------|
| `admin` | Full system administrator with all permissions |
| `key_manager` | Can create, rotate, revoke, and manage all keys |
| `encryptor` | Can encrypt files and manage own keys |
| `viewer` | Read-only access to key listings and info |
| `auditor` | Can view all keys and users for audit purposes |

## Global Flags

| Flag | Description |
|------|-------------|
| `--keystore PATH` | Override keystore directory |
| `--datadir PATH` | Override data root directory |
| `--user USERNAME` | RBAC user (or set `FILE_STORAGE_USER` env var) |
| `--quiet`, `-q` | Suppress non-error output |
| `--verbose`, `-v` | Enable verbose output |

## Audit Logging

All operations are logged to `<datadir>/audit/audit.jsonl` as JSON-lines. Each entry includes:

- Event ID and timestamp
- Event type (e.g., `file:encrypt`, `key:revoke`, `user:create`)
- Success/failure status
- Acting user
- Operation-specific details
- Error message on failure

## Project Structure

```
file_storage/
  __init__.py         # Package metadata
  __main__.py         # Entry point for python -m file_storage
  cli.py              # CLI interface and command handlers
  constants.py        # Configuration constants
  crypto.py           # AES-256-GCM encryption primitives
  integrity.py        # HMAC-SHA256 verification
  file_format.py      # Binary file header pack/unpack
  key_manager.py      # Key lifecycle operations
  key_store.py        # Key persistence (JSON files)
  user_store.py       # User persistence with password hashing
  role_store.py       # Role persistence (JSON files)
  access_control.py   # RBAC enforcement engine
  permissions.py      # Permission constants and default roles
  audit.py            # Audit logging
  errors.py           # Custom exception hierarchy
  utils.py            # Utility functions
tests/
  conftest.py         # Shared test fixtures
  test_*.py           # Test modules
```

## Running Tests

```bash
pytest
```

With coverage:

```bash
pytest --cov=file_storage
```