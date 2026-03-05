"""CLI interface for file_storage encryption tool."""

from __future__ import annotations

import argparse
import functools
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Callable

from file_storage.access_control import AccessController
from file_storage.audit import AuditLogger
from file_storage.constants import (
    DEFAULT_DATA_DIR,
    ENC_EXTENSION,
    ENV_CURRENT_USER,
    ENV_DATA_DIR,
    ENV_KEYSTORE_DIR,
    HMAC_SIZE,
)
from file_storage.crypto import (
    decrypt as aes_decrypt,
    derive_hmac_key,
    encrypt as aes_encrypt,
    generate_nonce,
)
from file_storage.errors import (
    FileStorageError,
    IntegrityError,
)
from file_storage.file_format import FileHeader, pack_header, unpack_header
from file_storage.integrity import compute_hmac, verify_hmac
from file_storage.key_manager import KeyManager
from file_storage.key_store import KeyStore
from file_storage.role_store import RoleStore
from file_storage.user_store import UserRecord, UserStore
from file_storage.utils import parse_datetime


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _get_data_dir(args: argparse.Namespace) -> Path:
    """Resolve the data root directory."""
    if hasattr(args, "datadir") and args.datadir:
        return Path(args.datadir)
    env_dir = os.environ.get(ENV_DATA_DIR)
    if env_dir:
        return Path(env_dir)
    return Path(DEFAULT_DATA_DIR)


def _get_keystore_dir(args: argparse.Namespace) -> Path:
    """Resolve the keystore directory from args, env, or default."""
    if hasattr(args, "keystore") and args.keystore:
        return Path(args.keystore)
    env_dir = os.environ.get(ENV_KEYSTORE_DIR)
    if env_dir:
        return Path(env_dir)
    return _get_data_dir(args) / "keys"


def _get_key_manager(args: argparse.Namespace) -> KeyManager:
    """Create a KeyManager from the resolved keystore directory."""
    store = KeyStore(_get_keystore_dir(args))
    return KeyManager(store)


def _get_access_controller(args: argparse.Namespace) -> AccessController:
    """Create an AccessController from resolved directories."""
    data_dir = _get_data_dir(args)
    user_store = UserStore(data_dir / "users")
    role_store = RoleStore(data_dir / "roles")
    return AccessController(user_store, role_store)


def _get_audit_logger(args: argparse.Namespace) -> AuditLogger:
    """Create an AuditLogger from the resolved data directory."""
    data_dir = _get_data_dir(args)
    return AuditLogger(data_dir / "audit")


def _resolve_current_user(
    args: argparse.Namespace, ac: AccessController
) -> UserRecord:
    """Resolve and validate the current user from --user flag or env var."""
    username = getattr(args, "user", None) or os.environ.get(ENV_CURRENT_USER)
    if not username:
        _print_error("--user is required (or set FILE_STORAGE_USER)")
        raise SystemExit(1)
    return ac.resolve_user(username)


def _print_error(msg: str) -> None:
    print(f"Error: {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Error handling decorator
# ---------------------------------------------------------------------------

def handle_errors(
    audit_event_type: str | None = None,
) -> Callable:
    """Decorator that handles exceptions and optional audit logging for CLI commands.

    Catches FileStorageError, OSError, SystemExit, and ValueError, printing
    appropriate error messages and returning exit code 1 on failure.
    When audit_event_type is provided, logs success/failure audit events.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(args: argparse.Namespace) -> int:
            audit = _get_audit_logger(args) if audit_event_type else None
            username = getattr(args, "user", None) or os.environ.get(ENV_CURRENT_USER)
            try:
                result = func(args)
                if audit and audit_event_type:
                    audit.log(
                        event_type=audit_event_type,
                        success=True,
                        username=username,
                        detail=_extract_audit_detail(args, audit_event_type),
                    )
                return result
            except SystemExit:
                if audit and audit_event_type:
                    audit.log(
                        event_type=audit_event_type,
                        success=False,
                        username=username,
                        error="operation aborted",
                    )
                return 1
            except ValueError as e:
                _print_error(str(e))
                if audit and audit_event_type:
                    audit.log(
                        event_type=audit_event_type,
                        success=False,
                        username=username,
                        error=str(e),
                    )
                return 1
            except FileStorageError as e:
                _print_error(str(e))
                if audit and audit_event_type:
                    audit.log(
                        event_type=audit_event_type,
                        success=False,
                        username=username,
                        error=str(e),
                    )
                return 1
            except OSError as e:
                _print_error(f"file operation failed: {e}")
                if audit and audit_event_type:
                    audit.log(
                        event_type=audit_event_type,
                        success=False,
                        username=username,
                        error=f"file operation failed: {e}",
                    )
                return 1
        return wrapper
    return decorator


def _extract_audit_detail(args: argparse.Namespace, event_type: str) -> dict:
    """Extract relevant details from args for audit logging."""
    detail: dict = {}
    if hasattr(args, "file") and args.file:
        detail["file"] = args.file
    if hasattr(args, "key_id") and args.key_id:
        detail["key_id"] = args.key_id
    if hasattr(args, "username") and args.username and event_type.startswith("user:"):
        detail["target_username"] = args.username
    if hasattr(args, "name") and args.name:
        detail["role_name"] = args.name
    if hasattr(args, "output") and args.output:
        detail["output"] = args.output
    return detail


# ---------------------------------------------------------------------------
# Encrypt / Decrypt commands
# ---------------------------------------------------------------------------

@handle_errors(audit_event_type="file:encrypt")
def cmd_encrypt(args: argparse.Namespace) -> int:
    """Encrypt a file."""
    input_path = Path(args.file)

    if not input_path.exists():
        _print_error(f"file not found: {input_path}")
        return 1
    if not input_path.is_file():
        _print_error(f"not a regular file: {input_path}")
        return 1
    if not os.access(input_path, os.R_OK):
        _print_error(f"permission denied: {input_path}")
        return 1

    output_path = Path(args.output) if args.output else Path(str(input_path) + ENC_EXTENSION)

    if output_path.exists() and not args.force:
        _print_error(f"output file exists: {output_path}. Use --force to overwrite.")
        return 1

    # RBAC enforcement
    ac = _get_access_controller(args)
    owner_id = None
    if ac.is_initialized():
        user = _resolve_current_user(args, ac)
        ac.check_permission(user, "file:encrypt")
        owner_id = user.user_id

    km = _get_key_manager(args)
    record = km.create_key(description=args.description or "", owner_id=owner_id)

    plaintext = input_path.read_bytes()
    nonce = generate_nonce()

    header = FileHeader(
        key_id=uuid.UUID(record.key_id),
        key_version=record.version,
        nonce=nonce,
        original_filename=input_path.name,
    )
    header_bytes = pack_header(header)

    key = km.get_key_material(record)
    ciphertext_tag = aes_encrypt(key, nonce, plaintext, aad=header_bytes)

    hmac_key = derive_hmac_key(key)
    file_content = header_bytes + ciphertext_tag
    hmac_digest = compute_hmac(hmac_key, file_content)

    # Atomic write
    fd, tmp_path = tempfile.mkstemp(
        dir=str(output_path.parent), suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(file_content + hmac_digest)
        os.replace(tmp_path, str(output_path))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    km.add_file_association(record.key_id, str(output_path))

    if not args.quiet:
        print(f"Encrypted: {input_path} -> {output_path}")
        print(f"Key ID: {record.key_id}")

    return 0


@handle_errors(audit_event_type="file:decrypt")
def cmd_decrypt(args: argparse.Namespace) -> int:
    """Decrypt a file."""
    input_path = Path(args.file)

    if not input_path.exists():
        _print_error(f"file not found: {input_path}")
        return 1
    if not os.access(input_path, os.R_OK):
        _print_error(f"permission denied: {input_path}")
        return 1

    data = input_path.read_bytes()

    if len(data) < HMAC_SIZE:
        _print_error("file too small to be a valid encrypted file")
        return 1

    # Split HMAC from file content
    file_data = data[:-HMAC_SIZE]
    stored_hmac = data[-HMAC_SIZE:]

    # Parse header
    header, offset = unpack_header(file_data)
    header_bytes = file_data[:offset]
    ciphertext_tag = file_data[offset:]

    # Load key and validate
    km = _get_key_manager(args)
    record = km.get_key(str(header.key_id))

    # RBAC enforcement
    ac = _get_access_controller(args)
    if ac.is_initialized():
        user = _resolve_current_user(args, ac)
        ac.check_key_access(user, "file:decrypt", "file:decrypt_any", record.owner_id)

    km.validate_key_for_use(record)

    # Get key material for the file's key version
    key = km.get_key_material_for_version(record, header.key_version)

    # Verify HMAC (pre-decryption integrity check)
    hmac_key = derive_hmac_key(key)
    if not verify_hmac(hmac_key, file_data, stored_hmac):
        raise IntegrityError(
            "File integrity check failed. The file may have been tampered with."
        )

    # Decrypt
    plaintext = aes_decrypt(key, header.nonce, ciphertext_tag, aad=header_bytes)

    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.parent / header.original_filename

    if output_path.exists() and not args.force:
        _print_error(
            f"output file exists: {output_path}. Use --force to overwrite."
        )
        return 1

    # Atomic write
    fd, tmp_path = tempfile.mkstemp(
        dir=str(output_path.parent), suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(plaintext)
        os.replace(tmp_path, str(output_path))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    if not args.quiet:
        print(f"Decrypted: {input_path} -> {output_path}")

    return 0


# ---------------------------------------------------------------------------
# Key management commands
# ---------------------------------------------------------------------------

@handle_errors(audit_event_type="key:list")
def cmd_keys_list(args: argparse.Namespace) -> int:
    """List all keys."""
    km = _get_key_manager(args)
    records = km.list_keys()

    # RBAC: filter by ownership
    ac = _get_access_controller(args)
    if ac.is_initialized():
        user = _resolve_current_user(args, ac)
        ac.check_permission(user, "key:list")
        if not ac.has_permission(user, "key:info_any"):
            records = [r for r in records if r.owner_id == user.user_id]

    if args.status != "all":
        records = [r for r in records if km.get_key_status(r) == args.status]

    if not records:
        if not args.quiet:
            print("No keys found.")
        return 0

    # Table output
    print(
        f"{'KEY ID':<38} {'VER':>3} {'STATUS':<8} {'CREATED':<26} {'EXPIRES':<26}"
    )
    print("-" * 103)
    for r in records:
        status = km.get_key_status(r)
        expires = r.expires_at or "never"
        print(
            f"{r.key_id:<38} {r.version:>3} {status:<8} {r.created_at:<26} {expires:<26}"
        )

    return 0


@handle_errors(audit_event_type="key:info")
def cmd_keys_info(args: argparse.Namespace) -> int:
    """Show details for a specific key."""
    km = _get_key_manager(args)
    record = km.get_key(args.key_id)

    # RBAC enforcement
    ac = _get_access_controller(args)
    if ac.is_initialized():
        user = _resolve_current_user(args, ac)
        ac.check_key_access(user, "key:info", "key:info_any", record.owner_id)

    status = km.get_key_status(record)

    print(f"Key ID:       {record.key_id}")
    print(f"Version:      {record.version}")
    print(f"Status:       {status}")
    print(f"Algorithm:    {record.algorithm}")
    print(f"Created:      {record.created_at}")
    print(f"Expires:      {record.expires_at or 'never'}")
    print(f"Revoked:      {record.revoked}")
    if record.revoked_at:
        print(f"Revoked at:   {record.revoked_at}")
    print(f"Description:  {record.description or '(none)'}")

    if record.associated_files:
        print(f"\nAssociated files ({len(record.associated_files)}):")
        for f in record.associated_files:
            print(f"  - {f}")

    if record.previous_versions:
        print(f"\nVersion history ({len(record.previous_versions)} previous):")
        for pv in record.previous_versions:
            print(
                f"  v{pv.version}: created {pv.created_at}, retired {pv.retired_at}"
            )

    return 0


@handle_errors(audit_event_type="key:revoke")
def cmd_keys_revoke(args: argparse.Namespace) -> int:
    """Revoke a key."""
    km = _get_key_manager(args)
    record = km.get_key(args.key_id)

    # RBAC enforcement
    ac = _get_access_controller(args)
    if ac.is_initialized():
        user = _resolve_current_user(args, ac)
        ac.check_key_access(user, "key:revoke", "key:revoke_any", record.owner_id)

    record = km.revoke_key(args.key_id)

    if not args.quiet:
        print(f"Key {record.key_id} has been revoked.")
        if record.associated_files:
            print(
                f"Warning: {len(record.associated_files)} associated file(s) "
                "will no longer be decryptable."
            )

    return 0


@handle_errors(audit_event_type="key:rotate")
def cmd_keys_rotate(args: argparse.Namespace) -> int:
    """Rotate a key (new version, re-encrypt associated files)."""
    km = _get_key_manager(args)
    record = km.get_key(args.key_id)

    # RBAC enforcement
    ac = _get_access_controller(args)
    if ac.is_initialized():
        user = _resolve_current_user(args, ac)
        ac.check_key_access(user, "key:rotate", "key:rotate_any", record.owner_id)

    record = km.rotate_key(args.key_id)

    if not args.quiet:
        print(
            f"Key {record.key_id} rotated to version {record.version}."
        )
        if record.associated_files:
            print(
                f"Re-encrypted {len(record.associated_files)} associated file(s)."
            )

    return 0


@handle_errors(audit_event_type="key:set_expiry")
def cmd_keys_expire(args: argparse.Namespace) -> int:
    """Set expiry on a key."""
    km = _get_key_manager(args)
    record = km.get_key(args.key_id)

    # RBAC enforcement
    ac = _get_access_controller(args)
    if ac.is_initialized():
        user = _resolve_current_user(args, ac)
        ac.check_key_access(
            user, "key:set_expiry", "key:set_expiry_any", record.owner_id
        )

    expires_at = parse_datetime(args.at)
    record = km.set_expiry(args.key_id, expires_at)

    if not args.quiet:
        print(f"Key {record.key_id} set to expire at {record.expires_at}.")

    return 0


# ---------------------------------------------------------------------------
# Init command
# ---------------------------------------------------------------------------

@handle_errors(audit_event_type="system:init")
def cmd_init(args: argparse.Namespace) -> int:
    """Initialize the RBAC system."""
    ac = _get_access_controller(args)
    user = ac.initialize(args.admin_user, args.admin_password)
    if not args.quiet:
        print(f"System initialized. Admin user '{user.username}' created.")
        print(f"User ID: {user.user_id}")
    return 0


# ---------------------------------------------------------------------------
# User management commands
# ---------------------------------------------------------------------------

@handle_errors(audit_event_type="user:create")
def cmd_user_create(args: argparse.Namespace) -> int:
    """Create a new user."""
    ac = _get_access_controller(args)
    acting_user = _resolve_current_user(args, ac)
    new_user = ac.create_user(acting_user, args.username, args.password, args.role)
    if not args.quiet:
        print(f"User '{new_user.username}' created with role '{args.role}'.")
        print(f"User ID: {new_user.user_id}")
    return 0


@handle_errors(audit_event_type="user:list")
def cmd_user_list(args: argparse.Namespace) -> int:
    """List all users."""
    ac = _get_access_controller(args)
    acting_user = _resolve_current_user(args, ac)
    users = ac.list_users(acting_user)
    if not users:
        if not args.quiet:
            print("No users found.")
        return 0
    print(f"{'USERNAME':<20} {'USER ID':<38} {'ACTIVE':<8} {'EXPIRES':<26}")
    print("-" * 94)
    for u in users:
        expires = u.access_expires_at or "never"
        active = "yes" if u.is_active else "no"
        print(f"{u.username:<20} {u.user_id:<38} {active:<8} {expires:<26}")
    return 0


@handle_errors(audit_event_type="user:info")
def cmd_user_info(args: argparse.Namespace) -> int:
    """Show user details."""
    ac = _get_access_controller(args)
    acting_user = _resolve_current_user(args, ac)
    target = ac.get_user_info(acting_user, args.username)
    print(f"User ID:     {target.user_id}")
    print(f"Username:    {target.username}")
    print(f"Active:      {target.is_active}")
    print(f"Created:     {target.created_at}")
    print(f"Expires:     {target.access_expires_at or 'never'}")
    if target.deactivated_at:
        print(f"Deactivated: {target.deactivated_at}")
    for role_id in target.role_ids:
        try:
            role = ac.role_store.load_role(role_id)
            print(f"Role:        {role.name} ({role_id})")
        except Exception:
            print(f"Role:        <unknown> ({role_id})")
    return 0


@handle_errors(audit_event_type="user:deactivate")
def cmd_user_deactivate(args: argparse.Namespace) -> int:
    """Deactivate a user."""
    ac = _get_access_controller(args)
    acting_user = _resolve_current_user(args, ac)
    target = ac.deactivate_user(acting_user, args.username)
    if not args.quiet:
        print(f"User '{target.username}' has been deactivated.")
    return 0


@handle_errors(audit_event_type="user:set_expiry")
def cmd_user_set_expiry(args: argparse.Namespace) -> int:
    """Set user access expiry."""
    ac = _get_access_controller(args)
    acting_user = _resolve_current_user(args, ac)
    target = ac.set_user_expiry(acting_user, args.username, args.at)
    if not args.quiet:
        print(f"User '{target.username}' access set to expire at {args.at}.")
    return 0


# ---------------------------------------------------------------------------
# Role commands
# ---------------------------------------------------------------------------

@handle_errors(audit_event_type="role:list")
def cmd_role_list(args: argparse.Namespace) -> int:
    """List all roles."""
    ac = _get_access_controller(args)
    acting_user = _resolve_current_user(args, ac)
    ac.check_permission(acting_user, "role:list")
    roles = ac.role_store.list_roles()
    if not roles:
        if not args.quiet:
            print("No roles found.")
        return 0
    print(f"{'NAME':<16} {'PERMISSIONS':<12} {'DESCRIPTION'}")
    print("-" * 70)
    for r in roles:
        print(f"{r.name:<16} {len(r.permissions):<12} {r.description}")
    return 0


@handle_errors(audit_event_type="role:info")
def cmd_role_info(args: argparse.Namespace) -> int:
    """Show role details."""
    ac = _get_access_controller(args)
    acting_user = _resolve_current_user(args, ac)
    ac.check_permission(acting_user, "role:info")
    role = ac.role_store.load_role_by_name(args.name)
    print(f"Role ID:      {role.role_id}")
    print(f"Name:         {role.name}")
    print(f"Description:  {role.description}")
    print(f"Created:      {role.created_at}")
    print(f"Permissions ({len(role.permissions)}):")
    for p in sorted(role.permissions):
        print(f"  - {p}")
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="file_storage",
        description="CLI file encryption tool with key lifecycle management",
    )
    parser.add_argument(
        "--keystore", help="Path to key store directory", default=None
    )
    parser.add_argument(
        "--datadir", help="Path to data root directory", default=None
    )
    parser.add_argument(
        "--user", help="Username for RBAC authentication", default=None
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress non-error output"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    subparsers = parser.add_subparsers(dest="command")

    # init
    init_cmd = subparsers.add_parser("init", help="Initialize RBAC system")
    init_cmd.add_argument("--admin-user", required=True, help="Admin username")
    init_cmd.add_argument("--admin-password", required=True, help="Admin password")
    init_cmd.set_defaults(func=cmd_init)

    # encrypt
    enc = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("file", help="Path to the file to encrypt")
    enc.add_argument("--output", "-o", help="Output file path")
    enc.add_argument("--force", "-f", action="store_true", help="Overwrite output")
    enc.add_argument("--description", help="Description for the generated key")
    enc.set_defaults(func=cmd_encrypt)

    # decrypt
    dec = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("file", help="Path to the encrypted file")
    dec.add_argument("--output", "-o", help="Output file path")
    dec.add_argument("--force", "-f", action="store_true", help="Overwrite output")
    dec.set_defaults(func=cmd_decrypt)

    # keys
    keys = subparsers.add_parser("keys", help="Key management commands")
    keys_sub = keys.add_subparsers(dest="keys_command")

    # keys list
    kl = keys_sub.add_parser("list", help="List all keys")
    kl.add_argument(
        "--status",
        choices=["active", "expired", "revoked", "all"],
        default="all",
        help="Filter by status",
    )
    kl.set_defaults(func=cmd_keys_list)

    # keys info
    ki = keys_sub.add_parser("info", help="Show key details")
    ki.add_argument("key_id", help="Key UUID")
    ki.set_defaults(func=cmd_keys_info)

    # keys revoke
    kr = keys_sub.add_parser("revoke", help="Revoke a key")
    kr.add_argument("key_id", help="Key UUID")
    kr.set_defaults(func=cmd_keys_revoke)

    # keys rotate
    krot = keys_sub.add_parser("rotate", help="Rotate a key")
    krot.add_argument("key_id", help="Key UUID")
    krot.set_defaults(func=cmd_keys_rotate)

    # keys expire
    ke = keys_sub.add_parser("expire", help="Set key expiry")
    ke.add_argument("key_id", help="Key UUID")
    ke.add_argument(
        "--at", required=True, help="Expiry datetime (ISO 8601 format)"
    )
    ke.set_defaults(func=cmd_keys_expire)

    # user
    user_cmd = subparsers.add_parser("user", help="User management commands")
    user_sub = user_cmd.add_subparsers(dest="user_command")

    uc = user_sub.add_parser("create", help="Create a new user")
    uc.add_argument("username", help="New user's username")
    uc.add_argument("--password", required=True, help="New user's password")
    uc.add_argument("--role", required=True, help="Role name to assign")
    uc.set_defaults(func=cmd_user_create)

    ul = user_sub.add_parser("list", help="List all users")
    ul.set_defaults(func=cmd_user_list)

    ui = user_sub.add_parser("info", help="Show user details")
    ui.add_argument("username", help="Username to inspect")
    ui.set_defaults(func=cmd_user_info)

    ud = user_sub.add_parser("deactivate", help="Deactivate a user")
    ud.add_argument("username", help="Username to deactivate")
    ud.set_defaults(func=cmd_user_deactivate)

    ue = user_sub.add_parser("set-expiry", help="Set user access expiry")
    ue.add_argument("username", help="Username")
    ue.add_argument("--at", required=True, help="Expiry datetime (ISO 8601)")
    ue.set_defaults(func=cmd_user_set_expiry)

    # role
    role_cmd = subparsers.add_parser("role", help="Role management commands")
    role_sub = role_cmd.add_subparsers(dest="role_command")

    rl = role_sub.add_parser("list", help="List all roles")
    rl.set_defaults(func=cmd_role_list)

    ri = role_sub.add_parser("info", help="Show role details")
    ri.add_argument("name", help="Role name")
    ri.set_defaults(func=cmd_role_info)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Parse args and dispatch."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    return args.func(args)


def main_entry() -> None:
    """Console script entry point."""
    sys.exit(main())
