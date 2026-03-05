"""End-to-end integration tests for CLI with RBAC enforcement."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from file_storage.cli import main
from file_storage.key_manager import KeyManager
from file_storage.key_store import KeyStore


@pytest.fixture
def rbac_env(tmp_path):
    """Set up an RBAC-enabled CLI environment."""
    datadir = tmp_path / "data"
    keystore = datadir / "keys"
    keystore.mkdir(parents=True)

    sample = tmp_path / "hello.txt"
    sample.write_text("Hello, World!")

    # Initialize RBAC
    ret = main([
        "--datadir", str(datadir),
        "init", "--admin-user", "admin", "--admin-password", "secret123",
    ])
    assert ret == 0

    # Create an encryptor user
    ret = main([
        "--datadir", str(datadir),
        "--user", "admin",
        "user", "create", "alice",
        "--password", "alice_pass", "--role", "encryptor",
    ])
    assert ret == 0

    # Create a viewer user
    ret = main([
        "--datadir", str(datadir),
        "--user", "admin",
        "user", "create", "viewer1",
        "--password", "viewer_pass", "--role", "viewer",
    ])
    assert ret == 0

    return {
        "datadir": str(datadir),
        "keystore": str(keystore),
        "tmp_path": tmp_path,
        "sample": sample,
    }


def run_rbac(*args, datadir=None, user=None):
    """Helper to invoke CLI with --datadir and --user."""
    cmd = list(args)
    if datadir:
        cmd = ["--datadir", datadir] + cmd
    if user:
        cmd = ["--user", user] + cmd
    return main(cmd)


# ---------------------------------------------------------------------------
# Init command
# ---------------------------------------------------------------------------

class TestInitCommand:
    def test_init_succeeds(self, tmp_path):
        datadir = tmp_path / "data"
        ret = main([
            "--datadir", str(datadir),
            "init", "--admin-user", "admin", "--admin-password", "pass",
        ])
        assert ret == 0

    def test_init_twice_fails(self, tmp_path):
        datadir = tmp_path / "data"
        main([
            "--datadir", str(datadir),
            "init", "--admin-user", "admin", "--admin-password", "pass",
        ])
        ret = main([
            "--datadir", str(datadir),
            "init", "--admin-user", "admin2", "--admin-password", "pass2",
        ])
        assert ret == 1

    def test_init_creates_roles_and_users_dirs(self, tmp_path):
        datadir = tmp_path / "data"
        main([
            "--datadir", str(datadir),
            "init", "--admin-user", "admin", "--admin-password", "pass",
        ])
        assert (datadir / "roles").exists()
        assert (datadir / "users").exists()


# ---------------------------------------------------------------------------
# Encrypt with RBAC
# ---------------------------------------------------------------------------

class TestEncryptWithRBAC:
    def test_admin_can_encrypt(self, rbac_env):
        ret = run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="admin",
        )
        assert ret == 0

    def test_encryptor_can_encrypt(self, rbac_env):
        ret = run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="alice",
        )
        assert ret == 0

    def test_viewer_cannot_encrypt(self, rbac_env):
        ret = run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="viewer1",
        )
        assert ret == 1

    def test_missing_user_flag_fails(self, rbac_env):
        ret = run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"],
        )
        assert ret == 1

    def test_unknown_user_fails(self, rbac_env):
        ret = run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="nobody",
        )
        assert ret == 1

    def test_encrypt_sets_owner_id(self, rbac_env):
        run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="alice",
        )
        km = KeyManager(KeyStore(Path(rbac_env["keystore"])))
        keys = km.list_keys()
        assert len(keys) == 1
        assert keys[0].owner_id is not None


# ---------------------------------------------------------------------------
# Decrypt with RBAC
# ---------------------------------------------------------------------------

class TestDecryptWithRBAC:
    def test_owner_can_decrypt_own_file(self, rbac_env):
        run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="alice",
        )
        enc = str(rbac_env["sample"]) + ".enc"
        rbac_env["sample"].unlink()
        ret = run_rbac(
            "decrypt", enc,
            datadir=rbac_env["datadir"], user="alice",
        )
        assert ret == 0
        assert rbac_env["sample"].read_text() == "Hello, World!"

    def test_admin_can_decrypt_any_file(self, rbac_env):
        run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="alice",
        )
        enc = str(rbac_env["sample"]) + ".enc"
        rbac_env["sample"].unlink()
        ret = run_rbac(
            "decrypt", enc,
            datadir=rbac_env["datadir"], user="admin",
        )
        assert ret == 0

    def test_viewer_cannot_decrypt(self, rbac_env):
        run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="alice",
        )
        enc = str(rbac_env["sample"]) + ".enc"
        out = rbac_env["tmp_path"] / "out.txt"
        ret = run_rbac(
            "decrypt", enc, "-o", str(out),
            datadir=rbac_env["datadir"], user="viewer1",
        )
        assert ret == 1

    def test_encryptor_cannot_decrypt_others_file(self, rbac_env):
        # Admin encrypts
        run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="admin",
        )
        enc = str(rbac_env["sample"]) + ".enc"
        out = rbac_env["tmp_path"] / "out.txt"
        # Alice tries to decrypt admin's file
        ret = run_rbac(
            "decrypt", enc, "-o", str(out),
            datadir=rbac_env["datadir"], user="alice",
        )
        assert ret == 1


# ---------------------------------------------------------------------------
# Key commands with RBAC
# ---------------------------------------------------------------------------

class TestKeyCommandsWithRBAC:
    def test_admin_can_revoke_any_key(self, rbac_env):
        run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="alice",
        )
        km = KeyManager(KeyStore(Path(rbac_env["keystore"])))
        keys = km.list_keys()
        ret = run_rbac(
            "keys", "revoke", keys[0].key_id,
            datadir=rbac_env["datadir"], user="admin",
        )
        assert ret == 0

    def test_encryptor_can_rotate_own_key(self, rbac_env):
        run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="alice",
        )
        km = KeyManager(KeyStore(Path(rbac_env["keystore"])))
        keys = km.list_keys()
        ret = run_rbac(
            "keys", "rotate", keys[0].key_id,
            datadir=rbac_env["datadir"], user="alice",
        )
        assert ret == 0

    def test_encryptor_cannot_revoke_others_key(self, rbac_env):
        # Admin encrypts
        run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="admin",
        )
        km = KeyManager(KeyStore(Path(rbac_env["keystore"])))
        keys = km.list_keys()
        # Alice tries to revoke admin's key -- no key:revoke or key:revoke_any
        ret = run_rbac(
            "keys", "revoke", keys[0].key_id,
            datadir=rbac_env["datadir"], user="alice",
        )
        assert ret == 1

    def test_viewer_can_list_keys(self, rbac_env):
        ret = run_rbac(
            "keys", "list",
            datadir=rbac_env["datadir"], user="viewer1",
        )
        assert ret == 0

    def test_encryptor_sees_only_own_keys(self, rbac_env, capsys):
        # Admin encrypts
        f1 = rbac_env["tmp_path"] / "admin_file.txt"
        f1.write_text("admin data")
        run_rbac(
            "encrypt", str(f1),
            datadir=rbac_env["datadir"], user="admin",
        )
        # Alice encrypts
        run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="alice",
        )
        # Clear captured output from encrypts
        capsys.readouterr()
        ret = run_rbac(
            "keys", "list",
            datadir=rbac_env["datadir"], user="alice",
        )
        assert ret == 0
        output = capsys.readouterr().out
        # Alice should see 1 key (hers), not 2
        # Count data lines (skip header and separator)
        lines = [l for l in output.strip().split("\n") if l and not l.startswith("-") and not l.startswith("KEY")]
        assert len(lines) == 1

    def test_admin_sees_all_keys(self, rbac_env, capsys):
        f1 = rbac_env["tmp_path"] / "admin_file.txt"
        f1.write_text("admin data")
        run_rbac(
            "encrypt", str(f1),
            datadir=rbac_env["datadir"], user="admin",
        )
        run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="alice",
        )
        # Clear captured output from encrypts
        capsys.readouterr()
        ret = run_rbac(
            "keys", "list",
            datadir=rbac_env["datadir"], user="admin",
        )
        assert ret == 0
        output = capsys.readouterr().out
        lines = [l for l in output.strip().split("\n") if l and not l.startswith("-") and not l.startswith("KEY")]
        assert len(lines) == 2


# ---------------------------------------------------------------------------
# User management commands
# ---------------------------------------------------------------------------

class TestUserCommands:
    def test_admin_creates_user(self, rbac_env, capsys):
        ret = run_rbac(
            "user", "create", "bob",
            "--password", "bob_pass", "--role", "encryptor",
            datadir=rbac_env["datadir"], user="admin",
        )
        assert ret == 0
        output = capsys.readouterr().out
        assert "bob" in output

    def test_admin_lists_users(self, rbac_env, capsys):
        ret = run_rbac(
            "user", "list",
            datadir=rbac_env["datadir"], user="admin",
        )
        assert ret == 0
        output = capsys.readouterr().out
        assert "admin" in output
        assert "alice" in output

    def test_admin_shows_user_info(self, rbac_env, capsys):
        ret = run_rbac(
            "user", "info", "alice",
            datadir=rbac_env["datadir"], user="admin",
        )
        assert ret == 0
        output = capsys.readouterr().out
        assert "alice" in output
        assert "encryptor" in output

    def test_admin_deactivates_user(self, rbac_env):
        ret = run_rbac(
            "user", "deactivate", "alice",
            datadir=rbac_env["datadir"], user="admin",
        )
        assert ret == 0
        # Alice should now be rejected
        ret = run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="alice",
        )
        assert ret == 1

    def test_admin_sets_user_expiry(self, rbac_env):
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        ret = run_rbac(
            "user", "set-expiry", "alice", "--at", past,
            datadir=rbac_env["datadir"], user="admin",
        )
        assert ret == 0
        # Alice should now be rejected (expired)
        ret = run_rbac(
            "encrypt", str(rbac_env["sample"]),
            datadir=rbac_env["datadir"], user="alice",
        )
        assert ret == 1

    def test_nonadmin_cannot_create_user(self, rbac_env):
        ret = run_rbac(
            "user", "create", "unauthorized",
            "--password", "pass", "--role", "viewer",
            datadir=rbac_env["datadir"], user="alice",
        )
        assert ret == 1


# ---------------------------------------------------------------------------
# Role commands
# ---------------------------------------------------------------------------

class TestRoleCommands:
    def test_role_list_shows_default_roles(self, rbac_env, capsys):
        ret = run_rbac(
            "role", "list",
            datadir=rbac_env["datadir"], user="admin",
        )
        assert ret == 0
        output = capsys.readouterr().out
        assert "admin" in output
        assert "encryptor" in output
        assert "viewer" in output

    def test_role_info_shows_permissions(self, rbac_env, capsys):
        ret = run_rbac(
            "role", "info", "encryptor",
            datadir=rbac_env["datadir"], user="admin",
        )
        assert ret == 0
        output = capsys.readouterr().out
        assert "file:encrypt" in output
        assert "file:decrypt" in output


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------

class TestBackwardCompatibility:
    def test_encrypt_without_init_works(self, tmp_path):
        """When RBAC is not initialized, encrypt works without --user."""
        keystore = tmp_path / "keys"
        sample = tmp_path / "test.txt"
        sample.write_text("no rbac needed")
        ret = main([
            "--keystore", str(keystore),
            "encrypt", str(sample),
        ])
        assert ret == 0

    def test_decrypt_without_init_works(self, tmp_path):
        """When RBAC is not initialized, decrypt works without --user."""
        keystore = tmp_path / "keys"
        sample = tmp_path / "test.txt"
        sample.write_text("no rbac needed")
        main(["--keystore", str(keystore), "encrypt", str(sample)])
        enc = str(sample) + ".enc"
        sample.unlink()
        ret = main(["--keystore", str(keystore), "decrypt", enc])
        assert ret == 0
        assert sample.read_text() == "no rbac needed"

    def test_keys_list_without_init_works(self, tmp_path):
        keystore = tmp_path / "keys"
        sample = tmp_path / "test.txt"
        sample.write_text("data")
        main(["--keystore", str(keystore), "encrypt", str(sample)])
        ret = main(["--keystore", str(keystore), "keys", "list"])
        assert ret == 0
