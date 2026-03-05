"""End-to-end integration tests for CLI commands."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from file_storage.cli import main
from file_storage.constants import HMAC_SIZE, MAGIC
from file_storage.key_manager import KeyManager
from file_storage.key_store import KeyStore


@pytest.fixture
def cli_env(tmp_path):
    """Set up a temporary environment for CLI testing."""
    keystore = tmp_path / "keys"
    keystore.mkdir()
    sample = tmp_path / "hello.txt"
    sample.write_text("Hello, World!")
    return {
        "keystore": str(keystore),
        "tmp_path": tmp_path,
        "sample": sample,
    }


def run_cli(*args, keystore=None):
    """Helper to invoke CLI with keystore flag."""
    cmd = list(args)
    if keystore:
        cmd = ["--keystore", keystore] + cmd
    return main(cmd)


class TestEncrypt:
    def test_encrypt_creates_output(self, cli_env):
        ret = run_cli(
            "encrypt", str(cli_env["sample"]),
            keystore=cli_env["keystore"],
        )
        assert ret == 0
        enc_path = Path(str(cli_env["sample"]) + ".enc")
        assert enc_path.exists()
        data = enc_path.read_bytes()
        assert data[:8] == MAGIC

    def test_encrypt_custom_output_path(self, cli_env):
        out = cli_env["tmp_path"] / "custom.enc"
        ret = run_cli(
            "encrypt", str(cli_env["sample"]),
            "-o", str(out),
            keystore=cli_env["keystore"],
        )
        assert ret == 0
        assert out.exists()

    def test_encrypt_nonexistent_file_error(self, cli_env):
        ret = run_cli(
            "encrypt", "/nonexistent/file.txt",
            keystore=cli_env["keystore"],
        )
        assert ret == 1

    def test_encrypt_output_exists_without_force(self, cli_env):
        out = cli_env["tmp_path"] / "exists.enc"
        out.write_text("existing")
        ret = run_cli(
            "encrypt", str(cli_env["sample"]),
            "-o", str(out),
            keystore=cli_env["keystore"],
        )
        assert ret == 1

    def test_encrypt_output_exists_with_force(self, cli_env):
        out = cli_env["tmp_path"] / "exists.enc"
        out.write_text("existing")
        ret = run_cli(
            "encrypt", str(cli_env["sample"]),
            "-o", str(out), "-f",
            keystore=cli_env["keystore"],
        )
        assert ret == 0


class TestDecrypt:
    def test_decrypt_restores_original(self, cli_env):
        original_content = cli_env["sample"].read_text()
        run_cli(
            "encrypt", str(cli_env["sample"]),
            keystore=cli_env["keystore"],
        )
        enc_path = str(cli_env["sample"]) + ".enc"
        # Remove original to avoid conflict
        cli_env["sample"].unlink()

        ret = run_cli(
            "decrypt", enc_path,
            keystore=cli_env["keystore"],
        )
        assert ret == 0
        assert cli_env["sample"].read_text() == original_content

    def test_decrypt_custom_output(self, cli_env):
        run_cli(
            "encrypt", str(cli_env["sample"]),
            keystore=cli_env["keystore"],
        )
        enc_path = str(cli_env["sample"]) + ".enc"
        out = cli_env["tmp_path"] / "restored.txt"

        ret = run_cli(
            "decrypt", enc_path,
            "-o", str(out),
            keystore=cli_env["keystore"],
        )
        assert ret == 0
        assert out.read_text() == "Hello, World!"

    def test_decrypt_nonexistent_file_error(self, cli_env):
        ret = run_cli(
            "decrypt", "/nonexistent/file.enc",
            keystore=cli_env["keystore"],
        )
        assert ret == 1

    def test_decrypt_expired_key_rejected(self, cli_env):
        run_cli(
            "encrypt", str(cli_env["sample"]),
            keystore=cli_env["keystore"],
        )
        enc_path = str(cli_env["sample"]) + ".enc"

        # Find the key and expire it
        km = KeyManager(KeyStore(Path(cli_env["keystore"])))
        keys = km.list_keys()
        assert len(keys) == 1
        key = keys[0]
        key.expires_at = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).isoformat()
        km.store.save_key(key)

        out = cli_env["tmp_path"] / "decrypted.txt"
        ret = run_cli(
            "decrypt", enc_path,
            "-o", str(out),
            keystore=cli_env["keystore"],
        )
        assert ret == 1

    def test_decrypt_revoked_key_rejected(self, cli_env):
        run_cli(
            "encrypt", str(cli_env["sample"]),
            keystore=cli_env["keystore"],
        )
        enc_path = str(cli_env["sample"]) + ".enc"

        # Find and revoke the key
        km = KeyManager(KeyStore(Path(cli_env["keystore"])))
        keys = km.list_keys()
        km.revoke_key(keys[0].key_id)

        out = cli_env["tmp_path"] / "decrypted.txt"
        ret = run_cli(
            "decrypt", enc_path,
            "-o", str(out),
            keystore=cli_env["keystore"],
        )
        assert ret == 1

    def test_decrypt_tampered_file_rejected(self, cli_env):
        run_cli(
            "encrypt", str(cli_env["sample"]),
            keystore=cli_env["keystore"],
        )
        enc_path = Path(str(cli_env["sample"]) + ".enc")

        # Tamper with the ciphertext (not the HMAC at the end)
        data = bytearray(enc_path.read_bytes())
        # Flip a byte in the middle of the file (ciphertext area)
        mid = len(data) // 2
        data[mid] ^= 0xFF
        enc_path.write_bytes(bytes(data))

        out = cli_env["tmp_path"] / "decrypted.txt"
        ret = run_cli(
            "decrypt", str(enc_path),
            "-o", str(out),
            keystore=cli_env["keystore"],
        )
        assert ret == 1

    def test_decrypt_tampered_header_rejected(self, cli_env):
        run_cli(
            "encrypt", str(cli_env["sample"]),
            keystore=cli_env["keystore"],
        )
        enc_path = Path(str(cli_env["sample"]) + ".enc")

        # Tamper with the header (byte 30 is in the nonce area)
        data = bytearray(enc_path.read_bytes())
        data[30] ^= 0xFF
        enc_path.write_bytes(bytes(data))

        out = cli_env["tmp_path"] / "decrypted.txt"
        ret = run_cli(
            "decrypt", str(enc_path),
            "-o", str(out),
            keystore=cli_env["keystore"],
        )
        assert ret == 1


class TestKeysCommands:
    def test_keys_list_empty(self, cli_env):
        ret = run_cli(
            "keys", "list",
            keystore=cli_env["keystore"],
        )
        assert ret == 0

    def test_keys_list_shows_keys(self, cli_env, capsys):
        run_cli(
            "encrypt", str(cli_env["sample"]),
            keystore=cli_env["keystore"],
        )
        ret = run_cli(
            "keys", "list",
            keystore=cli_env["keystore"],
        )
        assert ret == 0
        output = capsys.readouterr().out
        assert "active" in output

    def test_keys_list_filter_by_status(self, cli_env, capsys):
        run_cli(
            "encrypt", str(cli_env["sample"]),
            keystore=cli_env["keystore"],
        )
        # Revoke the key
        km = KeyManager(KeyStore(Path(cli_env["keystore"])))
        keys = km.list_keys()
        km.revoke_key(keys[0].key_id)

        ret = run_cli(
            "keys", "list", "--status", "active",
            keystore=cli_env["keystore"],
        )
        assert ret == 0
        output = capsys.readouterr().out
        assert "No keys found." in output

    def test_keys_info_shows_details(self, cli_env, capsys):
        run_cli(
            "encrypt", str(cli_env["sample"]),
            keystore=cli_env["keystore"],
        )
        km = KeyManager(KeyStore(Path(cli_env["keystore"])))
        keys = km.list_keys()

        ret = run_cli(
            "keys", "info", keys[0].key_id,
            keystore=cli_env["keystore"],
        )
        assert ret == 0
        output = capsys.readouterr().out
        assert "Key ID:" in output
        assert "AES-256-GCM" in output

    def test_keys_info_not_found(self, cli_env):
        ret = run_cli(
            "keys", "info", "nonexistent-key",
            keystore=cli_env["keystore"],
        )
        assert ret == 1

    def test_keys_revoke(self, cli_env, capsys):
        run_cli(
            "encrypt", str(cli_env["sample"]),
            keystore=cli_env["keystore"],
        )
        km = KeyManager(KeyStore(Path(cli_env["keystore"])))
        keys = km.list_keys()

        ret = run_cli(
            "keys", "revoke", keys[0].key_id,
            keystore=cli_env["keystore"],
        )
        assert ret == 0
        output = capsys.readouterr().out
        assert "revoked" in output

    def test_keys_rotate(self, cli_env, capsys):
        run_cli(
            "encrypt", str(cli_env["sample"]),
            keystore=cli_env["keystore"],
        )
        km = KeyManager(KeyStore(Path(cli_env["keystore"])))
        keys = km.list_keys()

        ret = run_cli(
            "keys", "rotate", keys[0].key_id,
            keystore=cli_env["keystore"],
        )
        assert ret == 0
        output = capsys.readouterr().out
        assert "version 2" in output

    def test_keys_rotate_then_decrypt(self, cli_env):
        """After rotation, the re-encrypted file should still be decryptable."""
        run_cli(
            "encrypt", str(cli_env["sample"]),
            keystore=cli_env["keystore"],
        )
        enc_path = str(cli_env["sample"]) + ".enc"

        km = KeyManager(KeyStore(Path(cli_env["keystore"])))
        keys = km.list_keys()
        run_cli(
            "keys", "rotate", keys[0].key_id,
            keystore=cli_env["keystore"],
        )

        cli_env["sample"].unlink()
        ret = run_cli(
            "decrypt", enc_path,
            keystore=cli_env["keystore"],
        )
        assert ret == 0
        assert cli_env["sample"].read_text() == "Hello, World!"

    def test_keys_expire(self, cli_env, capsys):
        run_cli(
            "encrypt", str(cli_env["sample"]),
            keystore=cli_env["keystore"],
        )
        km = KeyManager(KeyStore(Path(cli_env["keystore"])))
        keys = km.list_keys()

        future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        ret = run_cli(
            "keys", "expire", keys[0].key_id, "--at", future,
            keystore=cli_env["keystore"],
        )
        assert ret == 0
        output = capsys.readouterr().out
        assert "expire" in output

    def test_keys_expire_past_rejected(self, cli_env):
        run_cli(
            "encrypt", str(cli_env["sample"]),
            keystore=cli_env["keystore"],
        )
        km = KeyManager(KeyStore(Path(cli_env["keystore"])))
        keys = km.list_keys()

        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        ret = run_cli(
            "keys", "expire", keys[0].key_id, "--at", past,
            keystore=cli_env["keystore"],
        )
        assert ret == 1


class TestMainEntryPoint:
    def test_no_args_shows_help(self, capsys):
        ret = main([])
        assert ret == 1

    def test_encrypt_subcommand(self, cli_env):
        ret = main([
            "--keystore", cli_env["keystore"],
            "encrypt", str(cli_env["sample"]),
        ])
        assert ret == 0
