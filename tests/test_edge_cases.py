"""Edge case and robustness tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from file_storage.cli import main
from file_storage.constants import HMAC_SIZE, MAGIC
from file_storage.key_manager import KeyManager
from file_storage.key_store import KeyStore


@pytest.fixture
def cli_env(tmp_path):
    keystore = tmp_path / "keys"
    keystore.mkdir()
    return {"keystore": str(keystore), "tmp_path": tmp_path}


def run_cli(*args, keystore=None):
    cmd = list(args)
    if keystore:
        cmd = ["--keystore", keystore] + cmd
    return main(cmd)


class TestEmptyFile:
    def test_encrypt_empty_file(self, cli_env):
        empty = cli_env["tmp_path"] / "empty.txt"
        empty.write_bytes(b"")
        ret = run_cli("encrypt", str(empty), keystore=cli_env["keystore"])
        assert ret == 0
        enc = Path(str(empty) + ".enc")
        assert enc.exists()
        assert enc.stat().st_size > 0

    def test_decrypt_empty_encrypted_file(self, cli_env):
        empty = cli_env["tmp_path"] / "empty.txt"
        empty.write_bytes(b"")
        run_cli("encrypt", str(empty), keystore=cli_env["keystore"])
        enc = str(empty) + ".enc"
        empty.unlink()

        ret = run_cli("decrypt", enc, keystore=cli_env["keystore"])
        assert ret == 0
        assert empty.read_bytes() == b""


class TestLargeFile:
    @pytest.mark.timeout(30)
    def test_encrypt_large_file(self, cli_env):
        large = cli_env["tmp_path"] / "large.bin"
        data = os.urandom(10 * 1024 * 1024)  # 10MB
        large.write_bytes(data)

        ret = run_cli("encrypt", str(large), keystore=cli_env["keystore"])
        assert ret == 0

        enc = str(large) + ".enc"
        large.unlink()
        out = cli_env["tmp_path"] / "large_restored.bin"
        ret = run_cli("decrypt", enc, "-o", str(out), keystore=cli_env["keystore"])
        assert ret == 0
        assert out.read_bytes() == data


class TestBinaryFile:
    def test_encrypt_binary_file(self, cli_env):
        binf = cli_env["tmp_path"] / "data.bin"
        data = bytes(range(256)) * 100
        binf.write_bytes(data)

        ret = run_cli("encrypt", str(binf), keystore=cli_env["keystore"])
        assert ret == 0

        enc = str(binf) + ".enc"
        binf.unlink()
        ret = run_cli("decrypt", enc, keystore=cli_env["keystore"])
        assert ret == 0
        assert binf.read_bytes() == data


class TestFilenameEdgeCases:
    def test_file_with_spaces(self, cli_env):
        spaced = cli_env["tmp_path"] / "my file.txt"
        spaced.write_text("content")
        ret = run_cli("encrypt", str(spaced), keystore=cli_env["keystore"])
        assert ret == 0

        enc = str(spaced) + ".enc"
        spaced.unlink()
        ret = run_cli("decrypt", enc, keystore=cli_env["keystore"])
        assert ret == 0
        assert spaced.read_text() == "content"

    def test_file_with_unicode_name(self, cli_env):
        uni = cli_env["tmp_path"] / "file_\u00e9\u00e8.txt"
        uni.write_text("unicode content")
        ret = run_cli("encrypt", str(uni), keystore=cli_env["keystore"])
        assert ret == 0

        enc = str(uni) + ".enc"
        uni.unlink()
        ret = run_cli("decrypt", enc, keystore=cli_env["keystore"])
        assert ret == 0
        assert uni.read_text() == "unicode content"


class TestOutputConflicts:
    def test_output_exists_error(self, cli_env):
        src = cli_env["tmp_path"] / "src.txt"
        src.write_text("data")
        out = cli_env["tmp_path"] / "out.enc"
        out.write_text("existing")
        ret = run_cli(
            "encrypt", str(src), "-o", str(out),
            keystore=cli_env["keystore"],
        )
        assert ret == 1

    def test_output_exists_force(self, cli_env):
        src = cli_env["tmp_path"] / "src.txt"
        src.write_text("data")
        out = cli_env["tmp_path"] / "out.enc"
        out.write_text("existing")
        ret = run_cli(
            "encrypt", str(src), "-o", str(out), "-f",
            keystore=cli_env["keystore"],
        )
        assert ret == 0

    def test_decrypt_output_exists_error(self, cli_env):
        src = cli_env["tmp_path"] / "src.txt"
        src.write_text("data")
        run_cli("encrypt", str(src), keystore=cli_env["keystore"])
        enc = str(src) + ".enc"
        # src still exists, so decrypt without --force should fail
        ret = run_cli("decrypt", enc, keystore=cli_env["keystore"])
        assert ret == 1

    def test_decrypt_output_exists_force(self, cli_env):
        src = cli_env["tmp_path"] / "src.txt"
        src.write_text("data")
        run_cli("encrypt", str(src), keystore=cli_env["keystore"])
        enc = str(src) + ".enc"
        ret = run_cli("decrypt", enc, "-f", keystore=cli_env["keystore"])
        assert ret == 0


class TestKeystoreEdgeCases:
    def test_missing_keystore_auto_creates(self, cli_env):
        new_ks = cli_env["tmp_path"] / "new_store" / "keys"
        src = cli_env["tmp_path"] / "src.txt"
        src.write_text("data")
        ret = run_cli("encrypt", str(src), keystore=str(new_ks))
        assert ret == 0
        assert new_ks.exists()


class TestCorruptedEncryptedFiles:
    def test_truncated_file(self, cli_env):
        src = cli_env["tmp_path"] / "src.txt"
        src.write_text("Hello, World!")
        run_cli("encrypt", str(src), keystore=cli_env["keystore"])
        enc = Path(str(src) + ".enc")

        # Truncate to just a few bytes
        data = enc.read_bytes()
        enc.write_bytes(data[:10])

        out = cli_env["tmp_path"] / "out.txt"
        ret = run_cli("decrypt", str(enc), "-o", str(out), keystore=cli_env["keystore"])
        assert ret == 1

    def test_extra_bytes_detected(self, cli_env):
        src = cli_env["tmp_path"] / "src.txt"
        src.write_text("Hello, World!")
        run_cli("encrypt", str(src), keystore=cli_env["keystore"])
        enc = Path(str(src) + ".enc")

        # Append extra bytes (this shifts the HMAC position)
        data = enc.read_bytes()
        enc.write_bytes(data + b"\x00\x00\x00\x00")

        out = cli_env["tmp_path"] / "out.txt"
        ret = run_cli("decrypt", str(enc), "-o", str(out), keystore=cli_env["keystore"])
        assert ret == 1

    def test_completely_random_file_rejected(self, cli_env):
        fake = cli_env["tmp_path"] / "random.enc"
        fake.write_bytes(os.urandom(200))
        out = cli_env["tmp_path"] / "out.txt"
        ret = run_cli("decrypt", str(fake), "-o", str(out), keystore=cli_env["keystore"])
        assert ret == 1

    def test_too_small_file_rejected(self, cli_env):
        tiny = cli_env["tmp_path"] / "tiny.enc"
        tiny.write_bytes(b"tiny")
        out = cli_env["tmp_path"] / "out.txt"
        ret = run_cli("decrypt", str(tiny), "-o", str(out), keystore=cli_env["keystore"])
        assert ret == 1


class TestKeyRotationWithFiles:
    def test_rotate_reencrypts_and_decrypt_works(self, cli_env):
        src = cli_env["tmp_path"] / "rotatable.txt"
        src.write_text("rotatable content")
        run_cli("encrypt", str(src), keystore=cli_env["keystore"])

        km = KeyManager(KeyStore(Path(cli_env["keystore"])))
        keys = km.list_keys()
        key_id = keys[0].key_id

        # Rotate
        run_cli("keys", "rotate", key_id, keystore=cli_env["keystore"])

        # Verify version incremented
        updated = km.get_key(key_id)
        assert updated.version == 2

        # Decrypt should still work
        enc = str(src) + ".enc"
        src.unlink()
        ret = run_cli("decrypt", enc, keystore=cli_env["keystore"])
        assert ret == 0
        assert src.read_text() == "rotatable content"

    def test_rotate_revoked_key_fails(self, cli_env):
        src = cli_env["tmp_path"] / "src.txt"
        src.write_text("data")
        run_cli("encrypt", str(src), keystore=cli_env["keystore"])

        km = KeyManager(KeyStore(Path(cli_env["keystore"])))
        keys = km.list_keys()
        km.revoke_key(keys[0].key_id)

        ret = run_cli("keys", "rotate", keys[0].key_id, keystore=cli_env["keystore"])
        assert ret == 1


class TestMultipleFiles:
    def test_multiple_files_unique_keys(self, cli_env):
        f1 = cli_env["tmp_path"] / "file1.txt"
        f2 = cli_env["tmp_path"] / "file2.txt"
        f1.write_text("content 1")
        f2.write_text("content 2")

        run_cli("encrypt", str(f1), keystore=cli_env["keystore"])
        run_cli("encrypt", str(f2), keystore=cli_env["keystore"])

        km = KeyManager(KeyStore(Path(cli_env["keystore"])))
        keys = km.list_keys()
        assert len(keys) == 2
        assert keys[0].key_id != keys[1].key_id

    def test_multiple_encrypt_decrypt_roundtrips(self, cli_env):
        files = []
        for i in range(5):
            f = cli_env["tmp_path"] / f"file{i}.txt"
            f.write_text(f"content {i}")
            files.append(f)

        for f in files:
            run_cli("encrypt", str(f), keystore=cli_env["keystore"])

        for i, f in enumerate(files):
            enc = str(f) + ".enc"
            f.unlink()
            ret = run_cli("decrypt", enc, keystore=cli_env["keystore"])
            assert ret == 0
            assert f.read_text() == f"content {i}"
