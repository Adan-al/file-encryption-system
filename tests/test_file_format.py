"""Tests for binary header pack/unpack."""

import uuid

import pytest

from file_storage.constants import HEADER_FIXED_SIZE, MAGIC
from file_storage.errors import InvalidFileFormatError, UnsupportedVersionError
from file_storage.file_format import FileHeader, pack_header, unpack_header


def make_header(**kwargs) -> FileHeader:
    defaults = {
        "key_id": uuid.uuid4(),
        "key_version": 1,
        "nonce": b"\x00" * 12,
        "original_filename": "test.txt",
    }
    defaults.update(kwargs)
    return FileHeader(**defaults)


class TestPackUnpack:
    def test_pack_unpack_roundtrip(self):
        header = make_header()
        data = pack_header(header)
        result, offset = unpack_header(data)
        assert result.key_id == header.key_id
        assert result.key_version == header.key_version
        assert result.nonce == header.nonce
        assert result.original_filename == header.original_filename

    def test_pack_deterministic(self):
        header = make_header()
        data1 = pack_header(header)
        data2 = pack_header(header)
        assert data1 == data2

    def test_offset_points_after_header(self):
        header = make_header(original_filename="myfile.txt")
        data = pack_header(header)
        _, offset = unpack_header(data)
        expected = HEADER_FIXED_SIZE + len("myfile.txt".encode("utf-8"))
        assert offset == expected

    def test_header_starts_with_magic(self):
        header = make_header()
        data = pack_header(header)
        assert data[:8] == MAGIC


class TestUnpackErrors:
    def test_unpack_wrong_magic_raises(self):
        data = b"BADMAGIC" + b"\x00" * 40
        with pytest.raises(InvalidFileFormatError, match="Not a valid"):
            unpack_header(data)

    def test_unpack_too_short_raises(self):
        data = b"short"
        with pytest.raises(InvalidFileFormatError, match="too small"):
            unpack_header(data)

    def test_unpack_unsupported_version_raises(self):
        header = make_header()
        data = bytearray(pack_header(header))
        # Set version to 99 (bytes 8-9, big-endian uint16)
        data[8] = 0
        data[9] = 99
        with pytest.raises(UnsupportedVersionError, match="99"):
            unpack_header(bytes(data))

    def test_unpack_truncated_filename_raises(self):
        header = make_header(original_filename="longfilename.txt")
        data = pack_header(header)
        # Truncate the data mid-filename
        truncated = data[: HEADER_FIXED_SIZE + 2]
        with pytest.raises(InvalidFileFormatError, match="truncated"):
            unpack_header(truncated)


class TestFilenameHandling:
    def test_unicode_filename(self):
        header = make_header(original_filename="file_\u00e9\u00e8\u00ea.txt")
        data = pack_header(header)
        result, _ = unpack_header(data)
        assert result.original_filename == "file_\u00e9\u00e8\u00ea.txt"

    def test_long_filename(self):
        long_name = "a" * 500 + ".txt"
        header = make_header(original_filename=long_name)
        data = pack_header(header)
        result, _ = unpack_header(data)
        assert result.original_filename == long_name

    def test_empty_filename(self):
        header = make_header(original_filename="")
        data = pack_header(header)
        result, offset = unpack_header(data)
        assert result.original_filename == ""
        assert offset == HEADER_FIXED_SIZE
