"""Binary header pack/unpack for encrypted file format."""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass

from file_storage.constants import FORMAT_VERSION, HEADER_FIXED_SIZE, MAGIC
from file_storage.errors import InvalidFileFormatError, UnsupportedVersionError


@dataclass
class FileHeader:
    """Represents the header of an encrypted file."""

    key_id: uuid.UUID
    key_version: int
    nonce: bytes
    original_filename: str


def pack_header(header: FileHeader) -> bytes:
    """Pack a FileHeader into bytes.

    Format: magic(8) + version(2) + key_id(16) + key_version(4) + nonce(12) + fname_len(2) + fname(var)
    """
    filename_bytes = header.original_filename.encode("utf-8")
    fixed = struct.pack(
        "!8sH16sI12sH",
        MAGIC,
        FORMAT_VERSION,
        header.key_id.bytes,
        header.key_version,
        header.nonce,
        len(filename_bytes),
    )
    return fixed + filename_bytes


def unpack_header(data: bytes) -> tuple[FileHeader, int]:
    """Unpack a FileHeader from bytes.

    Returns (header, offset) where offset is the byte position after the header.
    """
    if len(data) < HEADER_FIXED_SIZE:
        raise InvalidFileFormatError("File too small to contain a valid header")

    if data[:8] != MAGIC:
        raise InvalidFileFormatError("Not a valid File_storage encrypted file")

    magic, version, key_id_bytes, key_ver, nonce, fname_len = struct.unpack(
        "!8sH16sI12sH", data[:HEADER_FIXED_SIZE]
    )

    if version != FORMAT_VERSION:
        raise UnsupportedVersionError(f"Format version {version} not supported")

    header_end = HEADER_FIXED_SIZE + fname_len
    if len(data) < header_end:
        raise InvalidFileFormatError("File truncated: incomplete filename")

    filename = data[HEADER_FIXED_SIZE:header_end].decode("utf-8")

    header = FileHeader(
        key_id=uuid.UUID(bytes=key_id_bytes),
        key_version=key_ver,
        nonce=nonce,
        original_filename=filename,
    )
    return header, header_end
