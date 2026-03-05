"""Constants used throughout the file_storage package."""

MAGIC: bytes = b"FLSTRG\x00\x01"
FORMAT_VERSION: int = 1
HEADER_FIXED_SIZE: int = 44  # 8 + 2 + 16 + 4 + 12 + 2
AES_KEY_BITS: int = 256
NONCE_SIZE: int = 12
TAG_SIZE: int = 16
HMAC_SIZE: int = 32
HMAC_HKDF_INFO: bytes = b"file_storage_hmac_v1"
DEFAULT_KEYSTORE_DIR: str = "./data/keys"
ENV_KEYSTORE_DIR: str = "FILE_STORAGE_KEYSTORE"
ENC_EXTENSION: str = ".enc"

# RBAC defaults
ENV_CURRENT_USER: str = "FILE_STORAGE_USER"
ENV_DATA_DIR: str = "FILE_STORAGE_DATADIR"
DEFAULT_DATA_DIR: str = "./data"
DEFAULT_AUDIT_DIR: str = "./data/audit"
