"""
Dedicated Crypto Module for Secure Digital Wallet (Backward Compatibility Facade).

Re-exports core AES-256-GCM encryption and decryption utilities
from `app.crypto_aes_gcm`.
"""

from app.crypto_aes_gcm import (
    CryptoError,
    InvalidKeyError,
    TamperedDataError,
    DecryptionError,
    generate_key,
    get_encryption_key,
    encrypt,
    decrypt,
    NONCE_LENGTH_BYTES,
    KEY_LENGTH_BYTES,
    TAG_LENGTH_BYTES,
)

__all__ = [
    "CryptoError",
    "InvalidKeyError",
    "TamperedDataError",
    "DecryptionError",
    "generate_key",
    "get_encryption_key",
    "encrypt",
    "decrypt",
    "NONCE_LENGTH_BYTES",
    "KEY_LENGTH_BYTES",
    "TAG_LENGTH_BYTES",
]
