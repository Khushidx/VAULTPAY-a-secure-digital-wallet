"""
Dedicated Crypto Module for VaultPay - AES-256-GCM AEAD.

Provides explicit access to core AES-256-GCM authenticated encryption and decryption
utilities, nonce/tag specifications, and cryptographic exceptions.
"""

from app.utils.crypto_aes_gcm import (
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
