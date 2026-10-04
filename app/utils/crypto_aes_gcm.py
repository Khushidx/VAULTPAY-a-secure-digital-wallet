"""
Cryptographic Service Module - AES-256-GCM AEAD.

Implements AES-256-GCM (Authenticated Encryption with Associated Data - AEAD)
for encrypting and decrypting sensitive demonstration data (simulated payment metadata).

Guarantees:
1. Confidentiality: 256-bit symmetric encryption using AES.
2. Authenticity & Integrity: 128-bit authentication tag verified on every decryption.
3. Fresh Nonce: 96-bit (12-byte) cryptographically secure random nonce per operation.
4. Defense Against Tampering: Any bit modification in ciphertext, tag, or nonce causes
   immediate rejection via TamperedDataError.
5. Authenticated Associated Data (AAD): Binds caller data (e.g. 4-digit security PIN)
   cryptographically to the ciphertext.
"""

import base64
import os
import secrets
from typing import Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app, has_app_context


# Standard NIST recommended nonce size for AES-GCM is 12 bytes (96 bits)
NONCE_LENGTH_BYTES = 12
# AES-256 requires exactly 32 bytes (256 bits) key length
KEY_LENGTH_BYTES = 32
# GCM authentication tag length is 16 bytes (128 bits)
TAG_LENGTH_BYTES = 16


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class InvalidKeyError(CryptoError):
    """Raised when an encryption key is missing, invalid, or of incorrect length."""
    pass


class TamperedDataError(CryptoError):
    """
    Raised when ciphertext integrity or authentication tag verification fails.
    Indicates that ciphertext, nonce, or associated data was altered or corrupted.
    """
    pass


class DecryptionError(CryptoError):
    """Raised when payload decoding or format unpacking fails."""
    pass


def generate_key() -> str:
    """
    Generates a cryptographically secure 256-bit (32-byte) random encryption key.
    
    Returns:
        str: Base64-encoded 32-byte encryption key suitable for storage in environment variables.
    """
    random_bytes = secrets.token_bytes(KEY_LENGTH_BYTES)
    return base64.b64encode(random_bytes).decode("utf-8")


def get_encryption_key(custom_key: Optional[Union[bytes, str]] = None) -> bytes:
    """
    Retrieves and validates a 32-byte (256-bit) encryption key.
    
    Order of precedence:
    1. Explicitly provided `custom_key` argument.
    2. Flask application configuration (`current_app.config["ENCRYPTION_KEY"]`).
    3. Operating system environment variable (`os.environ["ENCRYPTION_KEY"]`).
    
    Args:
        custom_key: Optional explicit key as bytes or base64 string.
        
    Returns:
        bytes: Exactly 32 bytes of raw key material.
        
    Raises:
        InvalidKeyError: If the key cannot be found or is not exactly 32 bytes.
    """
    raw_key_str_or_bytes = custom_key

    if raw_key_str_or_bytes is None:
        if has_app_context():
            raw_key_str_or_bytes = current_app.config.get("ENCRYPTION_KEY")
        if not raw_key_str_or_bytes:
            raw_key_str_or_bytes = os.environ.get("ENCRYPTION_KEY")

    if not raw_key_str_or_bytes:
        raise InvalidKeyError(
            "ENCRYPTION_KEY is not set in environment or application configuration. "
            "Never hard-code encryption keys in source code."
        )

    # Process key if provided as string
    if isinstance(raw_key_str_or_bytes, str):
        raw_key_str = raw_key_str_or_bytes.strip()
        # Attempt base64 decoding first
        try:
            decoded = base64.b64decode(raw_key_str, validate=True)
            if len(decoded) == KEY_LENGTH_BYTES:
                return decoded
        except Exception:
            pass

        # Fallback: check if raw string length is exactly 32 bytes
        encoded = raw_key_str.encode("utf-8")
        if len(encoded) == KEY_LENGTH_BYTES:
            return encoded
        raise InvalidKeyError(
            f"Encryption key must be exactly {KEY_LENGTH_BYTES} bytes (256 bits). "
            f"Provided key decoded to {len(encoded)} bytes."
        )

    # Process key if provided as bytes
    if isinstance(raw_key_str_or_bytes, bytes):
        if len(raw_key_str_or_bytes) == KEY_LENGTH_BYTES:
            return raw_key_str_or_bytes
        # Attempt base64 decoding
        try:
            decoded = base64.b64decode(raw_key_str_or_bytes, validate=True)
            if len(decoded) == KEY_LENGTH_BYTES:
                return decoded
        except Exception:
            pass
        raise InvalidKeyError(
            f"Encryption key must be exactly {KEY_LENGTH_BYTES} bytes (256 bits). "
            f"Provided bytes had length {len(raw_key_str_or_bytes)}."
        )

    raise InvalidKeyError("Encryption key must be a string or bytes.")


def encrypt(
    plaintext: Union[str, bytes],
    key: Optional[Union[bytes, str]] = None,
    associated_data: Optional[bytes] = None,
) -> str:
    """
    Encrypts plaintext using AES-256-GCM authenticated encryption.
    
    A fresh 12-byte (96-bit) cryptographically random nonce is generated for
    EVERY single encryption operation. The resulting payload packages:
        [ Nonce (12 bytes) ] + [ Ciphertext ] + [ Authentication Tag (16 bytes) ]
    encoded as a URL-safe Base64 string for safe database storage.
    
    Args:
        plaintext (str | bytes): Sensitive data to encrypt.
        key (bytes | str, optional): 256-bit encryption key (defaults to config/env).
        associated_data (bytes, optional): Authenticated Associated Data (AAD).
        
    Returns:
        str: Base64-encoded string containing (nonce + ciphertext + auth_tag).
        
    Raises:
        InvalidKeyError: If the encryption key is missing or invalid.
        CryptoError: If encryption fails.
    """
    if plaintext is None:
        raise ValueError("Cannot encrypt None plaintext.")

    raw_key = get_encryption_key(key)

    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode("utf-8")
    elif isinstance(plaintext, bytes):
        plaintext_bytes = plaintext
    else:
        raise TypeError("Plaintext must be str or bytes.")

    try:
        # Generate fresh, unique 12-byte nonce (NIST SP 800-38D requirement)
        nonce = os.urandom(NONCE_LENGTH_BYTES)
        
        # Initialize AES-GCM cipher with 256-bit key
        aesgcm = AESGCM(raw_key)
        
        # Encrypt: AESGCM.encrypt appends 16-byte authentication tag to ciphertext
        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)
        
        # Package nonce + ciphertext_and_tag into unified payload
        packaged_payload = nonce + ciphertext_and_tag
        
        return base64.b64encode(packaged_payload).decode("utf-8")

    except Exception as e:
        if isinstance(e, CryptoError):
            raise
        raise CryptoError(f"Encryption operation failed: {str(e)}") from e


def decrypt(
    encrypted_payload: Union[str, bytes],
    key: Optional[Union[bytes, str]] = None,
    associated_data: Optional[bytes] = None,
) -> str:
    """
    Decrypts an AES-256-GCM payload and verifies its cryptographic authentication tag.
    
    Decodes the Base64 payload, extracts the 12-byte nonce, and invokes AES-GCM
    decryption with tag verification. If any bit of the ciphertext, tag, nonce,
    or associated data was modified, decryption fails with TamperedDataError.
    
    Args:
        encrypted_payload (str | bytes): Base64-encoded (nonce + ciphertext + tag).
        key (bytes | str, optional): 256-bit encryption key (defaults to config/env).
        associated_data (bytes, optional): Authenticated Associated Data (AAD).
        
    Returns:
        str: Decrypted plaintext string.
        
    Raises:
        TamperedDataError: If ciphertext, tag, or nonce has been altered (tag check fails).
        DecryptionError: If the payload is malformed, truncated, or invalid Base64.
        InvalidKeyError: If the encryption key is missing or invalid.
    """
    if not encrypted_payload:
        raise ValueError("Cannot decrypt empty or None payload.")

    raw_key = get_encryption_key(key)

    # Decode Base64 payload
    try:
        if isinstance(encrypted_payload, str):
            payload_bytes = base64.b64decode(encrypted_payload.strip(), validate=True)
        elif isinstance(encrypted_payload, bytes):
            payload_bytes = base64.b64decode(encrypted_payload, validate=True)
        else:
            raise TypeError("Encrypted payload must be str or bytes.")
    except Exception as e:
        raise DecryptionError(f"Invalid Base64 payload: {str(e)}") from e

    # Minimum payload size: 12 bytes (nonce) + 16 bytes (tag) = 28 bytes
    min_required_len = NONCE_LENGTH_BYTES + TAG_LENGTH_BYTES
    if len(payload_bytes) < min_required_len:
        raise DecryptionError(
            f"Payload length ({len(payload_bytes)} bytes) is shorter than the minimum "
            f"required ({min_required_len} bytes) for nonce and authentication tag."
        )

    # Unpack components
    nonce = payload_bytes[:NONCE_LENGTH_BYTES]
    ciphertext_and_tag = payload_bytes[NONCE_LENGTH_BYTES:]

    try:
        aesgcm = AESGCM(raw_key)
        # AESGCM.decrypt validates the authentication tag against the ciphertext & AAD
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)
        return decrypted_bytes.decode("utf-8")

    except InvalidTag as e:
        # Cryptographic tag verification failure — ciphertext or nonce was tampered with!
        raise TamperedDataError(
            "Ciphertext integrity check failed: authentication tag mismatch. "
            "Data has been altered, corrupted, or decrypted with the wrong key."
        ) from e
    except UnicodeDecodeError as e:
        raise DecryptionError("Decrypted bytes could not be decoded as UTF-8 string.") from e
    except Exception as e:
        if isinstance(e, CryptoError):
            raise
        raise DecryptionError(f"Decryption failed: {str(e)}") from e
