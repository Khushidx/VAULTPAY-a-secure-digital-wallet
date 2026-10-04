"""
Salted SHA-256 Password and Security PIN Hashing Module.

Implements Salted SHA-256 password hashing and constant-time verification in
accordance with educational project specifications and cryptographic best practices.

Algorithm Workflow:
    Input Password / 4-Digit Numeric PIN
         +
    Cryptographically Secure 256-Bit Unique Salt (secrets.token_hex)
         ↓
    SHA-256 Digest Computation (hashlib.sha256)
         ↓
    64-Character Hexadecimal Digest
         ↓
    Constant-Time Verification (hmac.compare_digest)
"""

import hashlib
import hmac
import secrets


def generate_salt(num_bytes: int = 32) -> str:
    """
    Generates a cryptographically secure random unique salt.
    
    Uses Python's `secrets` module (backed by os.urandom / CryptGenRandom)
    to guarantee high-entropy randomness.
    
    Args:
        num_bytes (int): Number of random bytes to generate (default 32 bytes = 256 bits).
        
    Returns:
        str: Hexadecimal string representation of the random salt (64 characters).
    """
    return secrets.token_hex(num_bytes)


def hash_password(password: str, salt: str) -> str:
    """
    Computes the SHA-256 hash of (salt + password).
    
    Args:
        password (str): Plaintext password or PIN entered by user.
        salt (str): Hex-encoded unique random salt.
        
    Returns:
        str: 64-character hexadecimal SHA-256 digest.
        
    Raises:
        ValueError: If password or salt is empty/invalid.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    if not salt:
        raise ValueError("Salt cannot be empty.")
        
    hasher = hashlib.sha256()
    # Prepend the salt to the password bytes before hashing
    hasher.update(salt.encode("utf-8"))
    hasher.update(password.encode("utf-8"))
    return hasher.hexdigest()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """
    Verifies a plaintext password or PIN against a stored salt and expected hash.
    
    Uses constant-time comparison (`hmac.compare_digest`) to prevent
    timing side-channel attacks.
    
    Args:
        password (str): Plaintext password or PIN to verify.
        salt (str): Stored unique salt.
        expected_hash (str): Stored expected SHA-256 digest.
        
    Returns:
        bool: True if candidate hash matches expected_hash, False otherwise.
    """
    if not password or not salt or not expected_hash:
        return False
        
    candidate_hash = hash_password(password, salt)
    return hmac.compare_digest(candidate_hash, expected_hash)
