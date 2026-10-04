"""
Password Utility Module (Backward Compatibility Facade).

Re-exports core Salted SHA-256 hashing and verification routines
from `app.utils.password_sha256`.
"""

from app.utils.password_sha256 import (
    generate_salt,
    hash_password,
    verify_password,
)

__all__ = [
    "generate_salt",
    "hash_password",
    "verify_password",
]
