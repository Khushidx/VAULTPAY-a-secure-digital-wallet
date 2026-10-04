"""
User Model.

Represents a user account in the SQLite database.
Stores strictly necessary fields: identity, unique random salt,
and salted SHA-256 password hash. Plaintext passwords are NEVER stored.
"""

from datetime import datetime, timezone
from app.extensions import db
from app.utils.password_sha256 import generate_salt, hash_password, verify_password


class User(db.Model):
    """
    User account model.
    """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    
    # 64-character hexadecimal representation of SHA-256 digest
    password_hash = db.Column(db.String(64), nullable=False)
    
    # 64-character hexadecimal representation of 32-byte cryptographically secure random salt
    password_salt = db.Column(db.String(64), nullable=False)
    
    role = db.Column(db.String(20), nullable=False, default="user")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(
        db.DateTime, 
        nullable=False, 
        default=lambda: datetime.now(timezone.utc)
    )

    def set_password(self, password: str) -> None:
        """
        Generates a fresh unique cryptographically secure salt,
        computes the SHA-256 hash of (salt + password), and saves both.
        Plaintext passwords are never retained.
        """
        salt = generate_salt()
        self.password_salt = salt
        self.password_hash = hash_password(password, salt)

    def check_password(self, password: str) -> bool:
        """
        Verifies whether the provided plaintext password matches
        the stored hash using the user's unique salt.
        """
        if not self.password_salt or not self.password_hash:
            return False
        return verify_password(password, self.password_salt, self.password_hash)

    def __repr__(self) -> str:
        return f"<User id={self.id} username='{self.username}'>"
