"""
Payment Method Model for Simulated Payment Sources.

Educational Simulation Only:
- Represents simulated funding sources (Demo Visa, Demo Mastercard, Demo Bank Account).
- Never accepts or stores real financial credentials, real card numbers, or CVVs.
- Generates and stores opaque simulated tokens (tok_demo_...) similar to real payment gateways.
- Sensitive demonstration metadata is encrypted at rest using AES-256-GCM.
"""

from datetime import datetime
import json
from typing import Union, Optional
from app.extensions import db
from app.crypto_aes_gcm import encrypt, decrypt
from app.utils.password_sha256 import generate_salt, hash_password, verify_password


class PaymentMethod(db.Model):
    """
    Represents a simulated payment method attached to a user's wallet.
    
    Security & Architecture:
    1. Zero CVV: CVVs are NEVER accepted or stored.
    2. Zero Full PAN / Account Numbers: Only masked numbers (last 4 digits) are stored.
    3. Tokenization: Uses simulated tokens ('tok_demo_...') to abstract payment credentials.
    4. AES-256-GCM: Metadata (simulated routing/bank name/notes) is encrypted at rest.
    5. Representation Safety: __repr__ suppresses all secret/encrypted data.
    """
    __tablename__ = "payment_methods"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, 
        db.ForeignKey("users.id", ondelete="CASCADE"), 
        nullable=False, 
        index=True
    )
    method_type = db.Column(db.String(30), nullable=False)  # DEMO_VISA, DEMO_MASTERCARD, DEMO_BANK_ACCOUNT
    name = db.Column(db.String(100), nullable=False)        # User-friendly nickname
    token_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    masked_identifier = db.Column(db.String(50), nullable=False)
    encrypted_metadata = db.Column(db.Text, nullable=False)
    security_key_salt = db.Column(db.String(64), nullable=True)
    security_key_hash = db.Column(db.String(64), nullable=True)
    is_default = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationship to User
    user = db.relationship(
        "User", 
        backref=db.backref("payment_methods", lazy="dynamic", cascade="all, delete-orphan")
    )

    def set_security_key(self, key: str) -> None:
        """
        Hashes and stores the 4-digit security key using a fresh 256-bit salt.
        Never stores the security key in plaintext.
        """
        clean_key = str(key).strip()
        if not clean_key.isdigit() or len(clean_key) != 4:
            raise ValueError("Security key must be exactly 4 numeric digits.")
        self.security_key_salt = generate_salt(32)
        self.security_key_hash = hash_password(clean_key, self.security_key_salt)

    def verify_security_key(self, key: str) -> bool:
        """
        Constant-time verification of candidate 4-digit security key.
        """
        if not self.security_key_salt or not self.security_key_hash or not key:
            return False
        return verify_password(str(key).strip(), self.security_key_salt, self.security_key_hash)

    def set_metadata(self, metadata: Union[str, dict], security_key: Optional[str] = None) -> None:
        """
        Encrypts metadata with AES-256-GCM. If security_key is provided,
        it is cryptographically bound as Authenticated Associated Data (AAD).
        """
        if isinstance(metadata, dict):
            plaintext = json.dumps(metadata)
        elif isinstance(metadata, str):
            plaintext = metadata.strip()
        else:
            plaintext = "No metadata provided."

        aad = security_key.encode("utf-8") if security_key else None
        self.encrypted_metadata = encrypt(plaintext, associated_data=aad)

    def get_metadata(self, security_key: Optional[str] = None) -> Union[str, dict]:
        """
        Decrypts AES-256-GCM ciphertext and verifies authentication tag with AAD.
        
        Returns:
            dict or str: Decrypted plaintext metadata.
            
        Raises:
            TamperedDataError: If ciphertext integrity check or AAD check fails.
            DecryptionError: If decryption fails.
        """
        aad = security_key.encode("utf-8") if security_key else None
        decrypted_str = decrypt(self.encrypted_metadata, associated_data=aad)
        try:
            return json.loads(decrypted_str)
        except Exception:
            return decrypted_str

    def __repr__(self) -> str:
        """
        Defensive string representation: Never prints decrypted data or token secret material.
        """
        return (
            f"<PaymentMethod id={self.id} user_id={self.user_id} "
            f"type='{self.method_type}' masked='{self.masked_identifier}'>"
        )
