"""
Demo Card Model for Simulated Sensitive Payment Metadata.

Educational Simulation Only:
- Demonstrates AES-256-GCM encryption of sensitive data at rest.
- Strictly forbids storing real card numbers or CVVs.
- Only stores masked PANs (e.g. '**** **** **** 1234') for safe UI display.
- Sensitive demonstration billing metadata is encrypted before persistence.
"""

from datetime import datetime
from app.extensions import db
from app.crypto_aes_gcm import encrypt, decrypt


class DemoCard(db.Model):
    """
    Represents a simulated payment method with AES-256-GCM encrypted metadata.
    
    Security & Educational Architecture:
    1. Zero CVV Storage: CVVs are NEVER accepted or persisted.
    2. Zero Real PAN Storage: Only masked numbers (last 4 digits visible) are stored.
    3. Encrypted Payload: Billing details (e.g., demo address, bank note) are encrypted
       using AES-256-GCM with a unique 12-byte nonce per record.
    4. Representation Safety: __repr__ never leaks encrypted or decrypted data.
    """
    __tablename__ = "demo_cards"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, 
        db.ForeignKey("users.id", ondelete="CASCADE"), 
        nullable=False, 
        index=True
    )
    cardholder_name = db.Column(db.String(100), nullable=False)
    card_brand = db.Column(db.String(20), nullable=False, default="Visa")
    masked_pan = db.Column(db.String(25), nullable=False)
    encrypted_billing_details = db.Column(db.Text, nullable=False)
    exp_month = db.Column(db.Integer, nullable=False)
    exp_year = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationship to User
    user = db.relationship(
        "User", 
        backref=db.backref("demo_cards", lazy="dynamic", cascade="all, delete-orphan")
    )

    def set_billing_details(self, plaintext_details: str) -> None:
        """
        Encrypts simulated billing details with AES-256-GCM and sets the ciphertext.
        """
        if not plaintext_details:
            plaintext_details = "No simulated billing details provided."
        self.encrypted_billing_details = encrypt(plaintext_details)

    def get_billing_details(self) -> str:
        """
        Decrypts the AES-256-GCM ciphertext and verifies the authentication tag.
        
        Returns:
            str: Decrypted plaintext billing details.
            
        Raises:
            TamperedDataError: If the ciphertext has been modified or corrupted.
            DecryptionError: If decryption fails.
        """
        return decrypt(self.encrypted_billing_details)

    def __repr__(self) -> str:
        """
        Defensive string representation: Never prints decrypted data or full details.
        """
        return (
            f"<DemoCard id={self.id} user_id={self.user_id} "
            f"brand='{self.card_brand}' masked='{self.masked_pan}'>"
        )
