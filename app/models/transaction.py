"""
Transaction Model.

Represents an immutable ledger record of any balance change.
Stores reference IDs, transaction types, integer cents, and statuses.
"""

import uuid
from datetime import datetime, timezone
from app.extensions import db
from app.utils.money_integer_cents import format_cents


class Transaction(db.Model):
    """
    Financial transaction ledger entry.
    """
    __tablename__ = "transactions"

    id = db.Column(db.Integer, primary_key=True)
    
    # UUID reference ID for external tracking and idempotency
    reference_id = db.Column(
        db.String(36), 
        unique=True, 
        nullable=False, 
        index=True,
        default=lambda: str(uuid.uuid4())
    )
    
    wallet_id = db.Column(
        db.Integer, 
        db.ForeignKey("wallets.id", ondelete="CASCADE"), 
        nullable=False, 
        index=True
    )
    
    # Amount stored strictly in cents (positive for deposits/credits)
    amount_cents = db.Column(db.Integer, nullable=False)
    
    # Transaction type: 'DEPOSIT', 'WITHDRAWAL', 'TRANSFER_IN', 'TRANSFER_OUT'
    transaction_type = db.Column(db.String(20), nullable=False)
    
    # Status: 'COMPLETED', 'PENDING', 'FAILED'
    status = db.Column(db.String(20), nullable=False, default="COMPLETED")
    
    description = db.Column(db.String(255), nullable=True)
    
    created_at = db.Column(
        db.DateTime, 
        nullable=False, 
        default=lambda: datetime.now(timezone.utc)
    )

    # Relationship to Wallet
    wallet = db.relationship(
        "Wallet", 
        backref=db.backref("transactions", lazy="dynamic", order_by="desc(Transaction.created_at)")
    )

    @property
    def formatted_amount(self) -> str:
        """Returns the formatted monetary amount for UI display."""
        return format_cents(self.amount_cents)

    def __repr__(self) -> str:
        return (
            f"<Transaction id={self.id} ref='{self.reference_id}' "
            f"type='{self.transaction_type}' amount_cents={self.amount_cents} status='{self.status}'>"
        )
