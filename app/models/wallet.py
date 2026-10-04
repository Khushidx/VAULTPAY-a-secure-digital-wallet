"""
Wallet Model.

Stores simulated user wallet account details and balances.
Enforces integer-cent representation and database-level non-negative balance constraints.
"""

from datetime import datetime, timezone
from app.extensions import db
from app.utils.money_integer_cents import format_cents


class Wallet(db.Model):
    """
    User Wallet model representing a simulated financial account.
    """
    __tablename__ = "wallets"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, 
        db.ForeignKey("users.id", ondelete="CASCADE"), 
        unique=True, 
        nullable=False, 
        index=True
    )
    
    # Balance stored strictly as integer units (e.g., ₹10.00 = 1000 paise/cents)
    balance_cents = db.Column(db.Integer, nullable=False, default=0)
    currency = db.Column(db.String(3), nullable=False, default="INR")
    
    created_at = db.Column(
        db.DateTime, 
        nullable=False, 
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at = db.Column(
        db.DateTime, 
        nullable=False, 
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    # Database-level constraint to guarantee balance can never go below zero
    __table_args__ = (
        db.CheckConstraint("balance_cents >= 0", name="check_wallet_balance_non_negative"),
    )

    # Relationship to User (one-to-one)
    user = db.relationship(
        "User", 
        backref=db.backref("wallet", uselist=False, cascade="all, delete-orphan")
    )

    @property
    def formatted_balance(self) -> str:
        """Returns balance formatted as currency string for UI display."""
        return format_cents(self.balance_cents, "INR")

    def __repr__(self) -> str:
        return f"<Wallet id={self.id} user_id={self.user_id} balance_cents={self.balance_cents}>"
