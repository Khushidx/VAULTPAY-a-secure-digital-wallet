"""
Wallet Forms.

Defines WTF Forms for wallet actions such as simulated deposits.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length


class DepositForm(FlaskForm):
    """Form for wallet deposit."""
    amount = StringField(
        "Deposit Amount (₹)",
        validators=[
            DataRequired(message="Please enter a deposit amount."),
            Length(max=20, message="Amount string is too long.")
        ]
    )
    description = StringField(
        "Note / Description (Optional)",
        validators=[Length(max=255, message="Description cannot exceed 255 characters.")],
        default="Deposit"
    )
    submit = SubmitField("Deposit Funds")


class TransferForm(FlaskForm):
    """Form for peer-to-peer money transfers."""
    recipient = StringField(
        "Recipient Username or Email",
        validators=[
            DataRequired(message="Recipient username or email is required."),
            Length(max=120, message="Recipient identifier is too long.")
        ]
    )
    amount = StringField(
        "Transfer Amount (₹)",
        validators=[
            DataRequired(message="Please enter a transfer amount."),
            Length(max=20, message="Amount string is too long.")
        ]
    )
    note = StringField(
        "Note / Memo (Optional)",
        validators=[Length(max=255, message="Note cannot exceed 255 characters.")],
        default="P2P Transfer"
    )
    submit = SubmitField("Send Transfer")

