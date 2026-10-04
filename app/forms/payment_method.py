"""
Payment Method Form Module.

Provides CSRF-protected forms for managing simulated payment methods.
Strictly disallows collecting real financial credentials or CVVs.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, BooleanField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, Regexp


class PaymentMethodForm(FlaskForm):
    """
    Form for adding a payment method.
    
    Security Controls:
    1. Zero CVV Collection: CVVs are NEVER requested.
    2. Zero Full Card / Bank Account Numbers: Only the LAST 4 digits are accepted.
    3. AES-256-GCM Encryption: Metadata is encrypted at rest.
    4. 4-Digit Security Key: Hashed with 256-bit salt, required for subsequent decryption.
    """
    method_type = SelectField(
        "Payment Method Type",
        choices=[
            ("DEMO_VISA", "💳 Visa"),
            ("DEMO_MASTERCARD", "💳 Mastercard"),
            ("DEMO_BANK_ACCOUNT", "🏦 Bank Account"),
        ],
        default="DEMO_VISA",
        validators=[DataRequired()],
    )

    name = StringField(
        "Nickname / Label",
        validators=[
            DataRequired(message="A nickname is required."),
            Length(min=2, max=100, message="Name must be between 2 and 100 characters."),
        ],
        render_kw={"placeholder": "e.g. Primary Savings or Visa Card"},
    )

    last_four = StringField(
        "Last 4 Digits Only",
        validators=[
            DataRequired(message="Last 4 digits are required."),
            Length(min=4, max=4, message="Must be exactly 4 digits."),
            Regexp(r"^\d{4}$", message="Must contain exactly 4 numeric digits."),
        ],
        render_kw={
            "placeholder": "e.g. 4242",
            "maxlength": "4",
            "autocomplete": "off",
        },
    )

    security_key = PasswordField(
        "4-Digit Security Key (PIN)",
        validators=[
            DataRequired(message="A 4-digit numeric security key is required."),
            Length(min=4, max=4, message="Security key must be exactly 4 digits."),
            Regexp(r"^\d{4}$", message="Security key must contain exactly 4 numeric digits."),
        ],
        render_kw={
            "placeholder": "4-digit PIN (e.g. 1234)",
            "maxlength": "4",
            "autocomplete": "off",
            "inputmode": "numeric",
        },
    )

    demo_metadata = TextAreaField(
        "Encrypted Metadata (AES-256-GCM)",
        validators=[Length(max=500, message="Metadata cannot exceed 500 characters.")],
        render_kw={
            "placeholder": "Enter details (e.g. Bank Name, Branch Code, or Notes). This will be encrypted with AES-256-GCM.",
            "rows": 3,
        },
    )

    is_default = BooleanField("Set as default payment method")

    submit = SubmitField("Save Payment Method")


class RevealSecurityForm(FlaskForm):
    """
    Step-up authentication challenge form for decrypting payment method metadata.
    Requires user account password and the 4-digit security PIN set when adding the method.
    """
    password = PasswordField(
        "Account Password",
        validators=[DataRequired(message="Account password is required.")],
        render_kw={
            "placeholder": "Enter your account password",
            "autocomplete": "current-password",
        },
    )

    security_key = PasswordField(
        "4-Digit Security Key",
        validators=[
            DataRequired(message="4-digit security key is required."),
            Length(min=4, max=4, message="Security key must be exactly 4 digits."),
            Regexp(r"^\d{4}$", message="Security key must contain exactly 4 numeric digits."),
        ],
        render_kw={
            "placeholder": "Enter 4-digit PIN (e.g. 1234)",
            "maxlength": "4",
            "autocomplete": "off",
            "inputmode": "numeric",
        },
    )

    submit = SubmitField("Verify & Decrypt Metadata")
