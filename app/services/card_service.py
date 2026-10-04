"""
Demo Card Service Module.

Manages simulated payment methods with AES-256-GCM encrypted metadata.
Strictly adheres to PCI-DSS educational boundaries:
- ZERO real card numbers.
- ZERO CVV storage.
- All sensitive simulated billing details encrypted at rest.
- Strict IDOR defense: operations are scoped to the authenticated user ID.
"""

from datetime import datetime
from app.extensions import db
from app.models.card import DemoCard
from app.models.user import User


def create_demo_card(
    user_id: int,
    cardholder_name: str,
    last_four: str,
    card_brand: str,
    exp_month: int,
    exp_year: int,
    billing_details: str = "",
) -> DemoCard:
    """
    Creates and persists a simulated demo card with encrypted billing metadata.
    
    Args:
        user_id (int): ID of the card owner.
        cardholder_name (str): Simulated cardholder name.
        last_four (str): Exactly 4 digits representing the card ending.
        card_brand (str): Card network brand (e.g. Visa, Mastercard, Amex).
        exp_month (int): Expiration month (1-12).
        exp_year (int): Expiration year (e.g. 2028).
        billing_details (str): Sensitive simulated billing address or notes to encrypt.
        
    Returns:
        DemoCard: The created and committed card record.
        
    Raises:
        ValueError: If inputs violate safety or validation rules.
    """
    user = db.session.get(User, user_id)
    if not user:
        raise ValueError("User not found.")

    clean_name = cardholder_name.strip()
    if not clean_name or len(clean_name) > 100:
        raise ValueError("Cardholder name must be between 1 and 100 characters.")

    # Strict check on last_four: exactly 4 numeric digits
    clean_last_four = str(last_four).strip()
    if not clean_last_four.isdigit() or len(clean_last_four) != 4:
        raise ValueError(
            "For security and PCI-DSS simulation compliance, only provide the LAST 4 digits. "
            "Never enter a full card number."
        )

    # Validate expiration month and year
    if not isinstance(exp_month, int) or not (1 <= exp_month <= 12):
        raise ValueError("Expiration month must be an integer between 1 and 12.")

    current_year = datetime.utcnow().year
    if not isinstance(exp_year, int) or exp_year < current_year or exp_year > current_year + 25:
        raise ValueError(f"Expiration year must be between {current_year} and {current_year + 25}.")

    # Validate brand
    valid_brands = ["Visa", "Mastercard", "American Express", "Discover"]
    brand = card_brand.strip()
    if brand not in valid_brands:
        brand = "Visa"

    masked_pan = f"**** **** **** {clean_last_four}"

    card = DemoCard(
        user_id=user_id,
        cardholder_name=clean_name,
        card_brand=brand,
        masked_pan=masked_pan,
        exp_month=exp_month,
        exp_year=exp_year,
    )
    # Encrypt the sensitive simulated billing details using AES-256-GCM
    card.set_billing_details(billing_details.strip() if billing_details else "Simulated Billing Address")

    db.session.add(card)
    db.session.commit()
    return card


def get_user_cards(user_id: int) -> list[DemoCard]:
    """
    Retrieves all demo cards belonging to the specified user.
    Enforces authorization boundary (IDOR defense).
    """
    return (
        DemoCard.query.filter_by(user_id=user_id)
        .order_by(DemoCard.created_at.desc())
        .all()
    )


def get_decrypted_card_details(user_id: int, card_id: int) -> tuple[DemoCard, str]:
    """
    Retrieves a card and decrypts its sensitive billing metadata.
    Enforces IDOR defense by strictly querying user_id and card_id together.
    
    Returns:
        tuple[DemoCard, str]: The card entity and decrypted plaintext billing details.
        
    Raises:
        ValueError: If card does not exist or does not belong to the user.
    """
    card = DemoCard.query.filter_by(id=card_id, user_id=user_id).first()
    if not card:
        raise ValueError("Card not found or you are not authorized to view it.")

    decrypted_details = card.get_billing_details()
    return card, decrypted_details


def delete_demo_card(user_id: int, card_id: int) -> bool:
    """
    Deletes a demo card belonging to the specified user.
    """
    card = DemoCard.query.filter_by(id=card_id, user_id=user_id).first()
    if not card:
        raise ValueError("Card not found or you are not authorized to delete it.")

    db.session.delete(card)
    db.session.commit()
    return True
