"""
Money Utility Module - Integer-Cent Exact Financial Arithmetic.

Enforces strict financial arithmetic rules to eliminate IEEE-754 floating-point errors:
1. All monetary values are represented and stored strictly as 64-bit integer cents (paise).
2. Floating-point numbers are NEVER used for financial calculations or storage.
3. Python `Decimal` is used strictly for safe parsing of user string input into integer cents.
"""

from decimal import Decimal, InvalidOperation, ROUND_HALF_UP


def parse_amount_to_cents(amount_input: str) -> tuple[bool, int, str]:
    """
    Parses and validates a user-provided monetary amount string into integer cents.
    
    Rules enforced:
    - Must be a valid numeric string.
    - Must be strictly greater than zero (rejects zero and negative amounts).
    - Cannot have more than 2 decimal places (no fractional cents).
    - Cannot exceed maximum limit (₹10,000,000.00).
    
    Args:
        amount_input (str): The raw string from the user form (e.g., "50.00").
        
    Returns:
        tuple[bool, int, str]: (is_valid, amount_cents, error_message)
    """
    if amount_input is None:
        return False, 0, "Amount is required."
        
    raw_str = str(amount_input).strip()
    if not raw_str:
        return False, 0, "Amount is required."

    try:
        dec = Decimal(raw_str)
    except (InvalidOperation, ValueError, TypeError):
        return False, 0, "Invalid amount format. Please enter a valid number (e.g., 25.50)."

    # Reject zero and negative amounts
    if dec <= Decimal("0"):
        return False, 0, "Amount must be strictly greater than zero (₹0.00)."

    # Enforce maximum of 2 decimal places
    # dec.as_tuple().exponent indicates the number of digits after the decimal point (e.g. -2 for 0.01)
    if dec.as_tuple().exponent < -2:
        return False, 0, "Amount cannot have more than 2 decimal places."

    # Reasonable upper ceiling to prevent overflow
    if dec > Decimal("10000000.00"):
        return False, 0, "Deposit cannot exceed ₹10,000,000.00 per transaction."

    # Convert to integer paise/cents using standard financial rounding
    cents_decimal = (dec * Decimal("100")).to_integral_value(rounding=ROUND_HALF_UP)
    cents = int(cents_decimal)

    return True, cents, ""


def format_cents(cents: int, currency: str = "INR") -> str:
    """
    Formats an integer amount of paise into a human-readable currency string with Indian Rupee symbol (₹).
    Example: 1050 paise -> "₹10.50"
    
    Args:
        cents (int): Amount in smallest currency unit (paise).
        currency (str): Currency code (defaults to 'INR').
        
    Returns:
        str: Formatted string (e.g., "₹1,234.56").
    """
    is_negative = cents < 0
    abs_cents = abs(cents)
    units = abs_cents // 100
    remainder = abs_cents % 100
    sign = "-" if is_negative else ""
    symbol = "₹"
    return f"{sign}{symbol}{units:,}.{remainder:02d}"
