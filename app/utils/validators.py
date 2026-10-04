"""
Input Validation Module.

Enforces defensive validation rules on user registration and login inputs
to prevent malformed data, injection attempts, and weak passwords.
"""

import re

# Regex patterns for input validation
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,30}$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_username(username: str) -> tuple[bool, str]:
    """
    Validates username format.
    Must be 3 to 30 characters containing only letters, numbers, and underscores.
    """
    if not username or not username.strip():
        return False, "Username is required."
    username = username.strip()
    if not USERNAME_REGEX.match(username):
        return False, "Username must be 3-30 characters long and contain only letters, numbers, and underscores."
    return True, ""


def validate_email(email: str) -> tuple[bool, str]:
    """
    Validates email format and length.
    """
    if not email or not email.strip():
        return False, "Email address is required."
    email = email.strip()
    if len(email) > 120:
        return False, "Email address is too long (maximum 120 characters)."
    if not EMAIL_REGEX.match(email):
        return False, "Please enter a valid email address."
    return True, ""


def validate_password(password: str) -> tuple[bool, str]:
    """
    Validates password strength.
    Requires at least 8 characters, at least one uppercase letter,
    at least one lowercase letter, and at least one digit.
    """
    if not password:
        return False, "Password is required."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    return True, ""


def validate_registration(
    username: str, 
    email: str, 
    password: str, 
    confirm_password: str
) -> tuple[bool, str]:
    """
    Validates all registration fields.
    """
    valid, err = validate_username(username)
    if not valid:
        return False, err

    valid, err = validate_email(email)
    if not valid:
        return False, err

    valid, err = validate_password(password)
    if not valid:
        return False, err

    if password != confirm_password:
        return False, "Passwords do not match."

    return True, ""
