"""
Configuration Module for Secure Digital Wallet.

Defines different environment profiles (Development, Testing, Production)
and manages database connection URLs, secret keys, and session settings.
"""

import os
from pathlib import Path

# Base directory: points to the root directory containing 'app' and 'instance'
BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"


class Config:
    """Base configuration shared across all environments."""
    
    # Secret key used for signing session cookies and CSRF tokens
    # In production, this must be a cryptographically random string loaded from .env
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-secret-key-change-me")
    
    # SQLite / SQLAlchemy settings
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Cookie security settings (defense-in-depth)
    SESSION_COOKIE_HTTPONLY = True    # Mitigates XSS cookie theft
    SESSION_COOKIE_SAMESITE = "Lax"   # Mitigates Cross-Site Request Forgery
    SESSION_COOKIE_SECURE = False     # Set to True when HTTPS is enabled

    # AES-256-GCM encryption key for sensitive demonstration data (must be 32 bytes)
    # Loaded from environment variable; never hard-coded in source code
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")


class DevelopmentConfig(Config):
    """Configuration for local development."""
    
    DEBUG = True
    default_db_path = (INSTANCE_DIR / "wallet.sqlite").as_posix()
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", 
        f"sqlite:///{default_db_path}"
    )


class TestingConfig(Config):
    """Configuration for automated test suite (pytest)."""
    
    TESTING = True
    DEBUG = True
    # In-memory SQLite database ensures fast, isolated, non-persistent test runs
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    
    # Disable CSRF token checks during automated testing to simplify test requests
    WTF_CSRF_ENABLED = False

    # Dedicated 256-bit test key for cryptographic tests (Base64 of 32 bytes)
    ENCRYPTION_KEY = os.environ.get(
        "ENCRYPTION_KEY", 
        "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
    )


class ProductionConfig(Config):
    """Configuration for production deployment."""
    
    DEBUG = False
    TESTING = False
    
    # Require HTTPS for cookies in production
    SESSION_COOKIE_SECURE = True
    
    default_db_path = (INSTANCE_DIR / "wallet_prod.sqlite").as_posix()
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", 
        f"sqlite:///{default_db_path}"
    )
    
    # In production, ENCRYPTION_KEY MUST be provided via environment variable
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")


# Lookup dictionary to easily fetch config class by environment name
config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
