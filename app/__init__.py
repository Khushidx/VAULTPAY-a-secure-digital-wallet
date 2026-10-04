"""
Application Factory for Secure Digital Wallet.

Initializes the Flask app, configures the database, loads extensions,
registers blueprints, and applies security response headers.
"""

import os
from pathlib import Path
from flask import Flask

from app.config import config_by_name, INSTANCE_DIR
from app.extensions import db, csrf
from app.errors import register_error_handlers
from app.routes.main import main_bp
from app.routes.auth import auth_bp
from app.routes.wallet import wallet_bp
from app.routes.cards import cards_bp
from app.routes.payment_methods import payment_methods_bp
from app.routes.security_lab import security_lab_bp
import app.models  # Ensure models are discovered by SQLAlchemy before create_all()


def create_app(config_name=None):
    """
    Flask Application Factory.
    
    Args:
        config_name (str, optional): 'development', 'testing', or 'production'.
            Defaults to the FLASK_ENV environment variable or 'development'.
            
    Returns:
        Flask: The fully configured Flask application instance.
    """
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "development")

    # Initialize Flask app instance
    app = Flask(
        __name__,
        instance_path=str(INSTANCE_DIR),
        instance_relative_config=True,
    )

    # Load configuration
    config_class = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(config_class)

    # Ensure the instance folder exists for the SQLite database file
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)

    # Register Blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(wallet_bp)
    app.register_blueprint(cards_bp)
    app.register_blueprint(payment_methods_bp)
    app.register_blueprint(security_lab_bp)

    # Register custom error handlers
    register_error_handlers(app)

    # Add security HTTP headers to all outgoing responses (Defense-in-Depth)
    @app.after_request
    def set_security_headers(response):
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent clickjacking by forbidding embedding in iframes
        response.headers["X-Frame-Options"] = "DENY"
        # Control referrer information leak
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # Create SQLite database tables if they do not exist
    with app.app_context():
        db.create_all()

        # Automatically ensure existing SQLite tables have newly added columns
        try:
            with db.engine.connect() as conn:
                # payment_methods table
                res = conn.exec_driver_sql("PRAGMA table_info(payment_methods);").fetchall()
                existing_pm_cols = {row[1] for row in res}
                if existing_pm_cols:
                    if "security_key_salt" not in existing_pm_cols:
                        conn.exec_driver_sql("ALTER TABLE payment_methods ADD COLUMN security_key_salt VARCHAR(64);")
                    if "security_key_hash" not in existing_pm_cols:
                        conn.exec_driver_sql("ALTER TABLE payment_methods ADD COLUMN security_key_hash VARCHAR(64);")
                    conn.commit()

                # wallets table
                wallet_res = conn.exec_driver_sql("PRAGMA table_info(wallets);").fetchall()
                wallet_cols = {row[1] for row in wallet_res}
                if wallet_cols and "currency" not in wallet_cols:
                    conn.exec_driver_sql("ALTER TABLE wallets ADD COLUMN currency VARCHAR(3) DEFAULT 'INR';")
                    conn.commit()
        except Exception:
            pass

        # Automatically ensure all existing wallets have currency set to INR
        try:
            from app.models.wallet import Wallet
            Wallet.query.filter(Wallet.currency != "INR").update({"currency": "INR"})
            db.session.commit()
        except Exception:
            db.session.rollback()

    return app
