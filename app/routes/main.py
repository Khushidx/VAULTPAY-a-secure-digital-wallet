"""
Main Blueprint.

Contains general routes including the Home page and System Health endpoint.
"""

from datetime import datetime, timezone
from flask import Blueprint, jsonify, render_template, redirect, url_for
from sqlalchemy import text

from app.extensions import db
from app.utils.decorators import login_required

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """
    Renders the Welcome / Landing page explaining the Educational
    Digital Wallet simulation and safety boundaries.
    """
    return render_template("main/index.html")


@main_bp.route("/crypto-architecture")
@main_bp.route("/architecture")
@login_required
def crypto_architecture():
    """
    Renders the overall cryptographic architecture specification page.
    Restricted to authenticated users only.
    """
    return render_template("main/architecture.html")


@main_bp.route("/health")
def health_check():
    """
    System Health Check endpoint.
    
    Verifies that:
    1. The Flask application is running.
    2. The SQLite database connection is functional.
    
    Returns:
        JSON response with 200 OK on success, or 503 on database failure.
    """
    db_status = "unknown"
    http_code = 200
    
    try:
        # Run a lightweight query to verify SQLite responsiveness
        result = db.session.execute(text("SELECT 1")).scalar()
        if result == 1:
            db_status = "connected"
    except Exception as err:
        db_status = f"disconnected: {str(err)}"
        http_code = 503

    payload = {
        "status": "healthy" if http_code == 200 else "unhealthy",
        "app": "Secure Digital Wallet",
        "mode": "active",
        "database": db_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    
    return jsonify(payload), http_code
