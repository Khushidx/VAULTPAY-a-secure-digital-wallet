"""
Application Entry Point for Secure Digital Wallet.

Loads environment variables from .env using python-dotenv,
initializes the Flask application via the Application Factory,
and starts the local development server.
"""

import os
from dotenv import load_dotenv

# Load variables from .env file into os.environ
load_dotenv()

from app import create_app

# Determine environment from FLASK_ENV or default to development
env_name = os.getenv("FLASK_ENV", "development")
app = create_app(env_name)

if __name__ == "__main__":
    # Host 127.0.0.1 limits connections to local loopback (safe for development)
    # Port 5000 is the standard Flask development server port
    print(f"[*] Starting VaultPay ({env_name} mode)...")
    print("[*] Server running at: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
