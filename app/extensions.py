"""
Extensions Module.

Initializes Flask extensions without binding them to a specific app instance yet.
This prevents circular dependencies when importing models and routes.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

# Database ORM instance
db = SQLAlchemy()

# Cross-Site Request Forgery protection
csrf = CSRFProtect()
