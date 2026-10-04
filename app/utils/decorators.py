"""
Authentication Decorators Module.

Provides route protection helpers such as @login_required.
"""

from functools import wraps
from flask import flash, g, redirect, request, session, url_for, jsonify
from app.extensions import db
from app.models.user import User


def login_required(view_function):
    """
    Decorator that requires a valid active user session.
    Redirects unauthenticated browser requests to the login page
    and returns 401 Unauthorized for API/JSON requests.
    """
    @wraps(view_function)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        
        if not user_id:
            if (
                request.is_json 
                or request.path.startswith("/api/") 
                or request.accept_mimetypes.best == "application/json"
            ):
                return jsonify({"error": "Unauthorized", "message": "Authentication required."}), 401

            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.url))

        # Retrieve user from database and ensure the account is active
        user = db.session.get(User, user_id)
        if not user or not user.is_active:
            session.clear()
            flash("Your session is invalid or your account is deactivated. Please log in again.", "danger")
            return redirect(url_for("auth.login"))

        # Bind authenticated user to Flask's application context global `g`
        g.current_user = user
        return view_function(*args, **kwargs)

    return decorated_function
