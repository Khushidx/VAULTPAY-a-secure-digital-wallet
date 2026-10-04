"""
Authentication Forms.

Defines WTF Forms for user registration and login,
with automatic CSRF protection and field validation.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Regexp, Length, EqualTo


class RegistrationForm(FlaskForm):
    """Form for new user registration."""
    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Username is required."),
            Length(min=3, max=30, message="Username must be between 3 and 30 characters.")
        ]
    )
    email = StringField(
        "Email Address",
        validators=[
            DataRequired(message="Email address is required."),
            Regexp(
                r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$",
                message="Please provide a valid email address."
            ),
            Length(max=120, message="Email address is too long.")
        ]
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Password is required."),
            Length(min=8, max=128, message="Password must be at least 8 characters.")
        ]
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(message="Please confirm your password."),
            EqualTo("password", message="Passwords must match.")
        ]
    )
    submit = SubmitField("Create Account")


class LoginForm(FlaskForm):
    """Form for existing user authentication."""
    username_or_email = StringField(
        "Username or Email",
        validators=[DataRequired(message="Username or Email is required.")]
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Password is required.")]
    )
    submit = SubmitField("Log In")
