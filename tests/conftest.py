"""
Pytest Fixtures for Secure Digital Wallet.

Sets up an isolated, in-memory testing environment for running automated tests.
"""

import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.wallet import Wallet
from app.models.transaction import Transaction
from app.models.card import DemoCard
from app.models.payment_method import PaymentMethod
from app.utils.rate_limiter_sliding_window import login_limiter


@pytest.fixture(scope="session")
def app():
    """
    Creates and configures a new Flask app instance for testing.
    Uses TestingConfig with an in-memory SQLite database.
    """
    app = create_app("testing")

    with app.app_context():
        # Create all database tables in memory
        db.create_all()

    yield app

    with app.app_context():
        # Tear down all database tables after test session ends
        db.drop_all()


@pytest.fixture(autouse=True)
def reset_test_state(app):
    """
    Automatically resets rate limiter state and database tables
    before and after every test to guarantee test isolation.
    """
    login_limiter.clear_all()
    with app.app_context():
        db.session.rollback()
        db.session.close()
        db.drop_all()
        db.create_all()
        db.session.remove()
    yield
    login_limiter.clear_all()
    with app.app_context():
        db.session.rollback()
        db.session.close()
        db.session.remove()


@pytest.fixture
def client(app):
    """
    Provides a Flask test client to simulate HTTP requests without
    needing a running server process.
    """
    return app.test_client()


@pytest.fixture
def runner(app):
    """
    Provides a CLI runner to test Flask click commands.
    """
    return app.test_cli_runner()
