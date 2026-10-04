"""
Automated Test Suite for Step 3: Wallet Functionality.

Verifies:
- Automatic wallet provisioning on user registration
- Simulated deposits and integer-cent balance updates
- Validation rejecting zero, negative, and malformed amounts
- Floating-point inaccuracy prevention
- Authorization boundaries (users cannot view or alter other wallets)
- Transaction ledger records, statuses, and UUID reference IDs
"""

import pytest
from app.extensions import db
from app.models.user import User
from app.models.wallet import Wallet
from app.models.transaction import Transaction
from app.services.wallet_service import deposit_funds, get_or_create_user_wallet


# Helper to register and log in a user in tests
def register_and_login(client, username="alice_wallet", email="alice@wallet.edu", password="Password123!"):
    client.post(
        "/register",
        data={
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password,
        },
    )
    client.post(
        "/login",
        data={
            "username_or_email": username,
            "password": password,
        },
    )


# ============================================================================
# Wallet Creation & Balance Tests
# ============================================================================

def test_automatic_wallet_creation_on_registration(client, app):
    """Verify that a wallet is automatically created with ₹0.00 when a user registers."""
    client.post(
        "/register",
        data={
            "username": "new_user",
            "email": "new_user@college.edu",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    )

    with app.app_context():
        user = User.query.filter_by(username="new_user").first()
        assert user is not None
        assert user.wallet is not None
        assert user.wallet.balance_cents == 0
        assert user.wallet.currency == "INR"
        assert user.wallet.formatted_balance == "₹0.00"


def test_successful_deposit(client, app):
    """Verify that a valid deposit increments the wallet balance in integer cents."""
    register_and_login(client, username="depositor_1", email="dep1@college.edu")

    response = client.post(
        "/wallet/deposit",
        data={"amount": "50.25", "description": "Pocket money"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    content = response.get_data(as_text=True)
    assert "Deposit of ₹50.25 completed successfully" in content
    assert "₹50.25" in content

    with app.app_context():
        user = User.query.filter_by(username="depositor_1").first()
        assert user.wallet.balance_cents == 5025
        assert user.wallet.formatted_balance == "₹50.25"


def test_invalid_deposit_zero_and_negative(client, app):
    """Verify server rejects zero and negative deposit amounts."""
    register_and_login(client, username="zero_tester", email="zero@college.edu")

    # 1. Attempt deposit of $0.00
    res_zero = client.post(
        "/wallet/deposit",
        data={"amount": "0.00", "description": "Zero deposit"},
    )
    assert res_zero.status_code == 400
    assert "Amount must be strictly greater than zero" in res_zero.get_data(as_text=True)

    # 2. Attempt negative deposit -$25.00
    res_neg = client.post(
        "/wallet/deposit",
        data={"amount": "-25.00", "description": "Negative deposit"},
    )
    assert res_neg.status_code == 400
    assert "Amount must be strictly greater than zero" in res_neg.get_data(as_text=True)

    # Verify balance remains 0
    with app.app_context():
        user = User.query.filter_by(username="zero_tester").first()
        assert user.wallet.balance_cents == 0


def test_invalid_deposit_malformed_formats(client, app):
    """Verify server rejects text, non-numeric characters, and sub-cent decimals."""
    register_and_login(client, username="format_tester", email="fmt@college.edu")

    # 1. Text input
    res_text = client.post(
        "/wallet/deposit",
        data={"amount": "fifty_dollars"},
    )
    assert res_text.status_code == 400
    assert "Invalid amount format" in res_text.get_data(as_text=True)

    # 2. Sub-cent precision (more than 2 decimal places)
    res_subcents = client.post(
        "/wallet/deposit",
        data={"amount": "10.999"},
    )
    assert res_subcents.status_code == 400
    assert "cannot have more than 2 decimal places" in res_subcents.get_data(as_text=True)

    # 3. Excessive deposit limit test (₹10,000,001)
    res_overflow = client.post(
        "/wallet/deposit",
        data={"amount": "10000000.01"},
    )
    assert res_overflow.status_code == 400
    assert "cannot exceed ₹10,000,000.00" in res_overflow.get_data(as_text=True)


def test_integer_arithmetic_eliminates_floating_point_rounding_error(client, app):
    """
    Classic financial test: in IEEE-754 floating point, 0.1 + 0.2 = 0.30000000000000004.
    Verify that our integer-cents storage results in EXACTLY 30 paise (₹0.30).
    """
    register_and_login(client, username="float_tester", email="float@college.edu")

    client.post("/wallet/deposit", data={"amount": "0.10"})
    client.post("/wallet/deposit", data={"amount": "0.20"})

    with app.app_context():
        user = User.query.filter_by(username="float_tester").first()
        assert user.wallet.balance_cents == 30
        assert user.wallet.formatted_balance == "₹0.30"


# ============================================================================
# Authorization Boundaries & Unauthorized Access Tests
# ============================================================================

def test_unauthorized_wallet_access_requires_login(client):
    """Verify that unauthenticated requests to wallet routes redirect to login."""
    res_dash = client.get("/wallet/dashboard")
    assert res_dash.status_code == 302
    assert "/login" in res_dash.headers["Location"]

    res_dep = client.get("/wallet/deposit")
    assert res_dep.status_code == 302
    assert "/login" in res_dep.headers["Location"]

    res_hist = client.get("/wallet/history")
    assert res_hist.status_code == 302
    assert "/login" in res_hist.headers["Location"]


def test_users_can_access_only_their_own_wallet(client, app):
    """
    Verify IDOR protection: User A's session can only view and modify User A's wallet,
    never User B's wallet.
    """
    # Create User A
    register_and_login(client, username="user_alice", email="alice@test.edu")
    client.post("/wallet/deposit", data={"amount": "100.00"})
    client.get("/logout")

    # Create User B
    register_and_login(client, username="user_bob", email="bob@test.edu")
    client.post("/wallet/deposit", data={"amount": "25.00"})

    # Check User B's dashboard
    res_bob = client.get("/wallet/dashboard")
    content_bob = res_bob.get_data(as_text=True)
    assert "₹25.00" in content_bob
    assert "₹100.00" not in content_bob

    with app.app_context():
        alice = User.query.filter_by(username="user_alice").first()
        bob = User.query.filter_by(username="user_bob").first()
        assert alice.wallet.balance_cents == 10000
        assert bob.wallet.balance_cents == 2500
        assert alice.wallet.id != bob.wallet.id


# ============================================================================
# Transaction Ledger Tests
# ============================================================================

def test_transaction_creation_and_attributes(client, app):
    """Verify that a deposit creates a complete, immutable transaction ledger record."""
    register_and_login(client, username="ledger_user", email="ledger@test.edu")

    client.post(
        "/wallet/deposit",
        data={"amount": "75.50", "description": "Gift"},
    )

    with app.app_context():
        user = User.query.filter_by(username="ledger_user").first()
        txs = user.wallet.transactions.all()
        assert len(txs) == 1

        tx = txs[0]
        assert tx.amount_cents == 7550
        assert tx.formatted_amount == "₹75.50"
        assert tx.transaction_type == "DEPOSIT"
        assert tx.status == "COMPLETED"
        assert tx.description == "Gift"
        assert len(tx.reference_id) == 36  # Valid UUID string
        assert tx.wallet_id == user.wallet.id


def test_transaction_history_endpoint(client):
    """Verify transaction history view displays recorded transactions."""
    register_and_login(client, username="history_user", email="hist@test.edu")

    client.post("/wallet/deposit", data={"amount": "10.00", "description": "Deposit 1"})
    client.post("/wallet/deposit", data={"amount": "20.00", "description": "Deposit 2"})

    response = client.get("/wallet/history")
    assert response.status_code == 200
    content = response.get_data(as_text=True)
    assert "+₹10.00" in content
    assert "+₹20.00" in content
    assert "Deposit 1" in content
    assert "Deposit 2" in content
    assert "COMPLETED" in content


# ============================================================================
# Peer-to-Peer Transfer Tests (Step 4)
# ============================================================================

def test_successful_transfer(client, app):
    """Verify that a valid P2P transfer debits sender, credits receiver, and records ledger entries."""
    # 1. Create Alice (sender) and Bob (receiver)
    register_and_login(client, username="alice_sender", email="alice_s@test.edu")
    client.post("/wallet/deposit", data={"amount": "100.00"})
    client.get("/logout")

    register_and_login(client, username="bob_receiver", email="bob_r@test.edu")
    client.get("/logout")

    # 2. Alice transfers $40.00 to Bob
    client.post(
        "/login",
        data={"username_or_email": "alice_sender", "password": "Password123!"},
    )
    res_transfer = client.post(
        "/wallet/transfer",
        data={
            "recipient": "bob_receiver",
            "amount": "40.00",
            "note": "Coffee and donuts",
        },
        follow_redirects=True,
    )
    assert res_transfer.status_code == 200
    content = res_transfer.get_data(as_text=True)
    assert "Successfully sent ₹40.00 to @bob_receiver" in content
    assert "₹60.00" in content  # Alice's remaining balance

    # 3. Verify database records
    with app.app_context():
        alice = User.query.filter_by(username="alice_sender").first()
        bob = User.query.filter_by(username="bob_receiver").first()

        assert alice.wallet.balance_cents == 6000  # ₹60.00
        assert bob.wallet.balance_cents == 4000    # ₹40.00

        # Verify Alice's ledger entry
        alice_txs = alice.wallet.transactions.all()
        assert len(alice_txs) == 2  # 1 deposit + 1 transfer out
        tx_out = [t for t in alice_txs if t.transaction_type == "TRANSFER_OUT"][0]
        assert tx_out.amount_cents == -4000
        assert tx_out.formatted_amount == "-₹40.00"
        assert "@bob_receiver" in tx_out.description
        assert "Coffee and donuts" in tx_out.description
        assert tx_out.status == "COMPLETED"

        # Verify Bob's ledger entry
        bob_txs = bob.wallet.transactions.all()
        assert len(bob_txs) == 1  # 1 transfer in
        tx_in = bob_txs[0]
        assert tx_in.amount_cents == 4000
        assert tx_in.formatted_amount == "₹40.00"
        assert "@alice_sender" in tx_in.description
        assert "Coffee and donuts" in tx_in.description
        assert tx_in.status == "COMPLETED"


def test_transfer_unknown_recipient(client, app):
    """Verify transfer fails when the recipient does not exist."""
    register_and_login(client, username="sender_x", email="sx@test.edu")
    client.post("/wallet/deposit", data={"amount": "50.00"})

    response = client.post(
        "/wallet/transfer",
        data={
            "recipient": "non_existent_user_999",
            "amount": "25.00",
        },
    )
    assert response.status_code == 400
    assert "was not found" in response.get_data(as_text=True)

    with app.app_context():
        user = User.query.filter_by(username="sender_x").first()
        assert user.wallet.balance_cents == 5000  # Untouched


def test_transfer_insufficient_balance(client, app):
    """Verify transfer fails when sender attempts to send more than current balance."""
    # Create Alice with $10.00 and Bob
    register_and_login(client, username="alice_poor", email="poor@test.edu")
    client.post("/wallet/deposit", data={"amount": "10.00"})
    client.get("/logout")

    register_and_login(client, username="bob_target", email="btarget@test.edu")
    client.get("/logout")

    # Alice tries to send $50.00
    client.post(
        "/login",
        data={"username_or_email": "alice_poor", "password": "Password123!"},
    )
    response = client.post(
        "/wallet/transfer",
        data={"recipient": "bob_target", "amount": "50.00"},
    )
    assert response.status_code == 400
    assert "Insufficient balance" in response.get_data(as_text=True)

    with app.app_context():
        alice = User.query.filter_by(username="alice_poor").first()
        bob = User.query.filter_by(username="bob_target").first()
        assert alice.wallet.balance_cents == 1000  # Still $10.00
        assert bob.wallet.balance_cents == 0      # Still $0.00


def test_transfer_zero_and_negative_amount(client, app):
    """Verify server rejects zero and negative transfer amounts."""
    register_and_login(client, username="alice_amounts", email="amounts@test.edu")
    client.post("/wallet/deposit", data={"amount": "50.00"})
    client.get("/logout")

    register_and_login(client, username="bob_amounts", email="bamounts@test.edu")
    client.get("/logout")

    client.post(
        "/login",
        data={"username_or_email": "alice_amounts", "password": "Password123!"},
    )

    # 1. Zero amount
    res_zero = client.post(
        "/wallet/transfer",
        data={"recipient": "bob_amounts", "amount": "0.00"},
    )
    assert res_zero.status_code == 400
    assert "Amount must be strictly greater than zero" in res_zero.get_data(as_text=True)

    # 2. Negative amount
    res_neg = client.post(
        "/wallet/transfer",
        data={"recipient": "bob_amounts", "amount": "-15.00"},
    )
    assert res_neg.status_code == 400
    assert "Amount must be strictly greater than zero" in res_neg.get_data(as_text=True)

    with app.app_context():
        alice = User.query.filter_by(username="alice_amounts").first()
        assert alice.wallet.balance_cents == 5000


def test_transfer_self_transfer_rejected(client, app):
    """Verify user cannot send simulated money to themselves."""
    register_and_login(client, username="self_sender", email="self@test.edu")
    client.post("/wallet/deposit", data={"amount": "50.00"})

    # Attempt to transfer to self by username
    res_self = client.post(
        "/wallet/transfer",
        data={"recipient": "self_sender", "amount": "10.00"},
    )
    assert res_self.status_code == 400
    assert "cannot transfer money to yourself" in res_self.get_data(as_text=True)

    # Attempt to transfer to self by email
    res_self_email = client.post(
        "/wallet/transfer",
        data={"recipient": "self@test.edu", "amount": "10.00"},
    )
    assert res_self_email.status_code == 400
    assert "cannot transfer money to yourself" in res_self_email.get_data(as_text=True)

    with app.app_context():
        user = User.query.filter_by(username="self_sender").first()
        assert user.wallet.balance_cents == 5000


def test_unauthorized_transaction_access(client, app):
    """
    Verify that User C cannot see transactions between User A and User B.
    Each user can view only their own authorized transaction history.
    """
    # Alice sends Bob $30.00
    register_and_login(client, username="alice_priv", email="alice_p@test.edu")
    client.post("/wallet/deposit", data={"amount": "50.00"})
    client.get("/logout")

    register_and_login(client, username="bob_priv", email="bob_p@test.edu")
    client.get("/logout")

    client.post("/login", data={"username_or_email": "alice_priv", "password": "Password123!"})
    client.post("/wallet/transfer", data={"recipient": "bob_priv", "amount": "30.00", "note": "Secret memo 12345"})
    client.get("/logout")

    # Charlie logs in and views history
    register_and_login(client, username="charlie_eavesdropper", email="charlie@test.edu")
    res_charlie = client.get("/wallet/history")
    assert res_charlie.status_code == 200
    content = res_charlie.get_data(as_text=True)

    # Charlie must NOT see Alice or Bob's transaction or memo
    assert "Secret memo 12345" not in content
    assert "bob_priv" not in content
    assert "alice_priv" not in content
    assert "-₹30.00" not in content
    assert "+₹30.00" not in content


def test_transfer_atomic_rollback_on_failure(app):
    """
    Verify that if a failure occurs during the transfer process,
    the entire transaction is rolled back and neither party's balance is changed.
    """
    from unittest.mock import patch
    from app.services.wallet_service import transfer_funds

    with app.app_context():
        # Setup Alice ($50.00) and Bob ($0.00)
        alice = User(username="alice_rollback", email="aroll@test.edu")
        alice.set_password("Password123!")
        db.session.add(alice)
        db.session.flush()

        bob = User(username="bob_rollback", email="broll@test.edu")
        bob.set_password("Password123!")
        db.session.add(bob)
        db.session.flush()

        w_alice = Wallet(user_id=alice.id, balance_cents=5000)
        w_bob = Wallet(user_id=bob.id, balance_cents=0)
        db.session.add_all([w_alice, w_bob])
        db.session.commit()

        # Simulate a database crash or unexpected error right before commit
        with patch.object(db.session, "commit", side_effect=RuntimeError("Simulated Database Crash")):
            with pytest.raises(RuntimeError):
                transfer_funds(
                    sender_user_id=alice.id,
                    recipient_identifier="bob_rollback",
                    amount_cents=2500,
                )

        # Refresh objects and verify rollback
        db.session.rollback()
        db.session.expire_all()

        alice_check = User.query.filter_by(username="alice_rollback").first()
        bob_check = User.query.filter_by(username="bob_rollback").first()

        assert alice_check.wallet.balance_cents == 5000  # Completely untouched!
        assert bob_check.wallet.balance_cents == 0      # Completely untouched!

        # Verify no orphan transactions exist
        txs = Transaction.query.filter(
            Transaction.wallet_id.in_([alice_check.wallet.id, bob_check.wallet.id])
        ).all()
        assert len(txs) == 0

