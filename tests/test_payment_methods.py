"""
Automated Tests for Simulated Payment Methods.

Verifies:
1. Addition of Demo Visa, Demo Mastercard, and Demo Bank Account.
2. Tokenization: Generation of opaque fake tokens (tok_demo_...).
3. Masking: Correct display format for cards and bank accounts.
4. AES-256-GCM metadata encryption and safe storage at rest.
5. Removal / deletion of payment methods.
6. Authorization boundaries & IDOR defense (User A cannot access User B's methods).
7. Strict PCI-DSS simulation boundaries: Zero CVVs, Zero full account/card numbers.
"""

import pytest
from flask import g

from app.extensions import db
from app.models.user import User
from app.models.payment_method import PaymentMethod
from app.services.payment_method_service import (
    create_payment_method,
    get_user_payment_methods,
    get_payment_method_details,
    delete_payment_method,
    generate_payment_token,
    format_masked_identifier,
)


def test_add_demo_card_payment_methods(app):
    """
    Verify adding Demo Visa and Demo Mastercard generates unique simulated tokens,
    masks the identifier, and stores encrypted metadata.
    """
    with app.app_context():
        user = User(username="card_holder", email="card_holder@test.edu")
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()

        # 1. Add Demo Visa
        visa = create_payment_method(
            user_id=user.id,
            method_type="DEMO_VISA",
            name="Personal Demo Visa",
            last_four="4242",
            metadata={"bank": "Simulation Bank", "type": "Credit"},
            is_default=True,
        )

        assert visa.id is not None
        assert visa.method_type == "DEMO_VISA"
        assert visa.token_id.startswith("tok_demo_visa_")
        assert visa.masked_identifier == "**** **** **** 4242"
        assert visa.is_default is True

        # 2. Add Demo Mastercard
        mc = create_payment_method(
            user_id=user.id,
            method_type="DEMO_MASTERCARD",
            name="College Demo Mastercard",
            last_four="5555",
            metadata={"bank": "Demo Credit Union", "type": "Debit"},
            is_default=False,
        )

        assert mc.id is not None
        assert mc.token_id.startswith("tok_demo_mastercard_")
        assert mc.masked_identifier == "**** **** **** 5555"
        assert mc.token_id != visa.token_id


def test_add_demo_bank_account(app):
    """
    Verify adding a Demo Bank Account generates an appropriate bank token
    and formats the masked identifier as Bank Acct: *******<last_four>.
    """
    with app.app_context():
        user = User(username="bank_user", email="bank_user@test.edu")
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()

        bank = create_payment_method(
            user_id=user.id,
            method_type="DEMO_BANK_ACCOUNT",
            name="Student Checking Demo",
            last_four="9876",
            metadata={"routing": "123456789", "institution": "State Demo Bank"},
        )

        assert bank.id is not None
        assert bank.token_id.startswith("tok_demo_bank_")
        assert bank.masked_identifier == "Bank Acct: *******9876"


def test_payment_method_encrypted_metadata(app):
    """
    Verify that demonstration metadata is encrypted with AES-256-GCM at rest,
    never leaks plaintext in the database, and recovers cleanly on decryption.
    """
    with app.app_context():
        user = User(username="crypto_pm", email="crypto_pm@test.edu")
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()

        sensitive_demo_data = {
            "demo_branch": "Main Street Branch 001",
            "fake_routing": "021000021",
            "account_nickname": "Emergency Fund (Simulated)",
        }

        pm = create_payment_method(
            user_id=user.id,
            method_type="DEMO_BANK_ACCOUNT",
            name="Savings Demo",
            last_four="1122",
            metadata=sensitive_demo_data,
        )

        # Inspect raw database column
        saved_pm = PaymentMethod.query.filter_by(id=pm.id).first()
        assert "Main Street Branch" not in saved_pm.encrypted_metadata
        assert "021000021" not in saved_pm.encrypted_metadata

        # Verify decryption via service with valid 4-digit key
        _, decrypted_data = get_payment_method_details(user.id, pm.id, security_key="1234")
        assert isinstance(decrypted_data, dict)
        assert decrypted_data["demo_branch"] == "Main Street Branch 001"
        assert decrypted_data["fake_routing"] == "021000021"

        # Verify decryption fails with incorrect 4-digit key
        with pytest.raises(ValueError, match="Incorrect 4-digit security key"):
            get_payment_method_details(user.id, pm.id, security_key="9999")


def test_remove_payment_method(app):
    """
    Verify that a payment method can be removed and is cleanly deleted from the database.
    """
    with app.app_context():
        user = User(username="del_user", email="del@test.edu")
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()

        pm = create_payment_method(
            user_id=user.id,
            method_type="DEMO_VISA",
            name="Temporary Card",
            last_four="3333",
        )

        assert PaymentMethod.query.filter_by(id=pm.id).first() is not None

        # Delete payment method
        success = delete_payment_method(user.id, pm.id)
        assert success is True
        assert PaymentMethod.query.filter_by(id=pm.id).first() is None


def test_unauthorized_payment_method_access_idor(client, app):
    """
    Verify IDOR defense: User A cannot view, reveal, or delete User B's payment method.
    """
    with app.app_context():
        # Setup Alice and Bob
        alice = User(username="alice_pm", email="alice_pm@test.edu")
        alice.set_password("Password123!")
        bob = User(username="bob_pm", email="bob_pm@test.edu")
        bob.set_password("Password123!")
        db.session.add_all([alice, bob])
        db.session.commit()

        pm_alice = create_payment_method(
            user_id=alice.id,
            method_type="DEMO_VISA",
            name="Alice Secret Card",
            last_four="1234",
            metadata="Alice Confidential Demo Details",
        )

        pm_bob = create_payment_method(
            user_id=bob.id,
            method_type="DEMO_BANK_ACCOUNT",
            name="Bob Secret Bank",
            last_four="5678",
            metadata="Bob Confidential Demo Details",
        )

        # 1. Service-level authorization check: Bob cannot access Alice's method
        with pytest.raises(ValueError, match="not authorized"):
            get_payment_method_details(user_id=bob.id, method_id=pm_alice.id)

        with pytest.raises(ValueError, match="not authorized"):
            delete_payment_method(user_id=bob.id, method_id=pm_alice.id)

        # 2. HTTP-level authorization check: Login as Bob
        with client.session_transaction() as sess:
            sess["user_id"] = bob.id
            sess["username"] = bob.username

        # Bob attempts to reveal Alice's payment method
        res = client.get(f"/payment-methods/{pm_alice.id}/reveal", follow_redirects=True)
        assert b"Alice Confidential Demo Details" not in res.data
        assert b"not authorized" in res.data.lower()

        # Bob attempts to delete Alice's payment method
        res_del = client.post(f"/payment-methods/{pm_alice.id}/delete", follow_redirects=True)
        assert b"not authorized" in res_del.data.lower()

        # Verify Alice's payment method remains intact
        assert PaymentMethod.query.filter_by(id=pm_alice.id).first() is not None


def test_zero_cvv_and_zero_full_credentials(app):
    """
    Verify PCI-DSS educational boundaries:
    1. payment_methods table has NO cvv, cvc, pan, or full account_number column.
    2. create_payment_method rejects full card numbers or invalid lengths.
    """
    with app.app_context():
        user = User(username="pci_pm_user", email="pci_pm@test.edu")
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()

        # 1. Verify schema columns
        column_names = [col.name for col in PaymentMethod.__table__.columns]
        assert "cvv" not in column_names
        assert "cvc" not in column_names
        assert "pan" not in column_names
        assert "account_number" not in column_names
        assert "masked_identifier" in column_names

        # 2. Reject full 16-digit card number
        with pytest.raises(ValueError, match="only provide the LAST 4 digits"):
            create_payment_method(
                user_id=user.id,
                method_type="DEMO_VISA",
                name="Invalid Full Card",
                last_four="4000123456789010",
            )

        # 3. Reject non-numeric input
        with pytest.raises(ValueError, match="only provide the LAST 4 digits"):
            create_payment_method(
                user_id=user.id,
                method_type="DEMO_BANK_ACCOUNT",
                name="Invalid Letters",
                last_four="abcd",
            )


def test_default_payment_method_toggle(app):
    """
    Verify that setting a payment method as default unsets is_default on other methods.
    """
    with app.app_context():
        user = User(username="toggle_user", email="toggle@test.edu")
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()

        pm1 = create_payment_method(
            user_id=user.id,
            method_type="DEMO_VISA",
            name="Card 1",
            last_four="1111",
            is_default=True,
        )
        assert pm1.is_default is True

        pm2 = create_payment_method(
            user_id=user.id,
            method_type="DEMO_MASTERCARD",
            name="Card 2",
            last_four="2222",
            is_default=True,
        )
        assert pm2.is_default is True

        # Refresh pm1 from DB
        db.session.refresh(pm1)
        assert pm1.is_default is False


def test_reveal_challenge_flow_and_cvv_removal(client, app):
    """
    Verify:
    1. GET /payment-methods/<id>/reveal returns the step-up authentication challenge.
    2. Wrong password in challenge fails with error.
    3. Wrong 4-digit key in challenge fails with error.
    4. Correct password + correct 4-digit key decrypts metadata.
    5. 'CVV / Full Creds' is completely removed from the output.
    """
    with app.app_context():
        user = User(username="reveal_tester", email="reveal@test.edu")
        user.set_password("MyUserPassword123!")
        db.session.add(user)
        db.session.commit()

        pm = create_payment_method(
            user_id=user.id,
            method_type="DEMO_VISA",
            name="My Secure Card",
            last_four="4242",
            metadata="Confidential Secret Metadata 999",
            security_key="7890",
        )
        pm_id = pm.id
        user_id = user.id
        username = user.username

    # Authenticate session
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["username"] = username

    # 1. GET returns challenge form, does NOT reveal metadata
    res_get = client.get(f"/payment-methods/{pm_id}/reveal")
    assert res_get.status_code == 200
    get_html = res_get.get_data(as_text=True)
    assert "Step-Up Authentication" in get_html
    assert "Confidential Secret Metadata 999" not in get_html
    assert "Account Password" in get_html
    assert "4-Digit Security Key" in get_html

    # 2. POST with wrong password
    res_wrong_pw = client.post(
        f"/payment-methods/{pm_id}/reveal",
        data={
            "password": "WrongPassword!",
            "security_key": "7890",
        },
    )
    assert res_wrong_pw.status_code == 200
    wrong_pw_html = res_wrong_pw.get_data(as_text=True)
    assert "Incorrect account password" in wrong_pw_html
    assert "Confidential Secret Metadata 999" not in wrong_pw_html

    # 3. POST with wrong 4-digit key
    res_wrong_pin = client.post(
        f"/payment-methods/{pm_id}/reveal",
        data={
            "password": "MyUserPassword123!",
            "security_key": "1111",
        },
    )
    assert res_wrong_pin.status_code == 200
    wrong_pin_html = res_wrong_pin.get_data(as_text=True)
    assert "Incorrect 4-digit security key" in wrong_pin_html
    assert "Confidential Secret Metadata 999" not in wrong_pin_html

    # 4. POST with correct password and correct 4-digit key
    res_ok = client.post(
        f"/payment-methods/{pm_id}/reveal",
        data={
            "password": "MyUserPassword123!",
            "security_key": "7890",
        },
    )
    assert res_ok.status_code == 200
    ok_html = res_ok.get_data(as_text=True)
    assert "Confidential Secret Metadata 999" in ok_html
    assert "Integrity Tag Verified Successfully" in ok_html

    # 5. Verify CVV / Full Creds row is completely removed
    assert "CVV / Full Creds" not in ok_html
    assert "CVV / CVC" not in ok_html
