"""
Automated Tests for AES-256-GCM Encryption and Demo Cards Vault.

Verifies:
1. Successful round-trip encryption and decryption.
2. Fresh nonce generation (different ciphertext on repeated encryption).
3. Tampered ciphertext rejection (integrity/authentication tag verification).
4. Incorrect key rejection.
5. Encryption key is loaded dynamically and never hard-coded.
6. Authenticated Associated Data (AAD) integrity checks.
7. DemoCard model encryption at rest and safe representation.
8. Strict PCI-DSS simulation boundaries (Zero CVV, Zero full PAN storage).
9. Authorization boundaries on card reveal (IDOR defense).
"""

import base64
import os
import pytest
from flask import g

from app.extensions import db
from app.models.user import User
from app.models.card import DemoCard
from app.services.card_service import (
    create_demo_card,
    get_user_cards,
    get_decrypted_card_details,
    delete_demo_card,
)
from app.crypto_aes_gcm import (
    encrypt,
    decrypt,
    generate_key,
    get_encryption_key,
    TamperedDataError,
    DecryptionError,
    InvalidKeyError,
    KEY_LENGTH_BYTES,
    NONCE_LENGTH_BYTES,
)
from app.config import ProductionConfig


def test_successful_encryption_and_decryption(app):
    """
    Verify that plaintext can be encrypted and successfully decrypted back
    to its exact original value using AES-256-GCM.
    """
    with app.app_context():
        test_cases = [
            "Simple simulated billing address",
            "123 Fake Street, Suite 400, Springfield, USA 99999",
            "Special characters: !@#$%^&*()_+-=[]{}|;':,.<>/?`~",
            "Unicode data: 💳 🔐 🛡️ 💵 100€ 50£ 1000¥",
            '{"routing": "123456789", "account": "987654321", "type": "checking"}',
        ]

        for plaintext in test_cases:
            ciphertext = encrypt(plaintext)
            assert ciphertext != plaintext
            assert isinstance(ciphertext, str)

            decrypted = decrypt(ciphertext)
            assert decrypted == plaintext


def test_different_ciphertext_for_repeated_encryption(app):
    """
    Verify that encrypting the exact same plaintext multiple times produces
    different ciphertexts every time due to a fresh, random 12-byte nonce.
    """
    with app.app_context():
        plaintext = "Identical sensitive billing information"
        ciphertexts = [encrypt(plaintext) for _ in range(10)]

        # All 10 ciphertexts must be completely distinct
        assert len(set(ciphertexts)) == 10

        # Verify that the extracted nonces (first 12 bytes) are all distinct
        nonces = [base64.b64decode(c)[:NONCE_LENGTH_BYTES] for c in ciphertexts]
        assert len(set(nonces)) == 10


def test_tampered_ciphertext_rejection(app):
    """
    Verify that altering even a single bit in the ciphertext, nonce, or tag
    causes decryption to fail and raise TamperedDataError.
    """
    with app.app_context():
        plaintext = "Confidential simulated payment address"
        ciphertext_b64 = encrypt(plaintext)
        raw_bytes = bytearray(base64.b64decode(ciphertext_b64))

        # 1. Tamper with the ciphertext body (middle byte)
        tampered_body = bytearray(raw_bytes)
        tampered_body[15] ^= 0x01  # Flip one bit
        tampered_body_b64 = base64.b64encode(tampered_body).decode("utf-8")

        with pytest.raises(TamperedDataError):
            decrypt(tampered_body_b64)

        # 2. Tamper with the nonce (first byte)
        tampered_nonce = bytearray(raw_bytes)
        tampered_nonce[0] ^= 0xFF  # Flip bits in nonce
        tampered_nonce_b64 = base64.b64encode(tampered_nonce).decode("utf-8")

        with pytest.raises(TamperedDataError):
            decrypt(tampered_nonce_b64)

        # 3. Tamper with the authentication tag (last byte)
        tampered_tag = bytearray(raw_bytes)
        tampered_tag[-1] ^= 0x55  # Flip bits in authentication tag
        tampered_tag_b64 = base64.b64encode(tampered_tag).decode("utf-8")

        with pytest.raises(TamperedDataError):
            decrypt(tampered_tag_b64)

        # 4. Truncate payload (remove tag)
        truncated = raw_bytes[:15]
        truncated_b64 = base64.b64encode(truncated).decode("utf-8")

        with pytest.raises(DecryptionError):
            decrypt(truncated_b64)


def test_incorrect_key_rejection(app):
    """
    Verify that attempting to decrypt ciphertext with an incorrect 256-bit key
    fails authentication tag verification and raises TamperedDataError.
    """
    with app.app_context():
        key_alice = generate_key()
        key_bob = generate_key()
        assert key_alice != key_bob

        plaintext = "Secret data belonging to Alice"
        ciphertext = encrypt(plaintext, key=key_alice)

        # Decrypting with Alice's key succeeds
        assert decrypt(ciphertext, key=key_alice) == plaintext

        # Decrypting with Bob's key fails tag verification
        with pytest.raises(TamperedDataError):
            decrypt(ciphertext, key=key_bob)


def test_encryption_key_not_hardcoded(app, monkeypatch):
    """
    Verify that the encryption key is loaded from the environment/configuration
    and is never hard-coded in the source code.
    """
    with app.app_context():
        # 1. In ProductionConfig, verify ENCRYPTION_KEY is read from os.environ
        monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
        assert ProductionConfig.ENCRYPTION_KEY is None

        # 2. Verify get_encryption_key raises InvalidKeyError when key is absent in both env and config
        monkeypatch.setitem(app.config, "ENCRYPTION_KEY", None)
        with pytest.raises(InvalidKeyError):
            get_encryption_key(custom_key=None)

        # 3. Verify get_encryption_key rejects keys that are not 32 bytes
        with pytest.raises(InvalidKeyError):
            get_encryption_key(custom_key="too-short-key")

        with pytest.raises(InvalidKeyError):
            get_encryption_key(custom_key=b"12345")


def test_associated_data_integrity(app):
    """
    Verify that Authenticated Associated Data (AAD) is bound to the ciphertext.
    If the associated data is altered, decryption must be rejected.
    """
    with app.app_context():
        plaintext = "Simulated bank account note"
        user_binding = b"user_id:42"

        ciphertext = encrypt(plaintext, associated_data=user_binding)

        # Correct associated data decrypts successfully
        assert decrypt(ciphertext, associated_data=user_binding) == plaintext

        # Altered associated data fails tag check
        with pytest.raises(TamperedDataError):
            decrypt(ciphertext, associated_data=b"user_id:99")

        # Missing associated data fails tag check
        with pytest.raises(TamperedDataError):
            decrypt(ciphertext, associated_data=None)


def test_demo_card_model_encryption(app):
    """
    Verify that DemoCard persists AES-256-GCM ciphertext in the database,
    never leaks plaintext in storage, and recovers the plaintext via get_billing_details().
    """
    with app.app_context():
        user = User(username="carduser", email="carduser@test.edu")
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()

        card = create_demo_card(
            user_id=user.id,
            cardholder_name="Student Tester",
            last_four="4242",
            card_brand="Visa",
            exp_month=12,
            exp_year=2028,
            billing_details="742 Evergreen Terrace, Springfield (Simulated)",
        )

        # Verify database record
        saved_card = DemoCard.query.filter_by(id=card.id).first()
        assert saved_card is not None
        assert saved_card.masked_pan == "**** **** **** 4242"
        assert saved_card.card_brand == "Visa"

        # Verify that encrypted_billing_details in database does NOT contain plaintext
        assert "742 Evergreen Terrace" not in saved_card.encrypted_billing_details
        assert "Springfield" not in saved_card.encrypted_billing_details

        # Verify that get_billing_details() decrypts correctly
        decrypted = saved_card.get_billing_details()
        assert decrypted == "742 Evergreen Terrace, Springfield (Simulated)"

        # Verify safe __repr__ (no sensitive details leaked)
        rep = repr(saved_card)
        assert "742 Evergreen Terrace" not in rep
        assert saved_card.encrypted_billing_details not in rep


def test_zero_cvv_and_real_cards_prevented(app):
    """
    Verify strict PCI-DSS educational boundaries:
    1. DemoCard table has NO CVV column.
    2. create_demo_card rejects full card numbers (must be exactly 4 digits).
    """
    with app.app_context():
        user = User(username="pci_tester", email="pci@test.edu")
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()

        # 1. Verify DemoCard table has no CVV column
        column_names = [col.name for col in DemoCard.__table__.columns]
        assert "cvv" not in column_names
        assert "cvc" not in column_names
        assert "pan" not in column_names  # Only masked_pan exists
        assert "masked_pan" in column_names

        # 2. Reject full 16-digit card number
        with pytest.raises(ValueError, match="only provide the LAST 4 digits"):
            create_demo_card(
                user_id=user.id,
                cardholder_name="Alice",
                last_four="4111111111114242",  # Full card rejected
                card_brand="Visa",
                exp_month=5,
                exp_year=2027,
            )

        # 3. Reject non-numeric last_four
        with pytest.raises(ValueError, match="only provide the LAST 4 digits"):
            create_demo_card(
                user_id=user.id,
                cardholder_name="Alice",
                last_four="abcd",
                card_brand="Visa",
                exp_month=5,
                exp_year=2027,
            )


def test_cards_route_authorization_and_idor_defense(client, app):
    """
    Verify that users can only view, reveal, or delete their own cards.
    Any attempt to access another user's card is blocked (IDOR defense).
    """
    with app.app_context():
        # Setup Alice and Bob
        alice = User(username="alice_vault", email="alice_v@test.edu")
        alice.set_password("Password123!")
        bob = User(username="bob_vault", email="bob_v@test.edu")
        bob.set_password("Password123!")
        db.session.add_all([alice, bob])
        db.session.commit()

        card_alice = create_demo_card(
            user_id=alice.id,
            cardholder_name="Alice Vault",
            last_four="1111",
            card_brand="Visa",
            exp_month=10,
            exp_year=2027,
            billing_details="Alice Confidential Demo Address",
        )

        card_bob = create_demo_card(
            user_id=bob.id,
            cardholder_name="Bob Vault",
            last_four="2222",
            card_brand="Mastercard",
            exp_month=11,
            exp_year=2028,
            billing_details="Bob Confidential Demo Address",
        )

        # Login as Alice
        with client.session_transaction() as sess:
            sess["user_id"] = alice.id
            sess["username"] = alice.username

        # Alice reveals her own card -> 200 OK with decrypted details
        res = client.get(f"/cards/{card_alice.id}/reveal")
        assert res.status_code == 200
        assert b"Alice Confidential Demo Address" in res.data
        assert b"Integrity Tag Verified" in res.data

        # Alice attempts to reveal Bob's card -> Blocked! Redirects with error flash
        res_bob = client.get(f"/cards/{card_bob.id}/reveal", follow_redirects=True)
        assert b"Bob Confidential Demo Address" not in res_bob.data
        assert b"not authorized" in res_bob.data.lower()

        # Alice attempts to delete Bob's card -> Blocked!
        res_del = client.post(f"/cards/{card_bob.id}/delete", follow_redirects=True)
        assert b"not authorized" in res_del.data.lower()
        # Verify Bob's card still exists
        assert DemoCard.query.filter_by(id=card_bob.id).first() is not None


def test_aes_gcm_module_naming_and_backward_compatibility():
    """
    Verify that both the explicit algorithm module (app.crypto_aes_gcm / app.utils.crypto_aes_gcm)
    and the backward-compatibility facade (app.crypto / app.utils.crypto) export identical symbols.
    """
    import app.crypto_aes_gcm as explicit_crypto
    import app.crypto as facade_crypto
    import app.utils.crypto_aes_gcm as explicit_utils_crypto
    import app.utils.crypto as facade_utils_crypto

    assert explicit_crypto.encrypt is facade_crypto.encrypt
    assert explicit_crypto.decrypt is facade_crypto.decrypt
    assert explicit_crypto.TamperedDataError is facade_crypto.TamperedDataError
    assert explicit_crypto.KEY_LENGTH_BYTES == 32
    assert explicit_crypto.NONCE_LENGTH_BYTES == 12
    assert explicit_crypto.TAG_LENGTH_BYTES == 16

    assert explicit_utils_crypto.encrypt is facade_utils_crypto.encrypt
    assert explicit_utils_crypto.decrypt is facade_utils_crypto.decrypt

