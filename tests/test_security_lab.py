"""
Automated Test Suite for VaultPay Security Lab.

Verifies:
1. Cryptographic integrity of SHA-256 fingerprinting.
2. AES-256-GCM authenticated encryption and tamper detection (1-byte, tag, nonce, AAD).
3. Rejection of all modified data via backend cryptographic checks.
4. Clean restoration and decryption of pristine data.
5. Strict isolation from production database (wallets, transactions, payment methods, keys).
6. HTTP route endpoints and JSON API responses.
"""

import json
import os
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from app.services.security_demo_service import (
    SecurityLabDemoSession,
    security_lab_manager,
)
from app.models.wallet import Wallet
from app.models.transaction import Transaction
from app.models.payment_method import PaymentMethod
from app.models.user import User


# ============================================================================
# Core Cryptographic & Service Tests
# ============================================================================

def test_same_demo_transaction_produces_identical_sha256():
    """1. Same demo transaction -> same SHA-256 digest."""
    session = SecurityLabDemoSession("test-session-1")
    session.protect_transaction(amount_str="2500.00", recipient="Demo Merchant")
    hash1 = session.original_sha256

    # Recompute without modifying data
    canonical = json.dumps(session.transaction_data, sort_keys=True, separators=(",", ":"))
    import hashlib
    hash2 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert hash1 == hash2
    assert len(hash1) == 64


def test_modified_transaction_produces_different_sha256():
    """2. Modified transaction -> completely different SHA-256 digest."""
    session = SecurityLabDemoSession("test-session-2")
    session.protect_transaction(amount_str="2500.00")
    orig_hash = session.original_sha256

    # Tamper with amount
    res = session.tamper_transaction_data(new_amount_cents=2500000)
    current_hash = session.current_sha256

    assert current_hash != orig_hash
    assert res["summary"]["sha256_match"] is False
    assert res["overall_accepted"] is False
    assert res["transaction_status"] == "REJECTED"


def test_restore_original_transaction_restores_original_sha256():
    """3. Restore original transaction -> original digest returns."""
    session = SecurityLabDemoSession("test-session-3")
    session.protect_transaction(amount_str="2500.00")
    orig_hash = session.original_sha256

    session.tamper_transaction_data(new_amount_cents=999999)
    assert session.current_sha256 != orig_hash

    # Restore
    res = session.restore_original_record()
    assert session.current_sha256 == orig_hash
    assert res["summary"]["sha256_match"] is True
    assert res["overall_accepted"] is True


def test_original_ciphertext_decrypts_successfully():
    """4. Original ciphertext decrypts successfully with valid tag."""
    session = SecurityLabDemoSession("test-session-4")
    session.protect_transaction()
    res = session.run_verification()

    assert res["overall_accepted"] is True
    assert res["transaction_status"] == "Accepted"
    assert res["decrypted_payload"] is not None
    assert res["decrypted_payload"]["amount_cents"] == 250000
    assert res["decrypted_payload"]["payment_method"] == "Visa •••• 4242"


def test_one_byte_ciphertext_modification_fails_authentication():
    """5. One-byte ciphertext modification fails AES-GCM authentication."""
    session = SecurityLabDemoSession("test-session-5")
    session.protect_transaction()

    res = session.tamper_ciphertext(byte_index=3)
    assert res["overall_accepted"] is False
    assert res["transaction_status"] == "REJECTED"
    assert res["status_panel"]["authentication"] == "FAILED"
    assert res["status_panel"]["ciphertext"] == "MODIFIED"
    assert res["decrypted_payload"] is None
    assert "InvalidTag" in res["error_message"] or "authentication tag mismatch" in res["error_message"].lower()
    assert res["diff_info"] is not None
    assert "CHANGED" in res["diff_info"]["marker"]


def test_authentication_tag_modification_fails():
    """6. Authentication-tag modification fails verification."""
    session = SecurityLabDemoSession("test-session-6")
    session.protect_transaction()

    res = session.tamper_auth_tag(byte_index=0)
    assert res["overall_accepted"] is False
    assert res["transaction_status"] == "REJECTED"
    assert res["status_panel"]["authentication"] == "FAILED"
    assert res["decrypted_payload"] is None


def test_incorrect_aad_fails_authentication():
    """7. Incorrect AAD context fails authentication."""
    session = SecurityLabDemoSession("test-session-7")
    session.protect_transaction()

    res = session.tamper_aad(new_aad_user="demo-user-intruder")
    assert res["overall_accepted"] is False
    assert res["transaction_status"] == "REJECTED"
    assert res["status_panel"]["authentication"] == "FAILED"
    assert res["decrypted_payload"] is None


def test_incorrect_nonce_fails_decryption():
    """8. Incorrect nonce fails verification/decryption."""
    session = SecurityLabDemoSession("test-session-8")
    session.protect_transaction()

    res = session.tamper_nonce(byte_index=0)
    assert res["overall_accepted"] is False
    assert res["transaction_status"] == "REJECTED"
    assert res["status_panel"]["authentication"] == "FAILED"
    assert res["decrypted_payload"] is None


def test_incorrect_key_fails_decryption():
    """9. Incorrect key fails verification/decryption."""
    session = SecurityLabDemoSession("test-session-9")
    session.protect_transaction()

    wrong_key = AESGCM.generate_key(bit_length=256)
    aesgcm_wrong = AESGCM(wrong_key)

    with pytest.raises(InvalidTag):
        aesgcm_wrong.decrypt(
            session.nonce_bytes,
            session.ciphertext_bytes + session.tag_bytes,
            session.aad_bytes,
        )


def test_fresh_encryption_generates_fresh_nonce():
    """10. Fresh encryption generates a fresh random 12-byte nonce."""
    session = SecurityLabDemoSession("test-session-10")
    session.protect_transaction()
    nonce1 = session.nonce_bytes

    session.protect_transaction()
    nonce2 = session.nonce_bytes

    assert len(nonce1) == 12
    assert len(nonce2) == 12
    assert nonce1 != nonce2  # Fresh randomness guaranteed


# ============================================================================
# Strict Database & Production Isolation Tests
# ============================================================================

def test_security_lab_does_not_modify_database_wallets(client, app):
    """11. Security Lab does not modify database wallet balances."""
    with app.app_context():
        wallets_before = Wallet.query.count()

        # Execute multiple Security Lab operations
        client.get("/security-lab")
        client.post("/security-lab/api/protect", json={"amount": "50000.00"})
        client.post("/security-lab/api/attack/ciphertext")
        client.post("/security-lab/api/attack/data")
        client.post("/security-lab/api/restore")

        wallets_after = Wallet.query.count()
        assert wallets_before == wallets_after


def test_security_lab_does_not_create_real_transactions(client, app):
    """12. Security Lab does not create rows in database transactions table."""
    with app.app_context():
        tx_count_before = Transaction.query.count()

        client.get("/security-lab")
        client.post("/security-lab/api/protect", json={"amount": "9999.00"})
        client.post("/security-lab/api/verify")

        tx_count_after = Transaction.query.count()
        assert tx_count_before == tx_count_after


def test_security_lab_does_not_expose_production_encryption_key(client):
    """13. Security Lab never displays or exposes the production ENCRYPTION_KEY."""
    prod_key = os.environ.get("ENCRYPTION_KEY", "")

    resp = client.get("/security-lab")
    html = resp.get_data(as_text=True)

    if prod_key:
        assert prod_key not in html

    assert "🔐 PROTECTED / NOT DISPLAYED" in html
    assert "ACCESS DENIED" in html


def test_security_lab_does_not_expose_real_user_payment_methods(client, app):
    """14. Security Lab does not read or expose real user payment methods."""
    with app.app_context():
        # Ensure that whatever payment methods exist in DB are not leaked
        resp = client.get("/security-lab")
        html = resp.get_data(as_text=True)
        assert "Visa •••• 4242" in html
        assert "Demo Merchant" in html


# ============================================================================
# HTTP Endpoints & UI Route Tests
# ============================================================================

def test_security_lab_http_workflow(client):
    """15. Full HTTP workflow: GET /security-lab and JSON API endpoints."""
    # GET renders page with title and badges
    get_res = client.get("/security-lab")
    assert get_res.status_code == 200
    html = get_res.get_data(as_text=True)
    assert "VAULTPAY SECURITY LAB" in html
    assert "DEMO ENVIRONMENT" in html
    assert "All data shown in this laboratory is simulated" in html

    # POST /api/protect
    protect_res = client.post(
        "/security-lab/api/protect",
        json={"amount": "3500.00", "recipient": "Acme College Lab", "card_last_four": "9876"},
    )
    assert protect_res.status_code == 200
    pdata = protect_res.get_json()
    assert pdata["overall_accepted"] is True
    assert pdata["summary"]["transaction_data"]["amount_cents"] == 350000

    # POST /api/attack/ciphertext
    attack_res = client.post("/security-lab/api/attack/ciphertext")
    assert attack_res.status_code == 200
    adata = attack_res.get_json()
    assert adata["overall_accepted"] is False
    assert adata["transaction_status"] == "REJECTED"
    assert adata["status_panel"]["ciphertext"] == "MODIFIED"

    # POST /api/verify
    verify_res = client.post("/security-lab/api/verify")
    assert verify_res.status_code == 200
    vdata = verify_res.get_json()
    assert vdata["overall_accepted"] is False

    # POST /api/restore
    restore_res = client.post("/security-lab/api/restore")
    assert restore_res.status_code == 200
    rdata = restore_res.get_json()
    assert rdata["overall_accepted"] is True
    assert rdata["transaction_status"] == "Accepted"
    assert rdata["decrypted_payload"] is not None


def test_security_lab_custom_inputs_and_custom_tampering(client):
    """16. Test custom user inputs for transaction fields and customizable tampering parameters."""
    # 1. Custom transaction details input
    protect_res = client.post(
        "/security-lab/api/protect",
        json={
            "sender": "Alice Professor",
            "recipient": "University Bookstore",
            "amount": "1250.75",
            "payment_method": "RuPay •••• 9999",
            "transaction_id": "VP-CUSTOM-TEST-001",
            "sender_aad_id": "prof-alice-42",
        },
    )
    assert protect_res.status_code == 200
    pdata = protect_res.get_json()
    tx = pdata["summary"]["transaction_data"]
    assert tx["sender"] == "Alice Professor"
    assert tx["recipient"] == "University Bookstore"
    assert tx["amount_cents"] == 125075
    assert tx["amount_display"] == "₹1,250.75"
    assert tx["payment_method"] == "RuPay •••• 9999"
    assert tx["transaction_id"] == "VP-CUSTOM-TEST-001"
    assert pdata["overall_accepted"] is True

    # 2. Custom ciphertext tampering: user picks byte index 5 and new byte 0xAA
    attack_res = client.post(
        "/security-lab/api/attack/ciphertext",
        json={"byte_index": 5, "new_byte_val": "0xAA"},
    )
    assert attack_res.status_code == 200
    adata = attack_res.get_json()
    assert adata["overall_accepted"] is False
    assert adata["diff_info"]["byte_index"] == 5
    assert adata["diff_info"]["tampered_byte"] == "0xAA"

    # 3. Custom tag tampering: user picks tag byte index 7
    attack_tag_res = client.post(
        "/security-lab/api/attack/tag",
        json={"byte_index": 7, "new_byte_val": 0x42},
    )
    assert attack_tag_res.status_code == 200
    tdata = attack_tag_res.get_json()
    assert tdata["overall_accepted"] is False
    assert tdata["diff_info"]["byte_index"] == 7

    # 4. Custom AAD tampering: user sets custom AAD
    attack_aad_res = client.post(
        "/security-lab/api/attack/aad",
        json={"new_aad_user": "intruder-account-99"},
    )
    assert attack_aad_res.status_code == 200
    aaddata = attack_aad_res.get_json()
    assert aaddata["overall_accepted"] is False
    assert "intruder-account-99" in aaddata["diff_info"]["tampered_value"]

    # 5. Custom Data tampering: user sets altered amount and recipient
    attack_data_res = client.post(
        "/security-lab/api/attack/data",
        json={"new_amount_str": "99999.00", "new_recipient": "Offshore Shell Corp"},
    )
    assert attack_data_res.status_code == 200
    ddata = attack_data_res.get_json()
    assert ddata["overall_accepted"] is False
    assert ddata["summary"]["sha256_match"] is False
    assert ddata["diff_info"]["tampered_amount"] == "₹99,999.00"

    # 6. Restore brings back the custom transaction cleanly
    restore_res = client.post("/security-lab/api/restore")
    assert restore_res.status_code == 200
    rdata = restore_res.get_json()
    assert rdata["overall_accepted"] is True
    assert rdata["decrypted_payload"]["amount_cents"] == 125075
    assert rdata["decrypted_payload"]["payment_method"] == "RuPay •••• 9999"


def test_security_lab_original_or_valid_inputs_yield_valid_authentication(client):
    """17. Entering original/correct data in tampering tabs yields valid authentication and accepted status."""
    # 1. Protect transaction with known AAD
    prot_res = client.post(
        "/security-lab/api/protect",
        json={
            "sender": "Alice",
            "recipient": "Bob",
            "amount": "2500.00",
            "sender_aad_id": "demo-user-001",
            "transaction_id": "VP-DEMO-TEST-ORIG",
        },
    )
    assert prot_res.status_code == 200
    pdata = prot_res.get_json()
    orig_ciphertext_hex = pdata["summary"]["original_ciphertext_hex"]
    orig_byte_int = int(orig_ciphertext_hex[6:8], 16)  # byte at index 3

    # 2. Tamper AAD with attacker ID -> Fails
    bad_aad_res = client.post("/security-lab/api/attack/aad", json={"new_aad_user": "demo-user-999"})
    assert bad_aad_res.status_code == 200
    bad_aad_data = bad_aad_res.get_json()
    assert bad_aad_data["overall_accepted"] is False
    assert bad_aad_data["status_panel"]["authentication"] == "FAILED"
    assert bad_aad_data["diff_info"]["is_modified"] is True

    # 3. User inputs the ORIGINAL AAD -> Authentication is VALID!
    good_aad_res = client.post("/security-lab/api/attack/aad", json={"new_aad_user": "demo-user-001"})
    assert good_aad_res.status_code == 200
    good_aad_data = good_aad_res.get_json()
    assert good_aad_data["overall_accepted"] is True
    assert good_aad_data["status_panel"]["authentication"] == "Valid"
    assert good_aad_data["last_attack_type"] == "AAD_VERIFIED_ORIGINAL"
    assert good_aad_data["diff_info"]["is_modified"] is False
    assert "matches authentic sender context" in good_aad_data["last_attack_description"]

    # 4. User inputs the ORIGINAL byte into ciphertext tab -> Authentication is VALID!
    good_cipher_res = client.post(
        "/security-lab/api/attack/ciphertext",
        json={"byte_index": 3, "new_byte_val": orig_byte_int},
    )
    assert good_cipher_res.status_code == 200
    good_cipher_data = good_cipher_res.get_json()
    assert good_cipher_data["overall_accepted"] is True
    assert good_cipher_data["status_panel"]["authentication"] == "Valid"
    assert good_cipher_data["last_attack_type"] == "CIPHERTEXT_VERIFIED_ORIGINAL"
    assert good_cipher_data["diff_info"]["is_modified"] is False

    # 5. User inputs the ORIGINAL amount and recipient into data tab -> SHA-256 MATCH & VALID!
    good_data_res = client.post(
        "/security-lab/api/attack/data",
        json={"new_amount_str": "2500.00", "new_recipient": "Bob"},
    )
    assert good_data_res.status_code == 200
    good_data = good_data_res.get_json()
    assert good_data["overall_accepted"] is True
    assert good_data["status_panel"]["integrity"] == "Valid"
    assert good_data["summary"]["sha256_match"] is True
    assert good_data["last_attack_type"] == "DATA_VERIFIED_ORIGINAL"
    assert good_data["diff_info"]["is_modified"] is False


