"""
Security Lab Blueprint.

Routes and endpoints for the interactive VaultPay Security Lab:
- GET  /security-lab            -> Renders interactive security laboratory
- POST /security-lab/api/protect -> Protects a simulated VaultPay transaction
- POST /security-lab/api/attack/<type> -> Simulates controlled cryptographic attack
- POST /security-lab/api/verify  -> Executes complete security check pipeline
- POST /security-lab/api/restore -> Restores pristine demo record and verifies decryption
"""

import secrets
from flask import Blueprint, jsonify, render_template, request, session
from app.services.security_demo_service import security_lab_manager

security_lab_bp = Blueprint("security_lab", __name__, url_prefix="/security-lab")


def _get_demo_session():
    """Retrieves or provisions the isolated in-memory demo session."""
    lab_id = session.get("security_lab_id")
    if not lab_id:
        lab_id = secrets.token_hex(16)
        session["security_lab_id"] = lab_id
    return security_lab_manager.get_or_create_session(lab_id)


@security_lab_bp.route("", methods=["GET"])
@security_lab_bp.route("/", methods=["GET"])
def index():
    """
    Renders the interactive VaultPay Security Lab.
    """
    demo_session = _get_demo_session()
    verification_data = demo_session.run_verification()
    return render_template(
        "security_lab/index.html",
        demo=verification_data,
        summary=verification_data["summary"],
        status_panel=verification_data["status_panel"],
        checklist=verification_data["checklist"],
    )


@security_lab_bp.route("/api/protect", methods=["POST"])
def api_protect():
    """
    Protects a simulated VaultPay transaction with integer representation,
    SHA-256 fingerprinting, and AES-256-GCM AEAD encryption.
    """
    demo_session = _get_demo_session()
    data = request.get_json(silent=True) or request.form or {}

    sender = str(data.get("sender", "Demo User")).strip()
    amount_str = str(data.get("amount", "2500.00")).strip()
    recipient = str(data.get("recipient", "Demo Merchant")).strip()
    card_last_four = str(data.get("card_last_four", "4242")).strip()
    payment_method = data.get("payment_method")
    tx_id = data.get("transaction_id")
    aad_id = data.get("sender_aad_id")

    demo_session.protect_transaction(
        sender=sender,
        amount_str=amount_str,
        recipient=recipient,
        card_last_four=card_last_four,
        payment_method=payment_method,
        transaction_id=tx_id,
        sender_aad_id=aad_id,
    )
    result = demo_session.run_verification()
    return jsonify(result)


@security_lab_bp.route("/api/attack/<attack_type>", methods=["POST"])
def api_attack(attack_type: str):
    """
    Simulates a controlled cryptographic attack against the protected record.
    Supports default 1-click tampering or custom user-supplied byte offsets,
    hex payloads, and data values.
    """
    demo_session = _get_demo_session()
    data = request.get_json(silent=True) or request.form or {}
    attack_type = attack_type.lower()

    # Parse optional user-supplied tampering parameters
    byte_index = data.get("byte_index")
    if byte_index is not None:
        try:
            byte_index = int(byte_index)
        except (ValueError, TypeError):
            byte_index = None

    new_byte_val = data.get("new_byte_val")
    if new_byte_val is not None and str(new_byte_val).strip() != "":
        try:
            val_str = str(new_byte_val).strip()
            if val_str.startswith(("0x", "0X")):
                new_byte_val = int(val_str, 16)
            elif all(c in "0123456789ABCDEFabcdef" for c in val_str) and len(val_str) <= 2:
                new_byte_val = int(val_str, 16)
            else:
                new_byte_val = int(val_str)
        except (ValueError, TypeError):
            new_byte_val = None
    else:
        new_byte_val = None

    custom_hex = data.get("custom_hex")

    if attack_type == "ciphertext":
        idx = byte_index if byte_index is not None else 3
        result = demo_session.tamper_ciphertext(
            byte_index=idx, new_byte_val=new_byte_val, custom_hex=custom_hex
        )
    elif attack_type in ["tag", "auth_tag"]:
        idx = byte_index if byte_index is not None else 0
        result = demo_session.tamper_auth_tag(
            byte_index=idx, new_byte_val=new_byte_val, custom_hex=custom_hex
        )
    elif attack_type == "nonce":
        idx = byte_index if byte_index is not None else 0
        result = demo_session.tamper_nonce(
            byte_index=idx, new_byte_val=new_byte_val, custom_hex=custom_hex
        )
    elif attack_type == "aad":
        new_aad_user = data.get("new_aad_user")
        custom_aad_full = data.get("custom_aad_full")
        result = demo_session.tamper_aad(
            new_aad_user=new_aad_user, custom_aad_full=custom_aad_full
        )
    elif attack_type in ["data", "transaction_data"]:
        new_amount_str = data.get("new_amount_str")
        new_amount_cents = data.get("new_amount_cents")
        new_recipient = data.get("new_recipient")
        new_sender = data.get("new_sender")
        new_payment_method = data.get("new_payment_method")

        if new_amount_cents is None and new_amount_str is None:
            new_amount_cents = 2500000  # Default ₹25,000.00 demo change

        result = demo_session.tamper_transaction_data(
            new_amount_cents=new_amount_cents,
            new_amount_str=new_amount_str,
            new_recipient=new_recipient,
            new_sender=new_sender,
            new_payment_method=new_payment_method,
        )
    else:
        return jsonify({"error": f"Unsupported attack type '{attack_type}'."}), 400

    return jsonify(result)


@security_lab_bp.route("/api/verify", methods=["POST"])
def api_verify():
    """
    Runs the multi-step security verification pipeline on the current record.
    """
    demo_session = _get_demo_session()
    result = demo_session.run_verification()
    return jsonify(result)


@security_lab_bp.route("/api/restore", methods=["POST"])
def api_restore():
    """
    Restores the clean demo record and runs real AES-GCM verification/decryption.
    """
    demo_session = _get_demo_session()
    result = demo_session.restore_original_record()
    return jsonify(result)
