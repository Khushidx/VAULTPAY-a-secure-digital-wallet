"""
Security Demo Service for VaultPay Security Lab.

Provides isolated, in-memory simulation of the VaultPay security architecture:
1. Integer-cent monetary representation (eliminates floating-point rounding errors).
2. Deterministic SHA-256 transaction integrity fingerprinting.
3. AES-256-GCM authenticated encryption (AEAD) with 12-byte random nonce,
   16-byte authentication tag, and Authenticated Associated Data (AAD) binding.
4. Real-time controlled tampering simulations (1-byte ciphertext mutation,
   auth tag mutation, nonce alteration, AAD modification, data alteration).
5. Real backend cryptographic verification via Python's `cryptography` library.

Strict Isolation:
- Never interacts with production database or real wallet balances.
- Uses ephemeral in-memory 256-bit demo keys (never touches ENCRYPTION_KEY).
- Does not expose secret keys to the client.
"""

from collections import OrderedDict
from datetime import datetime, timezone
import hashlib
import json
import os
import secrets
from threading import Lock
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.utils.money_integer_cents import format_cents, parse_amount_to_cents


class SecurityLabDemoSession:
    """Represents an isolated Security Lab demonstration state."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        # Isolated 256-bit symmetric key generated exclusively for this demo session
        self.demo_key = secrets.token_bytes(32)
        self.created_at = datetime.now(timezone.utc)
        self.reset_to_default()

    def reset_to_default(self) -> None:
        """Initializes pristine demo transaction and protected state."""
        self.transaction_data = {
            "transaction_id": f"VP-DEMO-{secrets.token_hex(4).upper()}",
            "sender": "Demo User",
            "recipient": "Demo Merchant",
            "amount_display": "₹2,500.00",
            "amount_cents": 250000,
            "currency": "INR",
            "payment_method": "Visa •••• 4242",
            "timestamp": "2026-09-23T14:30:00Z",
            "status": "AUTHORIZED — DEMO ONLY",
            "sender_aad_id": "demo-user-001",
        }
        self.sensitive_payload = {
            "transaction_id": self.transaction_data["transaction_id"],
            "amount_cents": 250000,
            "payment_method": "Visa •••• 4242",
            "auth_code": "VP-AUTH-9092",
            "routing_point": "IN-MUM-SRV-01",
        }
        # Cryptographic records
        self.is_protected = False
        self.original_sha256 = ""
        self.current_sha256 = ""
        self.nonce_bytes = b""
        self.ciphertext_bytes = b""
        self.tag_bytes = b""
        self.aad_bytes = b""

        # Active modified state
        self.active_nonce_bytes = b""
        self.active_ciphertext_bytes = b""
        self.active_tag_bytes = b""
        self.active_aad_bytes = b""
        self.active_transaction_data = dict(self.transaction_data)

        # Attack mutation details
        self.last_attack_type: Optional[str] = None
        self.last_attack_description: Optional[str] = None
        self.last_diff_info: Optional[Dict[str, Any]] = None

    def protect_transaction(
        self,
        sender: str = "Demo User",
        recipient: str = "Demo Merchant",
        amount_str: str = "2500.00",
        card_last_four: str = "4242",
        payment_method: Optional[str] = None,
        transaction_id: Optional[str] = None,
        sender_aad_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes the VaultPay protection pipeline:
        1. Validates & parses amount to integer cents (paise).
        2. Computes deterministic SHA-256 fingerprint.
        3. Encrypts sensitive payload with AES-256-GCM & binds AAD.
        """
        # 1. Financial representation in integer paise
        is_valid, amount_cents, err = parse_amount_to_cents(amount_str)
        if not is_valid:
            amount_cents = 250000

        clean_last_four = str(card_last_four).strip()[-4:] if card_last_four else "4242"
        clean_tx_id = (transaction_id or self.transaction_data["transaction_id"]).strip()
        clean_sender = sender.strip() or "Demo User"
        clean_recipient = recipient.strip() or "Demo Merchant"
        clean_method = (
            payment_method.strip()
            if payment_method
            else f"Visa •••• {clean_last_four}"
        )
        clean_aad_id = (sender_aad_id or self.transaction_data.get("sender_aad_id", "demo-user-001")).strip()

        self.transaction_data.update({
            "transaction_id": clean_tx_id,
            "sender": clean_sender,
            "recipient": clean_recipient,
            "amount_cents": amount_cents,
            "amount_display": format_cents(amount_cents),
            "payment_method": clean_method,
            "sender_aad_id": clean_aad_id,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
        self.active_transaction_data = dict(self.transaction_data)

        # 2. SHA-256 Integrity Fingerprint
        canonical_json = json.dumps(
            self.transaction_data, sort_keys=True, separators=(",", ":")
        )
        self.original_sha256 = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        self.current_sha256 = self.original_sha256

        # 3. Sensitive payload & AAD
        self.sensitive_payload = {
            "transaction_id": clean_tx_id,
            "amount_cents": amount_cents,
            "payment_method": clean_method,
            "auth_code": f"VP-AUTH-{secrets.token_hex(2).upper()}",
            "routing_point": "IN-MUM-SRV-01",
        }
        payload_bytes = json.dumps(
            self.sensitive_payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

        # AAD context mathematically binding sender & transaction ID
        self.aad_bytes = f"{clean_tx_id}|{clean_aad_id}".encode("utf-8")

        # 4. Fresh 12-byte random nonce per operation (NIST SP 800-38D requirement)
        self.nonce_bytes = os.urandom(12)

        # 5. Real AES-256-GCM authenticated encryption
        aesgcm = AESGCM(self.demo_key)
        ciphertext_and_tag = aesgcm.encrypt(self.nonce_bytes, payload_bytes, self.aad_bytes)

        # Separate ciphertext and 16-byte authentication tag
        self.ciphertext_bytes = ciphertext_and_tag[:-16]
        self.tag_bytes = ciphertext_and_tag[-16:]

        # Copy pristine into active
        self.active_nonce_bytes = bytes(self.nonce_bytes)
        self.active_ciphertext_bytes = bytes(self.ciphertext_bytes)
        self.active_tag_bytes = bytes(self.tag_bytes)
        self.active_aad_bytes = bytes(self.aad_bytes)

        self.is_protected = True
        self.last_attack_type = None
        self.last_attack_description = None
        self.last_diff_info = None

        return self.get_summary()

    def tamper_ciphertext(
        self,
        byte_index: int = 3,
        new_byte_val: Optional[int] = None,
        custom_hex: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Simulates an attacker modifying ONE BYTE of the ciphertext or applying a custom payload.
        """
        if not self.is_protected:
            self.protect_transaction()

        # Reset other active buffers to baseline
        self.active_tag_bytes = bytes(self.tag_bytes)
        self.active_nonce_bytes = bytes(self.nonce_bytes)
        self.active_aad_bytes = bytes(self.aad_bytes)
        self.active_transaction_data = dict(self.transaction_data)
        self.current_sha256 = self.original_sha256

        if custom_hex:
            try:
                cleaned_hex = "".join(custom_hex.split())
                mutated = bytes.fromhex(cleaned_hex)
                self.active_ciphertext_bytes = mutated
                is_modified = self.active_ciphertext_bytes != self.ciphertext_bytes
                if is_modified:
                    self.last_attack_type = "CIPHERTEXT_MODIFIED"
                    self.last_attack_description = "Custom ciphertext hex payload applied by user."
                    marker = "Custom payload applied (ALTERED)"
                else:
                    self.last_attack_type = "CIPHERTEXT_VERIFIED_ORIGINAL"
                    self.last_attack_description = "Custom ciphertext matches original authentic ciphertext."
                    marker = "✓ Identical (Ciphertext Intact)"
                self.last_diff_info = {
                    "target": "Ciphertext",
                    "original_byte": "N/A",
                    "tampered_byte": "Custom Hex",
                    "before_hex": " ".join(f"{b:02X}" for b in self.ciphertext_bytes[:16]),
                    "after_hex": " ".join(f"{b:02X}" for b in self.active_ciphertext_bytes[:16]),
                    "marker": marker,
                    "is_modified": is_modified,
                }
                return self.run_verification()
            except ValueError:
                pass

        idx = max(0, min(byte_index, len(self.ciphertext_bytes) - 1))
        orig_byte = self.ciphertext_bytes[idx]
        if new_byte_val is not None:
            tampered_byte = new_byte_val & 0xFF
        else:
            tampered_byte = orig_byte ^ 0x01

        mutated = bytearray(self.ciphertext_bytes)
        mutated[idx] = tampered_byte
        self.active_ciphertext_bytes = bytes(mutated)
        is_modified = tampered_byte != orig_byte

        # Generate hex snippet comparison around the modified byte
        start_idx = max(0, idx - 4)
        end_idx = min(len(self.ciphertext_bytes), start_idx + 16)
        slice_orig = self.ciphertext_bytes[start_idx:end_idx]
        slice_tamp = self.active_ciphertext_bytes[start_idx:end_idx]

        orig_hex_tokens = [f"{b:02X}" for b in slice_orig]
        tamp_hex_tokens = [f"{b:02X}" for b in slice_tamp]
        marker_tokens = ["^^" if (start_idx + i) == idx and is_modified else "  " for i in range(len(slice_orig))]

        if is_modified:
            self.last_attack_type = "CIPHERTEXT_MODIFIED"
            self.last_attack_description = (
                f"1-byte modification simulated at byte offset {idx}: "
                f"0x{orig_byte:02X} ➔ 0x{tampered_byte:02X}."
            )
            marker_str = " ".join(marker_tokens) + " (CHANGED)"
        else:
            self.last_attack_type = "CIPHERTEXT_VERIFIED_ORIGINAL"
            self.last_attack_description = (
                f"Byte at offset {idx} matches original authentic byte (0x{orig_byte:02X})."
            )
            marker_str = "✓ Identical (Authentic Byte Intact)"

        self.last_diff_info = {
            "target": "Ciphertext",
            "byte_index": idx,
            "original_byte": f"0x{orig_byte:02X}",
            "tampered_byte": f"0x{tampered_byte:02X}",
            "before_hex": " ".join(orig_hex_tokens),
            "after_hex": " ".join(tamp_hex_tokens),
            "marker": marker_str,
            "is_modified": is_modified,
        }
        return self.run_verification()

    def tamper_auth_tag(
        self,
        byte_index: int = 0,
        new_byte_val: Optional[int] = None,
        custom_hex: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Simulates an attacker modifying ONE BYTE of the 16-byte authentication tag or custom tag.
        """
        if not self.is_protected:
            self.protect_transaction()

        # Reset other active buffers to baseline
        self.active_ciphertext_bytes = bytes(self.ciphertext_bytes)
        self.active_nonce_bytes = bytes(self.nonce_bytes)
        self.active_aad_bytes = bytes(self.aad_bytes)
        self.active_transaction_data = dict(self.transaction_data)
        self.current_sha256 = self.original_sha256

        if custom_hex:
            try:
                cleaned_hex = "".join(custom_hex.split())
                mutated = bytes.fromhex(cleaned_hex)
                self.active_tag_bytes = mutated
                is_modified = self.active_tag_bytes != self.tag_bytes
                if is_modified:
                    self.last_attack_type = "TAG_MODIFIED"
                    self.last_attack_description = "Custom authentication tag applied by user."
                    marker = "Custom tag applied (ALTERED)"
                else:
                    self.last_attack_type = "TAG_VERIFIED_ORIGINAL"
                    self.last_attack_description = "Custom authentication tag matches original authentic tag."
                    marker = "✓ Identical (Auth Tag Intact)"
                self.last_diff_info = {
                    "target": "Authentication Tag",
                    "original_byte": "N/A",
                    "tampered_byte": "Custom Tag",
                    "before_hex": " ".join(f"{b:02X}" for b in self.tag_bytes),
                    "after_hex": " ".join(f"{b:02X}" for b in self.active_tag_bytes),
                    "marker": marker,
                    "is_modified": is_modified,
                }
                return self.run_verification()
            except ValueError:
                pass

        idx = max(0, min(byte_index, len(self.tag_bytes) - 1))
        orig_byte = self.tag_bytes[idx]
        if new_byte_val is not None:
            tampered_byte = new_byte_val & 0xFF
        else:
            tampered_byte = orig_byte ^ 0x01

        mutated = bytearray(self.tag_bytes)
        mutated[idx] = tampered_byte
        self.active_tag_bytes = bytes(mutated)
        is_modified = tampered_byte != orig_byte

        orig_hex = " ".join(f"{b:02X}" for b in self.tag_bytes)
        tamp_hex = " ".join(f"{b:02X}" for b in self.active_tag_bytes)
        marker = " ".join("^^" if i == idx and is_modified else "  " for i in range(len(self.tag_bytes)))

        if is_modified:
            self.last_attack_type = "TAG_MODIFIED"
            self.last_attack_description = (
                f"Authentication tag altered at byte offset {idx}: "
                f"0x{orig_byte:02X} ➔ 0x{tampered_byte:02X}."
            )
            marker_str = marker + " (CHANGED)"
        else:
            self.last_attack_type = "TAG_VERIFIED_ORIGINAL"
            self.last_attack_description = (
                f"Authentication tag at byte offset {idx} matches original authentic byte (0x{orig_byte:02X})."
            )
            marker_str = "✓ Identical (Authentic Tag Intact)"

        self.last_diff_info = {
            "target": "Authentication Tag",
            "byte_index": idx,
            "original_byte": f"0x{orig_byte:02X}",
            "tampered_byte": f"0x{tampered_byte:02X}",
            "before_hex": orig_hex,
            "after_hex": tamp_hex,
            "marker": marker_str,
            "is_modified": is_modified,
        }
        return self.run_verification()

    def tamper_nonce(
        self,
        byte_index: int = 0,
        new_byte_val: Optional[int] = None,
        custom_hex: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Simulates modifying the 12-byte nonce used during encryption.
        """
        if not self.is_protected:
            self.protect_transaction()

        # Reset other active buffers to baseline
        self.active_ciphertext_bytes = bytes(self.ciphertext_bytes)
        self.active_tag_bytes = bytes(self.tag_bytes)
        self.active_aad_bytes = bytes(self.aad_bytes)
        self.active_transaction_data = dict(self.transaction_data)
        self.current_sha256 = self.original_sha256

        if custom_hex:
            try:
                cleaned_hex = "".join(custom_hex.split())
                mutated = bytes.fromhex(cleaned_hex)
                self.active_nonce_bytes = mutated
                is_modified = self.active_nonce_bytes != self.nonce_bytes
                if is_modified:
                    self.last_attack_type = "NONCE_MODIFIED"
                    self.last_attack_description = "Custom nonce applied by user."
                    marker = "Custom nonce applied (ALTERED)"
                else:
                    self.last_attack_type = "NONCE_VERIFIED_ORIGINAL"
                    self.last_attack_description = "Custom nonce matches original authentic 12-byte nonce."
                    marker = "✓ Identical (Nonce Intact)"
                self.last_diff_info = {
                    "target": "Nonce",
                    "original_byte": "N/A",
                    "tampered_byte": "Custom Nonce",
                    "before_hex": " ".join(f"{b:02X}" for b in self.nonce_bytes),
                    "after_hex": " ".join(f"{b:02X}" for b in self.active_nonce_bytes),
                    "marker": marker,
                    "is_modified": is_modified,
                }
                return self.run_verification()
            except ValueError:
                pass

        idx = max(0, min(byte_index, len(self.nonce_bytes) - 1))
        orig_byte = self.nonce_bytes[idx]
        if new_byte_val is not None:
            tampered_byte = new_byte_val & 0xFF
        else:
            tampered_byte = orig_byte ^ 0x01

        mutated = bytearray(self.nonce_bytes)
        mutated[idx] = tampered_byte
        self.active_nonce_bytes = bytes(mutated)
        is_modified = tampered_byte != orig_byte

        if is_modified:
            self.last_attack_type = "NONCE_MODIFIED"
            self.last_attack_description = (
                f"Nonce altered at byte {idx}: "
                f"0x{orig_byte:02X} ➔ 0x{tampered_byte:02X}."
            )
            marker_str = " ".join("^^" if i == idx else "  " for i in range(12)) + " (CHANGED)"
        else:
            self.last_attack_type = "NONCE_VERIFIED_ORIGINAL"
            self.last_attack_description = (
                f"Nonce at byte {idx} matches original authentic byte (0x{orig_byte:02X})."
            )
            marker_str = "✓ Identical (Authentic Nonce Intact)"

        self.last_diff_info = {
            "target": "Nonce",
            "byte_index": idx,
            "original_byte": f"0x{orig_byte:02X}",
            "tampered_byte": f"0x{tampered_byte:02X}",
            "before_hex": " ".join(f"{b:02X}" for b in self.nonce_bytes),
            "after_hex": " ".join(f"{b:02X}" for b in self.active_nonce_bytes),
            "marker": marker_str,
            "is_modified": is_modified,
        }
        return self.run_verification()

    def tamper_aad(
        self,
        new_aad_user: Optional[str] = None,
        custom_aad_full: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Simulates an attacker altering the Authenticated Associated Data context.
        """
        if not self.is_protected:
            self.protect_transaction()

        # Reset other active buffers to baseline
        self.active_ciphertext_bytes = bytes(self.ciphertext_bytes)
        self.active_tag_bytes = bytes(self.tag_bytes)
        self.active_nonce_bytes = bytes(self.nonce_bytes)
        self.active_transaction_data = dict(self.transaction_data)
        self.current_sha256 = self.original_sha256

        orig_str = self.aad_bytes.decode("utf-8")
        clean_tx_id = self.transaction_data["transaction_id"]

        if custom_aad_full is not None:
            tampered_str = custom_aad_full.strip()
        else:
            user_suffix = (new_aad_user or "demo-user-999").strip()
            tampered_str = f"{clean_tx_id}|{user_suffix}"

        self.active_aad_bytes = tampered_str.encode("utf-8")
        is_modified = self.active_aad_bytes != self.aad_bytes

        if is_modified:
            self.last_attack_type = "AAD_MODIFIED"
            self.last_attack_description = (
                f"Associated Authenticated Data (AAD) swapped from '{orig_str}' to '{tampered_str}'."
            )
            marker_str = "Context identity swapped (UNAUTHORIZED)"
        else:
            self.last_attack_type = "AAD_VERIFIED_ORIGINAL"
            self.last_attack_description = (
                f"Associated Authenticated Data (AAD) matches authentic sender context: '{orig_str}'."
            )
            marker_str = "✓ Identical (Authentic AAD Context Intact)"

        self.last_diff_info = {
            "target": "Associated Data (AAD)",
            "original_value": orig_str,
            "tampered_value": tampered_str,
            "before_hex": orig_str,
            "after_hex": tampered_str,
            "marker": marker_str,
            "is_modified": is_modified,
        }
        return self.run_verification()

    def tamper_transaction_data(
        self,
        new_amount_cents: Optional[int] = None,
        new_amount_str: Optional[str] = None,
        new_recipient: Optional[str] = None,
        new_sender: Optional[str] = None,
        new_payment_method: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Simulates altering transaction data directly (amount, recipient, sender, etc.).
        Demonstrates SHA-256 integrity fingerprint mismatch.
        """
        if not self.is_protected:
            self.protect_transaction()

        # Reset other active buffers to baseline
        self.active_ciphertext_bytes = bytes(self.ciphertext_bytes)
        self.active_tag_bytes = bytes(self.tag_bytes)
        self.active_nonce_bytes = bytes(self.nonce_bytes)
        self.active_aad_bytes = bytes(self.aad_bytes)

        self.active_transaction_data = dict(self.transaction_data)

        if new_amount_str is not None:
            valid, cents, _ = parse_amount_to_cents(new_amount_str)
            if valid:
                self.active_transaction_data["amount_cents"] = cents
                self.active_transaction_data["amount_display"] = format_cents(cents)
        elif new_amount_cents is not None:
            self.active_transaction_data["amount_cents"] = new_amount_cents
            self.active_transaction_data["amount_display"] = format_cents(new_amount_cents)

        if new_recipient is not None:
            self.active_transaction_data["recipient"] = new_recipient.strip()

        if new_sender is not None:
            self.active_transaction_data["sender"] = new_sender.strip()

        if new_payment_method is not None:
            self.active_transaction_data["payment_method"] = new_payment_method.strip()

        canonical_json = json.dumps(
            self.active_transaction_data, sort_keys=True, separators=(",", ":")
        )
        self.current_sha256 = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        is_modified = self.current_sha256 != self.original_sha256

        if is_modified:
            self.last_attack_type = "DATA_MODIFIED"
            self.last_attack_description = (
                f"Simulated transaction modified: "
                f"Amount={self.active_transaction_data['amount_display']}, "
                f"Recipient='{self.active_transaction_data['recipient']}'."
            )
            marker_str = "Hash digest mismatch detected (CORRUPTED DATA)"
        else:
            self.last_attack_type = "DATA_VERIFIED_ORIGINAL"
            self.last_attack_description = (
                f"Transaction parameters match original record: "
                f"Amount={self.active_transaction_data['amount_display']}, "
                f"Recipient='{self.active_transaction_data['recipient']}'."
            )
            marker_str = "✓ Identical (SHA-256 fingerprint matches original)"

        self.last_diff_info = {
            "target": "Transaction Data",
            "original_amount": self.transaction_data["amount_display"],
            "tampered_amount": self.active_transaction_data["amount_display"],
            "original_hash": self.original_sha256,
            "current_hash": self.current_sha256,
            "marker": marker_str,
            "is_modified": is_modified,
        }
        return self.run_verification()

    def run_verification(self) -> Dict[str, Any]:
        """
        Executes the real Python cryptographic verification pipeline:
        1. Validates transaction data structure.
        2. Evaluates SHA-256 fingerprint matching.
        3. Invokes real AESGCM.decrypt() verifying tag and AAD.
        4. Rejects tampered data with TamperedDataError.
        """
        if not self.is_protected:
            self.protect_transaction()

        # Step 1: Structure check
        structure_valid = (
            bool(self.active_transaction_data.get("transaction_id"))
            and isinstance(self.active_transaction_data.get("amount_cents"), int)
            and self.active_transaction_data.get("amount_cents", 0) > 0
        )

        # Step 2: SHA-256 Integrity check
        canonical_active = json.dumps(
            self.active_transaction_data, sort_keys=True, separators=(",", ":")
        )
        computed_sha = hashlib.sha256(canonical_active.encode("utf-8")).hexdigest()
        sha_valid = computed_sha == self.original_sha256

        # Step 3 & 4: AES-256-GCM AEAD Tag & Ciphertext Integrity check
        aes_auth_valid = False
        ciphertext_valid = False
        decrypted_payload = None
        error_message = ""

        try:
            aesgcm = AESGCM(self.demo_key)
            # Full ciphertext_and_tag package
            package_to_verify = self.active_ciphertext_bytes + self.active_tag_bytes
            decrypted_raw = aesgcm.decrypt(
                self.active_nonce_bytes,
                package_to_verify,
                self.active_aad_bytes,
            )
            # Decryption succeeded: authentication tag and ciphertext are 100% genuine!
            aes_auth_valid = True
            ciphertext_valid = True
            decrypted_payload = json.loads(decrypted_raw.decode("utf-8"))
        except InvalidTag:
            # Real cryptographic failure raised by AESGCM
            aes_auth_valid = False
            ciphertext_valid = False
            error_message = (
                "AES-GCM authentication tag mismatch: Cryptographic verification failed! "
                "The ciphertext, authentication tag, nonce, or AAD has been altered."
            )
        except Exception as e:
            aes_auth_valid = False
            ciphertext_valid = False
            error_message = f"Decryption failure: {str(e)}"

        # Final acceptance rule: all cryptographic integrity checks must pass
        overall_accepted = structure_valid and sha_valid and aes_auth_valid and ciphertext_valid

        # Status indicators
        ciphertext_state = (
            "Unmodified"
            if self.active_ciphertext_bytes == self.ciphertext_bytes
            else "MODIFIED"
        )
        auth_state = "Valid" if aes_auth_valid else "FAILED"
        integrity_state = "Valid" if (sha_valid and ciphertext_valid) else "FAILED"
        transaction_status = "Accepted" if overall_accepted else "REJECTED"

        return {
            "session_id": self.session_id,
            "overall_accepted": overall_accepted,
            "transaction_status": transaction_status,
            "status_panel": {
                "encryption": "AES-256-GCM",
                "ciphertext": ciphertext_state,
                "authentication": auth_state,
                "integrity": integrity_state,
                "transaction": transaction_status,
            },
            "checklist": [
                {"name": "Transaction structure", "passed": structure_valid, "label": "Valid format"},
                {
                    "name": "SHA-256 integrity fingerprint",
                    "passed": sha_valid,
                    "label": "MATCH" if sha_valid else "MISMATCH",
                },
                {
                    "name": "AES-256-GCM authentication tag",
                    "passed": aes_auth_valid,
                    "label": "VALID" if aes_auth_valid else "FAILED (InvalidTag)",
                },
                {
                    "name": "Ciphertext integrity verification",
                    "passed": ciphertext_valid,
                    "label": "VERIFIED" if ciphertext_valid else "FAILED",
                },
                {
                    "name": "Authenticated Associated Data (AAD)",
                    "passed": (self.active_aad_bytes == self.aad_bytes and aes_auth_valid),
                    "label": "MATCH" if self.active_aad_bytes == self.aad_bytes else "MODIFIED",
                },
            ],
            "error_message": error_message,
            "decrypted_payload": decrypted_payload,
            "last_attack_type": self.last_attack_type,
            "last_attack_description": self.last_attack_description,
            "diff_info": self.last_diff_info,
            "summary": self.get_summary(),
        }

    def restore_original_record(self) -> Dict[str, Any]:
        """
        Restores all parameters to pristine demo state and verifies genuine decryption.
        """
        self.active_nonce_bytes = bytes(self.nonce_bytes)
        self.active_ciphertext_bytes = bytes(self.ciphertext_bytes)
        self.active_tag_bytes = bytes(self.tag_bytes)
        self.active_aad_bytes = bytes(self.aad_bytes)
        self.active_transaction_data = dict(self.transaction_data)
        self.current_sha256 = self.original_sha256
        self.last_attack_type = "RESTORED"
        self.last_attack_description = "Pristine demo transaction record restored."
        self.last_diff_info = {
            "target": "Full Record",
            "is_modified": False,
            "before_hex": "Authentic baseline",
            "after_hex": "Authentic baseline",
            "marker": "✓ All cryptographic parameters intact & authenticated",
        }

        return self.run_verification()

    def get_summary(self) -> Dict[str, Any]:
        """Returns structured JSON serialization for UI visualization."""
        return {
            "transaction_data": self.active_transaction_data,
            "original_transaction_data": self.transaction_data,
            "original_sha256": self.original_sha256,
            "current_sha256": self.current_sha256,
            "sha256_match": self.current_sha256 == self.original_sha256,
            "nonce_hex": self.active_nonce_bytes.hex().upper(),
            "nonce_formatted": " ".join(f"{b:02X}" for b in self.active_nonce_bytes),
            "ciphertext_hex": self.active_ciphertext_bytes.hex().upper(),
            "ciphertext_formatted": " ".join(f"{b:02X}" for b in self.active_ciphertext_bytes[:32]) + (
                " ..." if len(self.active_ciphertext_bytes) > 32 else ""
            ),
            "tag_hex": self.active_tag_bytes.hex().upper(),
            "tag_formatted": " ".join(f"{b:02X}" for b in self.active_tag_bytes),
            "aad_string": self.active_aad_bytes.decode("utf-8", errors="replace"),
            "original_ciphertext_hex": self.ciphertext_bytes.hex().upper(),
            "original_tag_hex": self.tag_bytes.hex().upper(),
            "original_nonce_hex": self.nonce_bytes.hex().upper(),
            "original_aad_user": self.transaction_data.get("sender_aad_id", "demo-user-001"),
            "original_aad_string": self.aad_bytes.decode("utf-8", errors="replace"),
            "key_display": "🔐 PROTECTED / NOT DISPLAYED",
            "is_protected": self.is_protected,
            "attacker_view": {
                "transaction_id": self.active_transaction_data.get("transaction_id"),
                "ciphertext": self.active_ciphertext_bytes.hex()[:48] + "...",
                "nonce": self.active_nonce_bytes.hex(),
                "authentication_tag": self.active_tag_bytes.hex(),
                "encryption_key": "❌ ACCESS DENIED / NOT STORED IN RECORD",
                "plaintext_data": "❌ ENCRYPTED CIPHERTEXT ONLY",
            },
        }


# Global thread-safe session registry for isolated Security Lab instances
class SecurityLabSessionManager:
    """Manages isolated in-memory demonstration sessions."""

    def __init__(self):
        self._sessions: Dict[str, SecurityLabDemoSession] = {}
        self._lock = Lock()

    def get_or_create_session(self, session_id: Optional[str] = None) -> SecurityLabDemoSession:
        sid = session_id or secrets.token_hex(16)
        with self._lock:
            if sid not in self._sessions:
                demo_session = SecurityLabDemoSession(sid)
                demo_session.protect_transaction()
                self._sessions[sid] = demo_session
            return self._sessions[sid]

    def clear_session(self, session_id: str) -> None:
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]


# Global manager singleton
security_lab_manager = SecurityLabSessionManager()
