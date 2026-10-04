"""
Payment Methods Blueprint.

Manages simulated funding sources (Demo Visa, Demo Mastercard, Demo Bank Account).
All routes are protected by @login_required and enforce strict IDOR boundaries.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, g, request
from app.utils.decorators import login_required
from app.forms.payment_method import PaymentMethodForm, RevealSecurityForm
from app.models.payment_method import PaymentMethod
from app.utils.password_sha256 import verify_password
from app.services.payment_method_service import (
    create_payment_method,
    get_user_payment_methods,
    get_payment_method_details,
    delete_payment_method,
)
from app.crypto_aes_gcm import TamperedDataError, DecryptionError

payment_methods_bp = Blueprint("payment_methods", __name__, url_prefix="/payment-methods")


@payment_methods_bp.route("", methods=["GET"])
@payment_methods_bp.route("/", methods=["GET"])
@login_required
def index():
    """
    Displays the user's saved simulated payment methods with tokens and masked identifiers.
    """
    methods = get_user_payment_methods(g.current_user.id)
    return render_template("payment_methods/index.html", methods=methods)


@payment_methods_bp.route("/new", methods=["GET", "POST"])
@login_required
def new_method():
    """
    Form to add a payment method.
    The sensitive metadata is encrypted using AES-256-GCM before saving.
    """
    form = PaymentMethodForm()

    if form.validate_on_submit():
        try:
            create_payment_method(
                user_id=g.current_user.id,
                method_type=form.method_type.data,
                name=form.name.data,
                last_four=form.last_four.data,
                metadata=form.demo_metadata.data or "",
                is_default=form.is_default.data,
                security_key=form.security_key.data,
            )
            flash(
                "Payment method added successfully! Token generated and metadata encrypted with AES-256-GCM.",
                "success",
            )
            return redirect(url_for("payment_methods.index"))
        except ValueError as e:
            flash(str(e), "danger")
        except Exception as e:
            flash("An unexpected error occurred while encrypting payment metadata.", "danger")

    return render_template("payment_methods/new.html", form=form)


@payment_methods_bp.route("/<int:method_id>/reveal", methods=["GET", "POST"])
@login_required
def reveal(method_id: int):
    """
    Step-up authentication: Verifies account password and 4-digit security PIN
    before decrypting AES-256-GCM metadata.
    """
    # Verify method belongs to current user (IDOR defense)
    method = PaymentMethod.query.filter_by(id=method_id, user_id=g.current_user.id).first()
    if not method:
        flash("Payment method not found or you are not authorized to view it.", "danger")
        return redirect(url_for("payment_methods.index"))

    form = RevealSecurityForm()

    if request.method == "POST" and form.validate_on_submit():
        # 1. Verify user account password
        pw_ok = verify_password(form.password.data, g.current_user.password_salt, g.current_user.password_hash)
        if not pw_ok:
            flash("Incorrect account password. Access denied.", "danger")
            return render_template("payment_methods/verify_reveal.html", method=method, form=form)

        # 2. Verify 4-digit security key and decrypt metadata
        try:
            method, decrypted_metadata = get_payment_method_details(
                g.current_user.id, 
                method_id, 
                security_key=form.security_key.data
            )
            return render_template(
                "payment_methods/reveal.html",
                method=method,
                decrypted_metadata=decrypted_metadata,
            )
        except TamperedDataError as e:
            flash(f"Cryptographic integrity alert: {str(e)}", "danger")
            return render_template("payment_methods/verify_reveal.html", method=method, form=form)
        except ValueError as e:
            flash(str(e), "danger")
            return render_template("payment_methods/verify_reveal.html", method=method, form=form)
        except Exception:
            flash("Decryption failed.", "danger")
            return render_template("payment_methods/verify_reveal.html", method=method, form=form)

    # GET request: render the step-up verification challenge form
    return render_template("payment_methods/verify_reveal.html", method=method, form=form)


@payment_methods_bp.route("/<int:method_id>/delete", methods=["POST"])
@login_required
def delete(method_id: int):
    """
    Deletes a saved demo payment method.
    """
    try:
        delete_payment_method(g.current_user.id, method_id)
        flash("Payment method removed successfully.", "info")
    except ValueError as e:
        flash(str(e), "danger")
    return redirect(url_for("payment_methods.index"))
