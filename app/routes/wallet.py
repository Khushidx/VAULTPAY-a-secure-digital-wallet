"""
Wallet Blueprint.

Handles wallet dashboard, simulated deposit operations, and transaction history.
Enforces strict server-side validation, integer-cent arithmetic, and authorization boundaries.
"""

from flask import Blueprint, flash, redirect, render_template, request, url_for, g
from app.utils.decorators import login_required
from app.utils.money_integer_cents import parse_amount_to_cents, format_cents
from app.forms.wallet import DepositForm, TransferForm
from app.services.wallet_service import (
    get_or_create_user_wallet,
    deposit_funds,
    transfer_funds,
    get_wallet_transactions,
)
from app.services.payment_method_service import get_user_payment_methods

wallet_bp = Blueprint("wallet", __name__, url_prefix="/wallet")


@wallet_bp.route("")
@wallet_bp.route("/")
@wallet_bp.route("/dashboard")
@login_required
def dashboard():
    """
    Renders the authenticated user's wallet dashboard.
    Retrieves the wallet belonging strictly to g.current_user (IDOR protection).
    """
    wallet = get_or_create_user_wallet(g.current_user.id)
    recent_transactions = get_wallet_transactions(wallet.id, limit=5)
    payment_methods = get_user_payment_methods(g.current_user.id)
    
    return render_template(
        "wallet/dashboard.html",
        user=g.current_user,
        wallet=wallet,
        transactions=recent_transactions,
        payment_methods=payment_methods,
    )


@wallet_bp.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    """
    Simulated deposit handler.
    Validates amounts on the server using integer cents, rejects non-positive values,
    and executes atomic transaction logging.
    """
    wallet = get_or_create_user_wallet(g.current_user.id)
    form = DepositForm()

    if form.validate_on_submit():
        # Server-side validation of amount into integer cents
        is_valid, amount_cents, error_msg = parse_amount_to_cents(form.amount.data)
        
        if not is_valid:
            flash(error_msg, "danger")
            return render_template("wallet/deposit.html", form=form, wallet=wallet), 400

        try:
            # Atomic deposit execution
            tx = deposit_funds(
                user_id=g.current_user.id,
                amount_cents=amount_cents,
                description=form.description.data,
            )
            flash(
                f"Deposit of {format_cents(amount_cents)} completed successfully! (Ref: {tx.reference_id[:8]}...)",
                "success",
            )
            return redirect(url_for("wallet.dashboard"))

        except Exception as e:
            flash(f"Deposit failed: {str(e)}", "danger")
            return render_template("wallet/deposit.html", form=form, wallet=wallet), 500

    return render_template("wallet/deposit.html", form=form, wallet=wallet)


@wallet_bp.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    """
    Simulated peer-to-peer transfer handler.
    Validates recipient existence, positive integer cents, sufficient sender balance,
    and prohibits self-transfers. Executes inside an atomic transaction.
    """
    wallet = get_or_create_user_wallet(g.current_user.id)
    form = TransferForm()

    if form.validate_on_submit():
        # Validate amount into integer cents
        is_valid, amount_cents, err_msg = parse_amount_to_cents(form.amount.data)
        if not is_valid:
            flash(err_msg, "danger")
            return render_template("wallet/transfer.html", form=form, wallet=wallet), 400

        recipient_id = form.recipient.data.strip()

        try:
            tx_sender, tx_recipient = transfer_funds(
                sender_user_id=g.current_user.id,
                recipient_identifier=recipient_id,
                amount_cents=amount_cents,
                note=form.note.data,
            )
            flash(
                f"Successfully sent {format_cents(amount_cents)} to @{recipient_id}! (Ref: {tx_sender.reference_id[:8]}...)",
                "success",
            )
            return redirect(url_for("wallet.dashboard"))

        except ValueError as val_err:
            flash(str(val_err), "danger")
            return render_template("wallet/transfer.html", form=form, wallet=wallet), 400
        except Exception as exc:
            flash(f"Transfer failed: {str(exc)}", "danger")
            return render_template("wallet/transfer.html", form=form, wallet=wallet), 500

    return render_template("wallet/transfer.html", form=form, wallet=wallet)


@wallet_bp.route("/history")
@login_required
def history():
    """
    Renders full transaction history for the authenticated user's wallet.
    """
    wallet = get_or_create_user_wallet(g.current_user.id)
    transactions = get_wallet_transactions(wallet.id, limit=100)
    
    return render_template(
        "wallet/history.html",
        wallet=wallet,
        transactions=transactions,
    )


@wallet_bp.after_request
def add_wallet_cache_headers(response):
    """
    Prevents browsers from caching financial views.
    """
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response
