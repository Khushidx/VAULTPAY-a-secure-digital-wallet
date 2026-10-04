"""
Demo Cards Blueprint.

Demonstrates AES-256-GCM symmetric encryption of sensitive demonstration data at rest.
All routes are protected by @login_required and enforce strict IDOR boundaries.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, g, request
from app.utils.decorators import login_required
from app.forms.card import DemoCardForm
from app.services.card_service import (
    create_demo_card,
    get_user_cards,
    get_decrypted_card_details,
    delete_demo_card,
)
from app.crypto_aes_gcm import TamperedDataError, DecryptionError

cards_bp = Blueprint("cards", __name__, url_prefix="/cards")


@cards_bp.route("", methods=["GET"])
@cards_bp.route("/", methods=["GET"])
@login_required
def index():
    """
    Displays the user's saved demo cards with masked PANs and encryption status.
    """
    cards = get_user_cards(g.current_user.id)
    return render_template("cards/index.html", cards=cards)


@cards_bp.route("/new", methods=["GET", "POST"])
@login_required
def new_card():
    """
    Form to add a simulated demonstration card.
    The sensitive billing details are encrypted using AES-256-GCM before saving.
    """
    form = DemoCardForm()

    if form.validate_on_submit():
        try:
            create_demo_card(
                user_id=g.current_user.id,
                cardholder_name=form.cardholder_name.data,
                last_four=form.last_four.data,
                card_brand=form.card_brand.data,
                exp_month=form.exp_month.data,
                exp_year=form.exp_year.data,
                billing_details=form.billing_details.data or "",
            )
            flash(
                "Simulated card saved successfully! Billing details were encrypted with AES-256-GCM.",
                "success",
            )
            return redirect(url_for("cards.index"))
        except ValueError as e:
            flash(str(e), "danger")
        except Exception as e:
            flash("An unexpected error occurred while encrypting the card details.", "danger")

    return render_template("cards/new.html", form=form)


@cards_bp.route("/<int:card_id>/reveal", methods=["GET"])
@login_required
def reveal(card_id: int):
    """
    Educational demonstration: Decrypts AES-256-GCM ciphertext on demand
    and verifies the 16-byte authentication tag in real time.
    """
    try:
        card, decrypted_details = get_decrypted_card_details(g.current_user.id, card_id)
        return render_template(
            "cards/reveal.html",
            card=card,
            decrypted_details=decrypted_details,
        )
    except TamperedDataError as e:
        flash(f"Cryptographic integrity alert: {str(e)}", "danger")
        return redirect(url_for("cards.index"))
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for("cards.index"))
    except Exception as e:
        flash("Decryption failed.", "danger")
        return redirect(url_for("cards.index"))


@cards_bp.route("/<int:card_id>/delete", methods=["POST"])
@login_required
def delete(card_id: int):
    """
    Deletes a saved demo card.
    """
    try:
        delete_demo_card(g.current_user.id, card_id)
        flash("Simulated card removed successfully.", "info")
    except ValueError as e:
        flash(str(e), "danger")
    return redirect(url_for("cards.index"))
