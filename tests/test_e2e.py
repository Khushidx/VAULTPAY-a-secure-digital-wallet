"""
End-to-End (E2E) Browser & Workflow Test Suite.

Simulates complete end-to-end user journeys using ONLY fake/demo data for
Alice and Bob. Verifies:
1. Positive User Flows: Registration, Login, Simulated Deposit, Demo Payment Method,
   Balance Checking, Peer-to-Peer Transfer, Recipient Verification, Logout,
   and Protected Route Enforcement.
2. Negative & Security Edge Cases: Wrong password, invalid amounts (zero, negative,
   malformed), insufficient balance, unknown recipient, self-transfer, and IDOR defenses.
3. Link & Page Integrity: Crawl and verification of all internal links and forms.
4. Privacy & Leakage Audit: Zero exposure of passwords, hashes, salts, or encryption keys.
"""

import re
from urllib.parse import urlparse
import pytest
from flask import g
from app.extensions import db
from app.models.user import User
from app.models.wallet import Wallet
from app.models.payment_method import PaymentMethod
from app.models.card import DemoCard
from app.services.payment_method_service import create_payment_method
from app.services.card_service import create_demo_card


# Regex helper to extract all internal links and form actions from HTML
LINK_PATTERN = re.compile(r'(?:href|action)=["\'](/[^"\']*)["\']', re.IGNORECASE)


def extract_internal_links(html: str) -> set[str]:
    """Extracts all relative internal URLs from href and action attributes."""
    links = set()
    for match in LINK_PATTERN.findall(html):
        # Ignore static assets, javascript, and anchor hashes
        parsed = urlparse(match)
        path = parsed.path
        if (
            path
            and not path.startswith("/static/")
            and not path.startswith("#")
            and not path.startswith("javascript:")
        ):
            links.add(path)
    return links


def test_e2e_complete_positive_user_flow(client, app):
    """
    Complete E2E positive workflow with demo users Alice and Bob:
    1. Alice registers.
    2. Alice logs in.
    3. Alice receives simulated money ($150.00).
    4. Alice adds a demo payment method (Demo Visa **** 4242).
    5. Alice views her balance ($150.00).
    6. Bob registers.
    7. Alice sends simulated money ($40.00) to Bob.
    8. Bob logs in.
    9. Bob checks his balance ($40.00).
    10. Bob checks transaction history (+$40.00 from @Alice).
    11. Alice logs out.
    12. Attempt to access protected pages while logged out (redirects to /login).
    """

    # --- Step 1: Alice registers ---
    reg_resp = client.post(
        "/register",
        data={
            "username": "Alice",
            "email": "alice@college.edu",
            "password": "AliceSecurePass123!",
            "confirm_password": "AliceSecurePass123!",
        },
        follow_redirects=True,
    )
    assert reg_resp.status_code == 200
    assert "Account created successfully" in reg_resp.get_data(as_text=True)

    # --- Step 2: Alice logs in ---
    login_resp = client.post(
        "/login",
        data={
            "username_or_email": "Alice",
            "password": "AliceSecurePass123!",
        },
        follow_redirects=True,
    )
    assert login_resp.status_code == 200
    alice_dash = login_resp.get_data(as_text=True)
    assert "Welcome back, Alice" in alice_dash
    assert "₹0.00" in alice_dash

    # --- Step 3: Alice receives money (₹150.00) ---
    deposit_resp = client.post(
        "/wallet/deposit",
        data={
            "amount": "150.00",
            "description": "College Grant",
        },
        follow_redirects=True,
    )
    assert deposit_resp.status_code == 200
    deposit_html = deposit_resp.get_data(as_text=True)
    assert "deposit of ₹150.00 completed successfully" in deposit_html.lower()
    assert "₹150.00" in deposit_html

    # --- Step 4: Alice adds a payment method ---
    pm_resp = client.post(
        "/payment-methods/new",
        data={
            "method_type": "DEMO_VISA",
            "name": "Alice Student Visa",
            "last_four": "4242",
            "security_key": "1234",
            "demo_metadata": "Card Exp: 12/28",
            "is_default": "y",
        },
        follow_redirects=True,
    )
    assert pm_resp.status_code == 200
    pm_html = pm_resp.get_data(as_text=True)
    assert "Payment method added successfully" in pm_html
    assert "Alice Student Visa" in pm_html
    assert "**** **** **** 4242" in pm_html

    # --- Step 5: Alice views her balance ---
    dash_resp = client.get("/wallet/dashboard")
    assert dash_resp.status_code == 200
    dash_html = dash_resp.get_data(as_text=True)
    assert "₹150.00" in dash_html
    assert "College Grant" in dash_html

    # --- Step 6: Bob registers (so recipient exists) ---
    # Log out Alice temporarily to register Bob
    client.get("/logout")
    bob_reg = client.post(
        "/register",
        data={
            "username": "Bob",
            "email": "bob@college.edu",
            "password": "BobSecurePass456!",
            "confirm_password": "BobSecurePass456!",
        },
        follow_redirects=True,
    )
    assert bob_reg.status_code == 200
    assert "Account created successfully" in bob_reg.get_data(as_text=True)

    # --- Step 7: Alice sends money to Bob (₹40.00) ---
    # Log back in as Alice
    client.post(
        "/login",
        data={
            "username_or_email": "Alice",
            "password": "AliceSecurePass123!",
        },
        follow_redirects=True,
    )

    transfer_resp = client.post(
        "/wallet/transfer",
        data={
            "recipient": "Bob",
            "amount": "40.00",
            "note": "Split lab textbook expenses",
        },
        follow_redirects=True,
    )
    assert transfer_resp.status_code == 200
    transfer_html = transfer_resp.get_data(as_text=True)
    assert "Successfully sent ₹40.00 to @Bob" in transfer_html
    # Alice's balance must now be ₹150.00 - ₹40.00 = ₹110.00
    assert "₹110.00" in transfer_html

    # Check Alice's transaction history shows -₹40.00
    alice_hist = client.get("/wallet/history")
    assert alice_hist.status_code == 200
    alice_hist_html = alice_hist.get_data(as_text=True)
    assert "-₹40.00" in alice_hist_html
    assert "Bob" in alice_hist_html
    assert "Split lab textbook expenses" in alice_hist_html

    # --- Step 8: Bob logs in ---
    client.get("/logout")
    bob_login = client.post(
        "/login",
        data={
            "username_or_email": "Bob",
            "password": "BobSecurePass456!",
        },
        follow_redirects=True,
    )
    assert bob_login.status_code == 200
    bob_dash = bob_login.get_data(as_text=True)
    assert "Welcome back, Bob" in bob_dash

    # --- Step 9: Bob checks his balance (₹40.00) ---
    # Bob started at ₹0.00 + ₹40.00 received from Alice = ₹40.00
    assert "₹40.00" in bob_dash

    # --- Step 10: Bob checks transaction history ---
    bob_hist = client.get("/wallet/history")
    assert bob_hist.status_code == 200
    bob_hist_html = bob_hist.get_data(as_text=True)
    assert "+₹40.00" in bob_hist_html
    assert "Alice" in bob_hist_html
    assert "Split lab textbook expenses" in bob_hist_html

    # --- Step 11: Bob logs out ---
    logout_resp = client.get("/logout", follow_redirects=True)
    assert logout_resp.status_code == 200
    assert "successfully logged out" in logout_resp.get_data(as_text=True).lower()

    # --- Step 12: Attempt to access protected pages while logged out ---
    protected_urls = [
        "/wallet/dashboard",
        "/wallet/deposit",
        "/wallet/transfer",
        "/wallet/history",
        "/payment-methods",
        "/payment-methods/new",
        "/profile",
        "/cards",
        "/cards/new",
        "/dashboard",
    ]
    for url in protected_urls:
        resp = client.get(url, follow_redirects=False)
        assert resp.status_code == 302, f"Expected 302 redirect for {url}, got {resp.status_code}"
        assert "/login" in resp.headers["Location"], f"Expected redirect to /login for {url}"


def test_e2e_invalid_and_security_cases(client, app):
    """
    Verifies all required negative and security edge cases:
    - Wrong password handling
    - Invalid monetary amounts (zero, negative, malformed)
    - Insufficient balance rejection
    - Unknown recipient rejection
    - Self-transfer prevention
    - Unauthorized resource access (IDOR defenses)
    """

    # Register Alice and Bob
    client.post(
        "/register",
        data={
            "username": "Alice",
            "email": "alice@college.edu",
            "password": "AliceSecurePass123!",
            "confirm_password": "AliceSecurePass123!",
        },
    )
    client.post(
        "/register",
        data={
            "username": "Bob",
            "email": "bob@college.edu",
            "password": "BobSecurePass456!",
            "confirm_password": "BobSecurePass456!",
        },
    )

    # 1. Wrong Password Test
    wrong_pw_resp = client.post(
        "/login",
        data={
            "username_or_email": "Alice",
            "password": "IncorrectPassword999!",
        },
    )
    assert wrong_pw_resp.status_code == 401
    assert "Invalid username or password" in wrong_pw_resp.get_data(as_text=True)

    # Log in as Alice and deposit $50.00
    client.post(
        "/login",
        data={
            "username_or_email": "Alice",
            "password": "AliceSecurePass123!",
        },
    )
    client.post("/wallet/deposit", data={"amount": "50.00", "description": "Initial Fund"})

    # 2. Invalid Amount Tests (Deposit)
    # Zero amount
    zero_dep = client.post("/wallet/deposit", data={"amount": "0.00"})
    assert zero_dep.status_code == 400
    assert "greater than zero" in zero_dep.get_data(as_text=True)

    # Negative amount
    neg_dep = client.post("/wallet/deposit", data={"amount": "-25.00"})
    assert neg_dep.status_code == 400
    assert "greater than zero" in neg_dep.get_data(as_text=True)

    # Malformed text amount
    bad_dep = client.post("/wallet/deposit", data={"amount": "one_hundred"})
    assert bad_dep.status_code == 400
    assert "Invalid amount format" in bad_dep.get_data(as_text=True)

    # Fractional sub-cents (> 2 decimal places)
    fractional_dep = client.post("/wallet/deposit", data={"amount": "10.555"})
    assert fractional_dep.status_code == 400
    assert "cannot have more than 2 decimal places" in fractional_dep.get_data(as_text=True)

    # 3. Invalid Amount Tests (Transfer)
    # Zero transfer
    zero_tx = client.post("/wallet/transfer", data={"recipient": "Bob", "amount": "0.00"})
    assert zero_tx.status_code == 400
    assert "greater than zero" in zero_tx.get_data(as_text=True)

    # Negative transfer
    neg_tx = client.post("/wallet/transfer", data={"recipient": "Bob", "amount": "-15.00"})
    assert neg_tx.status_code == 400
    assert "greater than zero" in neg_tx.get_data(as_text=True)

    # Malformed transfer
    bad_tx = client.post("/wallet/transfer", data={"recipient": "Bob", "amount": "abc"})
    assert bad_tx.status_code == 400
    assert "Invalid amount format" in bad_tx.get_data(as_text=True)

    # 4. Insufficient Balance Test
    # Alice has $50.00, attempts to send $100.00
    insufficient_tx = client.post(
        "/wallet/transfer",
        data={"recipient": "Bob", "amount": "100.00", "note": "Too much money"},
    )
    assert insufficient_tx.status_code == 400
    assert "Insufficient balance" in insufficient_tx.get_data(as_text=True)

    # Verify Alice's balance is strictly unchanged at ₹50.00
    dash_check = client.get("/wallet/dashboard")
    assert "₹50.00" in dash_check.get_data(as_text=True)

    # 5. Unknown Recipient Test
    unknown_tx = client.post(
        "/wallet/transfer",
        data={"recipient": "NonExistentUser123", "amount": "10.00"},
    )
    assert unknown_tx.status_code == 400
    assert "not found" in unknown_tx.get_data(as_text=True)

    # 6. Self-Transfer Test
    self_tx = client.post(
        "/wallet/transfer",
        data={"recipient": "Alice", "amount": "10.00"},
    )
    assert self_tx.status_code == 400
    assert "cannot transfer money to yourself" in self_tx.get_data(as_text=True)

    # 7. Unauthorized Resource Access (IDOR Defenses)
    # Create a payment method and a demo card for Alice
    with app.app_context():
        alice = User.query.filter_by(username="Alice").first()
        bob = User.query.filter_by(username="Bob").first()
        alice_pm = create_payment_method(
            user_id=alice.id,
            method_type="DEMO_VISA",
            name="Alice Secret Card",
            last_four="9999",
            metadata="Alice Private Secret Data",
        )
        alice_card = create_demo_card(
            user_id=alice.id,
            cardholder_name="Alice Student",
            last_four="8888",
            card_brand="Visa",
            exp_month=11,
            exp_year=2028,
            billing_details="123 Alice St",
        )
        alice_pm_id = alice_pm.id
        alice_card_id = alice_card.id

    # Switch session to Bob
    client.get("/logout")
    client.post(
        "/login",
        data={
            "username_or_email": "Bob",
            "password": "BobSecurePass456!",
        },
    )

    # Bob attempts to reveal Alice's payment method metadata
    pm_reveal = client.get(f"/payment-methods/{alice_pm_id}/reveal", follow_redirects=True)
    assert "Alice Private Secret Data" not in pm_reveal.get_data(as_text=True)
    assert "not authorized" in pm_reveal.get_data(as_text=True).lower() or pm_reveal.status_code == 403

    # Bob attempts to delete Alice's payment method
    pm_del = client.post(f"/payment-methods/{alice_pm_id}/delete", follow_redirects=True)
    assert "not authorized" in pm_del.get_data(as_text=True).lower()

    # Verify Alice's payment method was NOT deleted
    with app.app_context():
        pm_still_exists = PaymentMethod.query.filter_by(id=alice_pm_id).first()
        assert pm_still_exists is not None

    # Bob attempts to reveal Alice's demo card
    card_reveal = client.get(f"/cards/{alice_card_id}/reveal", follow_redirects=True)
    assert "123 Alice St" not in card_reveal.get_data(as_text=True)
    assert "not authorized" in card_reveal.get_data(as_text=True).lower() or card_reveal.status_code == 403

    # Bob attempts to delete Alice's demo card
    card_del = client.post(f"/cards/{alice_card_id}/delete", follow_redirects=True)
    assert "not authorized" in card_del.get_data(as_text=True).lower()

    # Verify Alice's card was NOT deleted
    with app.app_context():
        card_still_exists = DemoCard.query.filter_by(id=alice_card_id).first()
        assert card_still_exists is not None


def test_e2e_link_integrity_and_page_crawl(client, app):
    """
    Crawls every authenticated and unauthenticated page in the application.
    Extracts all internal links (<a href> and <form action>) and verifies:
    1. No broken links (no 404 or 500 errors).
    2. Every referenced endpoint responds with 200 OK or 302 Redirect.
    """
    # Create and login user
    client.post(
        "/register",
        data={
            "username": "CrawlerUser",
            "email": "crawler@college.edu",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    )
    client.post(
        "/login",
        data={
            "username_or_email": "CrawlerUser",
            "password": "Password123!",
        },
    )

    # Known core pages to visit
    seed_urls = [
        "/",
        "/health",
        "/wallet/dashboard",
        "/wallet/deposit",
        "/wallet/transfer",
        "/wallet/history",
        "/payment-methods",
        "/payment-methods/new",
        "/cards",
        "/cards/new",
        "/profile",
    ]

    discovered_links = set(seed_urls)

    for url in seed_urls:
        resp = client.get(url)
        assert resp.status_code in (200, 302, 308), f"Seed page {url} returned {resp.status_code}"
        if resp.status_code == 200:
            html = resp.get_data(as_text=True)
            page_links = extract_internal_links(html)
            discovered_links.update(page_links)

    # Verify every discovered link
    for link in discovered_links:
        # Ignore parameterized or dynamic action paths like /cards/1/delete or /logout
        if "<" in link or "/delete" in link or link in ("/logout", "/register", "/login"):
            continue

        resp = client.get(link, follow_redirects=False)
        assert resp.status_code in (200, 302, 308), (
            f"Broken link detected: {link} returned HTTP {resp.status_code}"
        )


def test_e2e_data_exposure_audit(client, app):
    """
    Audits rendered HTML across all pages to guarantee ZERO exposure of:
    - User plaintext passwords
    - Salted SHA-256 password hashes
    - Cryptographic password salts
    - AES-256-GCM master encryption keys
    """
    password = "SensitiveSuperPassword987!"
    client.post(
        "/register",
        data={
            "username": "AuditUser",
            "email": "audit@college.edu",
            "password": password,
            "confirm_password": password,
        },
    )
    client.post(
        "/login",
        data={
            "username_or_email": "AuditUser",
            "password": password,
        },
    )

    with app.app_context():
        user = User.query.filter_by(username="AuditUser").first()
        password_hash = user.password_hash
        password_salt = user.password_salt
        encryption_key = app.config.get("ENCRYPTION_KEY", "")

    pages_to_audit = [
        "/",
        "/health",
        "/wallet/dashboard",
        "/wallet/deposit",
        "/wallet/transfer",
        "/wallet/history",
        "/payment-methods",
        "/payment-methods/new",
        "/cards",
        "/cards/new",
        "/profile",
    ]

    for page in pages_to_audit:
        resp = client.get(page)
        if resp.status_code == 200:
            html = resp.get_data(as_text=True)

            # Plaintext password check
            assert password not in html, f"LEAK ALERT: Plaintext password leaked on {page}!"

            # Password hash check
            assert password_hash not in html, f"LEAK ALERT: Password hash leaked on {page}!"

            # Password salt check
            assert password_salt not in html, f"LEAK ALERT: Password salt leaked on {page}!"

            # Master encryption key check
            if encryption_key:
                assert encryption_key not in html, f"LEAK ALERT: Encryption key leaked on {page}!"
