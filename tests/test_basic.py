"""
Basic Application Tests.

Verifies the Flask factory, configuration, home page route,
/health endpoint, error handling, and security response headers.
"""


def test_config_settings(app):
    """Verify that testing environment configuration is properly applied."""
    assert app.config["TESTING"] is True
    assert app.config["SQLALCHEMY_DATABASE_URI"] == "sqlite:///:memory:"
    assert app.config["WTF_CSRF_ENABLED"] is False


def test_home_page(client):
    """Verify that the home page loads successfully."""
    response = client.get("/")
    assert response.status_code == 200
    
    # Check that key title strings are present in the HTML and simulation text is absent
    content = response.get_data(as_text=True)
    assert "Secure Digital Wallet" in content
    assert "SIMULATION ONLY" not in content
    assert "Educational Simulation" not in content


def test_health_endpoint(client):
    """Verify that the /health endpoint returns a valid JSON health status."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.is_json is True
    
    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert data["mode"] == "active"
    assert "timestamp" in data


def test_404_error_handling(client):
    """Verify that a non-existent URL returns a clean 404 page."""
    response = client.get("/non-existent-route-for-testing")
    assert response.status_code == 404
    content = response.get_data(as_text=True)
    assert "Resource Not Found" in content


def test_security_headers_applied(client):
    """Verify that defensive HTTP response headers are present."""
    response = client.get("/")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_all_frontend_pages_render_successfully(client, app):
    """
    Verify that all 9 required pages render with HTTP 200 (or proper redirect).
    1. Login
    2. Register
    3. Dashboard
    4. Add simulated money (Deposit)
    5. Send money (Transfer)
    6. Payment methods
    7. Transaction history
    8. Security/profile
    9. Logout
    """
    from app.extensions import db
    from app.models.user import User
    from app.services.wallet_service import get_or_create_user_wallet

    with app.app_context():
        # Setup user
        user = User(username="frontend_user", email="frontend@test.edu")
        user.set_password("MySecurePass123!")
        db.session.add(user)
        db.session.commit()
        get_or_create_user_wallet(user.id)
        user_id = user.id
        user_username = user.username
        user_email = user.email

    # 1. Login page
    res_login = client.get("/login")
    assert res_login.status_code == 200
    assert "Log In" in res_login.get_data(as_text=True)

    # 2. Register page
    res_reg = client.get("/register")
    assert res_reg.status_code == 200
    assert "Create Account" in res_reg.get_data(as_text=True)

    # Authenticate user session
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["username"] = user_username

    # 3. Dashboard page
    res_dash = client.get("/wallet/dashboard")
    assert res_dash.status_code == 200
    dash_html = res_dash.get_data(as_text=True)
    # Check all required Dashboard elements:
    assert user_username in dash_html               # User name
    assert "Available Balance" in dash_html         # Balance
    assert "Recent Transactions" in dash_html       # Recent transactions
    assert "Send Money" in dash_html                # Send money button
    assert "Add Money" in dash_html                 # Add money button
    assert "Payment Methods" in dash_html           # Payment methods link
    assert "Log Out" in dash_html                   # Logout button

    # Top-level /dashboard redirect
    res_dash_redirect = client.get("/dashboard")
    assert res_dash_redirect.status_code == 302

    # 4. Add money (Deposit)
    res_dep = client.get("/wallet/deposit")
    assert res_dep.status_code == 200
    assert "Deposit Funds" in res_dep.get_data(as_text=True)

    # 5. Send money (Transfer)
    res_transfer = client.get("/wallet/transfer")
    assert res_transfer.status_code == 200
    assert "Send Money" in res_transfer.get_data(as_text=True)

    # 6. Payment methods
    res_pm = client.get("/payment-methods")
    assert res_pm.status_code == 200
    assert "Payment Methods" in res_pm.get_data(as_text=True)

    res_pm_new = client.get("/payment-methods/new")
    assert res_pm_new.status_code == 200
    assert "Add Payment Method" in res_pm_new.get_data(as_text=True)

    # 7. Transaction history
    res_hist = client.get("/wallet/history")
    assert res_hist.status_code == 200
    assert "Transaction History" in res_hist.get_data(as_text=True)

    # 8. Security/profile
    res_prof = client.get("/profile", follow_redirects=True)
    assert res_prof.status_code == 200
    prof_html = res_prof.get_data(as_text=True)
    assert "Security & Account Profile" in prof_html
    assert user_username in prof_html
    assert user_email in prof_html

    # 9. Logout
    res_logout = client.get("/logout", follow_redirects=True)
    assert res_logout.status_code == 200
    assert "successfully logged out" in res_logout.get_data(as_text=True).lower()


def test_zero_leakage_of_passwords_hashes_salts_and_keys(client, app):
    """
    Verify that none of the rendered pages ever display or leak:
    - Passwords
    - Password hashes
    - Password salts
    - Encryption keys
    """
    from app.extensions import db
    from app.models.user import User
    from app.services.wallet_service import get_or_create_user_wallet

    with app.app_context():
        user = User(username="leak_check_user", email="leakcheck@test.edu")
        user.set_password("SuperSecretPassword999!")
        db.session.add(user)
        db.session.commit()
        get_or_create_user_wallet(user.id)

        # Retain references to sensitive values
        secret_password = "SuperSecretPassword999!"
        secret_hash = user.password_hash
        secret_salt = user.password_salt
        encryption_key = app.config.get("ENCRYPTION_KEY")

    with client.session_transaction() as sess:
        sess["user_id"] = user.id
        sess["username"] = user.username

    pages_to_check = [
        "/",
        "/login",
        "/register",
        "/wallet/dashboard",
        "/wallet/deposit",
        "/wallet/transfer",
        "/payment-methods",
        "/wallet/history",
        "/profile",
        "/crypto-architecture",
    ]

    for page in pages_to_check:
        res = client.get(page)
        html = res.get_data(as_text=True)
        assert secret_password not in html, f"Plaintext password leaked in {page}!"
        assert secret_hash not in html, f"Password hash leaked in {page}!"
        assert secret_salt not in html, f"Password salt leaked in {page}!"
        if encryption_key:
            assert encryption_key not in html, f"Encryption key leaked in {page}!"


def test_crypto_architecture_access_control(client, app):
    """
    Verify that the Crypto Architecture tab is protected:
    - Unauthenticated access redirects to /login.
    - Authenticated access renders HTTP 200 with full architecture details.
    """
    from app.extensions import db
    from app.models.user import User

    # 1. Unauthenticated request must redirect to /login
    res_unauth = client.get("/crypto-architecture")
    assert res_unauth.status_code == 302
    assert "/login" in res_unauth.headers.get("Location", "")

    res_alias_unauth = client.get("/architecture")
    assert res_alias_unauth.status_code == 302
    assert "/login" in res_alias_unauth.headers.get("Location", "")

    # 2. Authenticated request
    with app.app_context():
        user = User(username="arch_tester", email="arch@test.edu")
        user.set_password("SecurePassword999!")
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["username"] = "arch_tester"

    res_auth = client.get("/crypto-architecture")
    assert res_auth.status_code == 200
    html = res_auth.get_data(as_text=True)

    # Verify key architectural content is present
    assert "CRYPTOGRAPHIC ARCHITECTURE" in html
    assert "AUTHENTICATED ACCESS ONLY" in html
    assert "Salted SHA-256" in html
    assert "AES-256-GCM" in html
    assert "User Identity & Password Storage" in html
    assert "Sensitive Vault (AEAD)" in html
    assert "Ledger & Arithmetic" in html

