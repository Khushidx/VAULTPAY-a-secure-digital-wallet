# VaultPay — Secure Digital Wallet & Ledger

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.0+-green?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/Database-SQLite%20%2F%20SQLAlchemy-lightblue?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Cryptography](https://img.shields.io/badge/Encryption-AES--256--GCM%20AEAD-blueviolet?logo=lock&logoColor=white)](https://cryptography.io/)
[![Tests](https://img.shields.io/badge/Tests-55%2F55%20Passing%20(100%25)-brightgreen?logo=pytest&logoColor=white)](tests/)
[![Currency](https://img.shields.io/badge/Currency-INR%20(%E2%82%B9)%20Integer%20Paise-orange)](app/utils/money.py)
[![Design](https://img.shields.io/badge/Design-Restrained%20Editorial-2563EB)](app/static/css/styles.css)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

**VaultPay** is an enterprise-grade digital wallet and double-entry transaction ledger engineered with defense-in-depth security principles. It features authenticated AES-256-GCM encryption for stored payment metadata, salted SHA-256 password hashing, step-up two-factor authentication with user-defined 4-digit security PINs, atomic financial transactions, and zero floating-point arithmetic in Indian Rupees (₹).

---

## Visual Design & User Interface

VaultPay uses a **restrained professional editorial design system** inspired by modern institutional fintech platforms (such as Stripe, Wise, and Mercury):

- **Palette**:
  - **Background**: `#F8F7F4` (warm off-white canvas)
  - **Primary**: `#17202A` (deep charcoal for high-contrast headings and prominent text)
  - **Secondary**: `#4B5563` (muted gray for descriptions, subheadings, and secondary labels)
  - **Accent**: `#2563EB` (professional blue for primary actions and focus states)
  - **Accent Hover**: `#1D4ED8`
  - **Cards / Surfaces**: `#FFFFFF` (crisp white elevated cards)
  - **Elevated Surfaces**: `#F9FAFB` (light neutral for table headers, code blocks, and chips)
  - **Borders**: `#E5E7EB` (`#D1D5DB` strong)
- **Typography**:
  - **Headings**: **Inter** (semibold/bold, tight `-0.02em` tracking)
  - **Body**: **Inter** (regular, line-height `1.5` to `1.6`)
  - **Monospace**: **JetBrains Mono** for monetary amounts (`₹`), token IDs, and masked PANs
- **Restrained Aesthetics**:
  - **No Gradients**: Clean, solid surfaces with crisp structural borders.
  - **No Excessive Rounded Corners**: Restrained radii (`4px` sm, `6px` md, `8px` lg).
  - **No Neon Colors or Glowing Shadows**: Subtle, standard shadows (`0 1px 2px rgba(0,0,0,0.04)`) and muted, semantic status fills.
  - **No Emojis**: Replaced entirely with standardized, pixel-aligned inline SVG vector icons.

---

## Security Architecture & Engineering Highlights

### 1. Cryptographic Security & Privacy
- **Salted SHA-256 Password Hashing**: Passwords are never stored in plaintext. Each account receives a unique 256-bit cryptographically secure random salt (`secrets.token_hex(32)`), verified via constant-time comparison (`hmac.compare_digest`) to prevent timing attacks.
- **AES-256-GCM Authenticated Encryption at Rest**: Sensitive payment metadata is encrypted using AES-256-GCM AEAD with a unique 12-byte cryptographically secure random nonce and a 16-byte authentication tag per record.
- **Cryptographic PIN Binding (Authenticated Associated Data - AAD)**: When adding a payment method, users define a 4-digit numeric security key (PIN). The PIN is stored as a salted SHA-256 hash and bound directly to the AES-256-GCM ciphertext as AAD. The ciphertext cannot be decrypted without the exact 4-digit PIN.
- **Step-Up Authentication**: Decrypting or inspecting payment method metadata requires step-up two-factor verification: re-entering the account password and the 4-digit security PIN.
- **Zero CVV & Full Credential Policy**: CVVs, CVCs, and full card numbers (PANs) are strictly rejected and never stored. Only masked identifiers (`**** **** **** 4242`) and opaque tokens (`tok_...`) are retained.
- **Zero Presentation Leakage**: Passwords, password hashes, cryptographic salts, and master encryption keys are audited and verified to never appear in any HTML response.

### 2. Financial Integrity & Invariants
- **Zero Floating-Point Arithmetic**: All monetary amounts are converted and stored on the server as integer smallest currency units (**paise**). Eliminates IEEE-754 floating-point rounding errors ($0.1 + 0.2 \neq 0.3$).
- **Database Non-Negative Invariant**: An SQLite database-level `CHECK (balance_cents >= 0)` constraint guarantees that balances can never become negative, even under race conditions.
- **Atomic Double-Entry Transactions**: Transfers execute atomically within database transactions. Sender debit and recipient credit either commit together or roll back completely on failure.
- **Audit Ledger**: Every balance adjustment produces an immutable transaction record with a unique UUID reference ID, timestamp, and status.

### 3. Application Defense-in-Depth
- **Brute-Force Rate Limiting**: Login endpoints lock the IP/account for 5 minutes after 5 consecutive failed attempts.
- **CSRF Protection**: All forms utilize cryptographically signed CSRF tokens via Flask-WTF.
- **Session Security**: Session cookies configured with `HttpOnly` (mitigates XSS token theft), `SameSite=Lax` (mitigates CSRF), and session ID regeneration upon login (prevents session fixation).
- **IDOR Protection**: All wallet, card, and payment method operations are strictly bounded to the authenticated session (`session['user_id']`). Access to another user's resources is blocked.
- **Defensive HTTP Headers**: Responses include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: strict-origin-when-cross-origin`.

---

## Project Structure

```text
secure_wallet/
├── app/
│   ├── __init__.py              # Application factory & automatic schema migration
│   ├── config.py                # Configuration classes (Dev, Testing, Prod)
│   ├── crypto.py                # Top-level crypto exports
│   ├── errors.py                # Custom error handlers (400, 404, 500, CSRF)
│   ├── extensions.py            # Flask extensions (SQLAlchemy, CSRFProtect)
│   ├── forms/                   # WTForms form definitions with validation
│   │   ├── auth.py              # Login & Registration forms
│   │   ├── card.py              # Card vault form
│   │   ├── payment_method.py    # Payment Method & Step-Up Reveal forms
│   │   └── wallet.py            # Deposit & Transfer forms
│   ├── models/                  # SQLAlchemy database models
│   │   ├── card.py              # DemoCard model with AES-256-GCM
│   │   ├── payment_method.py    # PaymentMethod model with AAD PIN binding
│   │   ├── transaction.py       # Transaction ledger model
│   │   ├── user.py              # User model with salted SHA-256
│   │   └── wallet.py            # Wallet model with integer paise & CHECK constraint
│   ├── routes/                  # Blueprint route controllers
│   │   ├── auth.py              # Register, Login, Logout, Profile
│   │   ├── cards.py             # Cards Vault management
│   │   ├── main.py              # Landing page & /health endpoint
│   │   ├── payment_methods.py   # Payment methods & Step-Up Reveal challenge
│   │   ├── security_lab.py      # Interactive VaultPay Security Lab controller
│   │   └── wallet.py            # Dashboard, Deposit, Transfer, History
│   ├── services/                # Business logic layer
│   │   ├── payment_method_service.py # Tokenization & payment method operations
│   │   ├── security_demo_service.py  # Isolated Security Lab attack & crypto simulator
│   │   └── wallet_service.py    # Atomic deposit, transfer, & ledger operations
│   ├── static/
│   │   └── css/
│   │       └── styles.css       # Restrained professional editorial design system
│   ├── templates/               # Jinja2 templates (VaultPay theme)
│   │   ├── auth/                # login.html, register.html, profile.html
│   │   ├── base.html            # Global base template with clean navbar & footer
│   │   ├── cards/               # index.html, new.html, reveal.html
│   │   ├── errors/              # 400.html, 404.html, 500.html, csrf_error.html
│   │   ├── main/                # index.html (landing page)
│   │   ├── payment_methods/     # index.html, new.html, reveal.html, verify_reveal.html
│   │   ├── security_lab/        # index.html (interactive attack & crypto lab)
│   │   └── wallet/              # dashboard.html, deposit.html, transfer.html, history.html
│   ├── crypto_aes_gcm.py        # Top-level AES-256-GCM cryptographic facade
│   └── utils/                   # Algorithmic & helper modules
│       ├── crypto_aes_gcm.py    # AES-256-GCM AEAD encryption & decryption engine
│       ├── password_sha256.py   # Salted SHA-256 hashing & constant-time verification
│       ├── rate_limiter_sliding_window.py # In-memory sliding-window brute-force limiter
│       ├── money_integer_cents.py # Integer-cent precision currency arithmetic
│       ├── decorators.py        # @login_required route decorator
│       └── validators.py        # Input sanitation & registration validation
├── instance/                    # SQLite database storage
├── scripts/                     # Operational & verification scripts
│   ├── migrate_db.py            # Standalone SQLite schema migration
│   ├── verify_e2e_live.py       # 20-step automated live verification
│   └── verify_live.py           # Live wallet test script
├── tests/                       # Automated test suite (72 tests)
│   ├── conftest.py              # Isolated in-memory SQLite fixtures
│   ├── test_auth.py             # Authentication & salt tests
│   ├── test_basic.py            # Routes, health, & security headers
│   ├── test_crypto.py           # AES-256-GCM & tamper rejection tests
│   ├── test_e2e.py              # End-to-end user journeys & crawl audit
│   ├── test_payment_methods.py  # Step-up challenge, PIN, & IDOR tests
│   ├── test_security_lab.py     # Security Lab real crypto & attack simulation tests
│   └── test_wallet.py           # Atomic ledger, transfer, & money tests
├── .env.example                 # Environment variables template
├── .gitignore                   # Git ignore patterns
├── pytest.ini                   # Pytest configuration
├── requirements.txt             # Python package dependencies
└── run.py                       # Development server entry point
```

---

## Getting Started

### Prerequisites
- **Python 3.10, 3.11, or 3.12** installed on your system.
- On Windows, ensure **"Add Python to PATH"** was checked during installation.

### 1. Clone or Copy the Repository
```bash
git clone https://github.com/your-username/VaultPay.git
cd VaultPay
```

### 2. Create and Activate a Virtual Environment
- **Windows (Command Prompt / PowerShell):**
  ```powershell
  python -m venv .venv
  .\.venv\Scripts\activate
  ```
  *(If PowerShell displays an execution policy error, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

- **macOS / Linux:**
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy `.env.example` to create your local `.env` file:

- **Windows:**
  ```powershell
  copy .env.example .env
  ```
- **macOS / Linux:**
  ```bash
  cp .env.example .env
  ```

The default `.env` includes a development 256-bit AES encryption key. To generate a unique 256-bit key for production, run:
```bash
python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"
```

### 5. Start the Application
```bash
python run.py
```

The server will start on port `5000`:
```text
[*] Starting VaultPay (development mode)...
[*] Server running at: http://127.0.0.1:5000
```

Open your browser and navigate to **`http://127.0.0.1:5000`**.

---

## Testing & Verification

VaultPay includes a comprehensive automated test suite with **55 tests** covering authentication, cryptographic integrity, integer currency calculations, double-entry ledger invariants, IDOR defenses, and full user workflows.

### Run All Tests with Pytest
```bash
pytest -v
```

**Test Suite Coverage:**
```text
tests/test_auth.py ...........                                           [ 20%]
tests/test_basic.py .......                                              [ 32%]
tests/test_crypto.py .........                                           [ 49%]
tests/test_e2e.py ....                                                   [ 56%]
tests/test_payment_methods.py ........                                   [ 70%]
tests/test_wallet.py ................                                    [100%]

============================= 55 passed in 1.46s ==============================
```

### Run Live End-to-End Verification
Execute the 20-step verification script simulating complete user journeys for Alice and Bob:
```bash
python scripts/verify_e2e_live.py
```

**All 20 Checks Covered:**
- Step 1: User Registration with Salted SHA-256 and automatic wallet provisioning
- Step 2: Login authentication & session fixation defense
- Step 3: Atomic deposit in Indian Rupees (`₹150.00` / 15,000 paise)
- Step 4: Payment method creation with 4-digit PIN, AES-256-GCM encryption, and step-up challenge verification
- Step 5: Balance verification on dashboard
- Step 6: Second user registration (Bob)
- Step 7: Atomic peer-to-peer transfer from Alice to Bob (`₹40.00`)
- Step 8-10: Bob login, balance verification (`₹40.00`), and transaction history audit
- Step 11: Alice logout and session invalidation
- Step 12: Unauthorized access attempts redirected to login
- Step 13: Wrong password rejection
- Step 14: Invalid deposit amounts rejected (zero, negative, non-numeric, fractional cents)
- Step 15: Invalid transfer amounts rejected
- Step 16: Insufficient balance transfer rejected
- Step 17: Unknown recipient transfer rejected
- Step 18: Self-transfer rejected
- Step 19: IDOR unauthorized access rejection
- Step 20: Data privacy audit (zero plaintext passwords, hashes, salts, or AES keys in responses)

---

## Application Endpoints

| Method | Endpoint | Description | Auth Required |
|:---|:---|:---|:---:|
| `GET` | `/` | Landing page | No |
| `GET` | `/health` | JSON health & database status | No |
| `GET`, `POST` | `/register` | Create a new user account | No |
| `GET`, `POST` | `/login` | Authenticate user session | No |
| `GET` | `/logout` | Invalidate active session | Yes |
| `GET` | `/profile` | Account details & active security controls | Yes |
| `GET` | `/wallet/dashboard` | Main wallet dashboard & balance | Yes |
| `GET`, `POST` | `/wallet/deposit` | Deposit funds (integer paise) | Yes |
| `GET`, `POST` | `/wallet/transfer` | P2P transfer to another user | Yes |
| `GET` | `/wallet/history` | Double-entry transaction audit history | Yes |
| `GET` | `/payment-methods/` | List saved payment methods | Yes |
| `GET`, `POST` | `/payment-methods/new` | Add payment method with 4-digit PIN | Yes |
| `GET`, `POST` | `/payment-methods/<id>/reveal` | Step-up auth challenge & metadata reveal | Yes |
| `POST` | `/payment-methods/<id>/delete` | Remove a saved payment method | Yes |

---

## Authors & Contributors

This project was engineered as a collaborative Cryptography capstone project by: 

* **Anushka Roy** 
* **Khushi Gojanur** 

## License

This project is licensed under the MIT License.

