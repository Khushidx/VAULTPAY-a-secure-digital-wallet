# Secure Digital Wallet — Architecture & Implementation Plan
*Educational Simulation Project*

---

## 1. Project Overview & Safety Boundaries

This project is an **educational simulation** of a secure digital wallet system built for a college-level computer science demonstration. It demonstrates core principles of financial software engineering: defensive programming, cryptographic data protection, atomic transaction handling, and secure web application design.

### Crucial Safety Limitations (Non-Negotiable)
- **No Real Money**: All balances, transfers, and transactions are strictly simulated demo tokens.
- **No Real Banking Connectivity**: No ACH, SWIFT, SEPA, UPI, or real-world clearing houses.
- **No Real Cardholder Data**: No real Visa, Mastercard, or Amex card numbers; only simulated mock cards (e.g., standard test ranges like `4000 0000 0000 1234`).
- **Zero CVV Storage**: In accordance with PCI-DSS guidance, CVVs/CVCs are never stored, even in simulation.
- **No Real Payment Gateways**: No Stripe, PayPal, or Razorpay API keys or real payment webhooks.

---

## 2. Technology Stack & Rationale

| Component | Choice | Educational Rationale |
| :--- | :--- | :--- |
| **Language** | Python 3 | Clean syntax, readable security code, rich standard library and ecosystem. |
| **Web Framework** | Flask | Lightweight, unopinionated microframework allowing students to see exactly how requests, sessions, and middlewares work without hidden framework magic. |
| **Database** | SQLite + SQLAlchemy | File-based, zero-configuration, ACID-compliant relational DB. SQLAlchemy provides an Object-Relational Mapper (ORM) with built-in query parameterization to prevent SQL injection. |
| **Password Hashing** | Salted SHA-256 via PBKDF2 (`hashlib.pbkdf2_hmac`) | NIST/OWASP recommended password hashing mechanism using SHA-256. Uses a cryptographically random salt and 600,000 iterations to resist GPU brute-force attacks, using Python's standard library without external C dependencies. |
| **Data Encryption** | AES-256-GCM (`cryptography`) | Authenticated Encryption with Associated Data (AEAD). Provides both confidentiality (AES) and cryptographic integrity/authenticity (Galois Counter Mode tag), preventing ciphertext tampering. |
| **Frontend** | HTML5, CSS3, Vanilla JS | Clean semantic templates using Jinja2; avoids external framework bloat while providing an interactive, accessible, and responsive user experience. |
| **Automated Testing**| pytest | Industry-standard testing framework to verify balance invariants, concurrency safety, crypto correctness, and authorization boundaries. |

---

## 3. System Architecture

The application adopts a **Layered Architecture** utilizing the Flask Application Factory pattern to decouple concerns into clear, auditable layers:

```
┌────────────────────────────────────────────────────────┐
│                   Presentation Layer                   │
│        Jinja2 Templates (HTML/CSS/Vanilla JS)          │
└───────────────────────────┬────────────────────────────┘
                            │ HTTP Requests / CSRF Tokens
┌───────────────────────────▼────────────────────────────┐
│                    Controller Layer                    │
│      Flask Blueprints: auth, wallet, cards, admin      │
└───────────────────────────┬────────────────────────────┘
                            │ Clean Service Calls
┌───────────────────────────▼────────────────────────────┐
│                     Service Layer                      │
│  - AuthService      (Salted SHA-256 hashing, session auth)│
│  - WalletService    (Atomic transfers, balance checks) │
│  - CryptoService    (AES-256-GCM encrypt/decrypt)     │
│  - AuditService     (Immutable security event logging) │
└───────────────────────────┬────────────────────────────┘
                            │ ORM Entities / Transactions
┌───────────────────────────▼────────────────────────────┐
│                    Persistence Layer                   │
│        SQLAlchemy Models & SQLite Database File        │
└────────────────────────────────────────────────────────┘
```

---

## 4. SQLite Database Schema Design

All monetary amounts are stored as **64-bit Integers representing Cents** (or smallest currency unit). 
*Why?* Standard IEEE-754 floating-point arithmetic introduces rounding errors (e.g., `0.1 + 0.2 = 0.30000000000000004`), which can cause money to appear or disappear over time. Storing cents as integers guarantees exact math.

```
┌──────────────────────────┐             ┌──────────────────────────┐
│          users           │ 1         1 │         wallets          │
├──────────────────────────┤◄───────────►├──────────────────────────┤
│ id (INTEGER PK)          │             │ id (INTEGER PK)          │
│ username (TEXT UNIQUE)   │             │ user_id (INT FK UNIQUE)  │
│ email (TEXT UNIQUE)      │             │ balance_cents (INTEGER)  │
│ password_hash (TEXT)     │             │ currency (TEXT 'USD')    │
│ role (TEXT 'user'/'admin')             │ updated_at (TIMESTAMP)   │
│ is_active (BOOLEAN)      │             └─────────────┬────────────┘
│ created_at (TIMESTAMP)   │                           │ 1
└────────────┬─────────────┘                           │
             │ 1                                       │
             │                                         │ 0..*
             ▼ 0..*                                    ▼
┌──────────────────────────┐             ┌──────────────────────────┐
│        demo_cards        │             │       transactions       │
├──────────────────────────┤             ├──────────────────────────┤
│ id (INTEGER PK)          │             │ id (INTEGER PK)          │
│ user_id (INT FK)         │             │ reference_id (UUID TEXT) │
│ cardholder_name (TEXT)   │             │ sender_wallet_id (FK)    │
│ masked_pan (TEXT)        │             │ receiver_wallet_id (FK)  │
│ encrypted_payload (TEXT) │             │ amount_cents (INTEGER)   │
│ card_brand (TEXT)        │             │ transaction_type (TEXT)  │
│ exp_month (INTEGER)      │             │ status (TEXT)            │
│ exp_year (INTEGER)       │             │ description (TEXT)       │
│ created_at (TIMESTAMP)   │             │ created_at (TIMESTAMP)   │
└──────────────────────────┘             └──────────────────────────┘
             │ 1
             │ 0..*
┌────────────▼─────────────┐
│        audit_logs        │
├──────────────────────────┤
│ id (INTEGER PK)          │
│ user_id (INT FK, NULL)   │
│ action (TEXT)            │
│ ip_address (TEXT)        │
│ details_json (TEXT)      │
│ created_at (TIMESTAMP)   │
└──────────────────────────┘
```

### Table Definitions
1. **`users`**: Stores user authentication credentials.
   - `password_hash`: Salted SHA-256 hash using PBKDF2 (format: `pbkdf2_sha256$iterations$salt$hash`).
2. **`wallets`**: One-to-one relationship with `users`.
   - `balance_cents`: Current balance in cents. Constrained to `balance_cents >= 0` via a SQLite `CHECK` constraint to prevent overdraft at the database engine level.
3. **`transactions`**: Double-entry/ledger records.
   - `reference_id`: Unique UUID generated per transaction for idempotency.
   - `sender_wallet_id`: NULL for external deposits.
   - `receiver_wallet_id`: NULL for external withdrawals.
   - `transaction_type`: `DEPOSIT`, `TRANSFER`, `WITHDRAWAL`.
   - `status`: `COMPLETED`, `FAILED`, `PENDING`.
4. **`demo_cards`**: Educational demonstration of AES-256-GCM symmetric encryption.
   - `masked_pan`: e.g. `**** **** **** 1234` for safe UI display.
   - `encrypted_payload`: Base64 encoded payload holding `Nonce (12 bytes) + Ciphertext + Tag (16 bytes)` representing fake billing details.
5. **`audit_logs`**: Tamper-evident record of security-sensitive events (logins, failed logins, transfers, card creations).

---

## 5. Folder Structure

```
secure_wallet/
├── app/
│   ├── __init__.py          # Application Factory (create_app)
│   ├── config.py            # Configuration settings (Dev, Test, Prod)
│   ├── extensions.py        # SQLAlchemy, CSRFProtect, Limiter instances
│   │
│   ├── models/              # SQLAlchemy Data Models
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── wallet.py
│   │   ├── transaction.py
│   │   ├── card.py
│   │   └── audit_log.py
│   │
│   ├── services/            # Pure Business & Security Logic
│   │   ├── __init__.py
│   │   ├── auth_service.py   # Password hashing & session checks
│   │   ├── wallet_service.py # Atomic transfers, deposits, invariants
│   │   ├── crypto_service.py # AES-256-GCM encryption & decryption
│   │   └── audit_service.py  # Security logging
│   │
│   ├── routes/              # Flask Blueprints (HTTP Handlers)
│   │   ├── __init__.py
│   │   ├── auth.py          # Login, Register, Logout
│   │   ├── wallet.py        # Balance, Transfer, Deposit, History
│   │   ├── cards.py         # Demo card management (AES demo)
│   │   └── main.py          # Home, landing page
│   │
│   ├── static/              # Static Frontend Assets
│   │   ├── css/
│   │   │   └── styles.css   # Modern, clean styling with dark/light themes
│   │   └── js/
│   │       └── wallet.js    # Client-side validation & dynamic UI updates
│   │
│   └── templates/           # Jinja2 HTML Templates
│       ├── base.html        # Main layout (navigation, flash messages, footer)
│       ├── auth/
│       │   ├── login.html
│       │   └── register.html
│       ├── wallet/
│       │   ├── dashboard.html
│       │   ├── transfer.html
│       │   ├── deposit.html
│       │   └── history.html
│       └── cards/
│           ├── index.html
│           └── new.html
│
├── tests/                   # Pytest Automated Test Suite
│   ├── __init__.py
│   ├── conftest.py          # Test fixtures (test client, in-memory DB)
│   ├── test_auth.py         # Login, registration, hash validation
│   ├── test_crypto.py       # AES-256-GCM encrypt/decrypt/tamper tests
│   ├── test_wallet.py       # Balance checks, transfers, atomic rollback
│   └── test_security.py     # IDOR, CSRF, negative balance prevention
│
├── instance/                # Local SQLite database file (gitignored)
├── .env.example             # Environment variable template
├── .gitignore               # Git ignore rules
├── requirements.txt         # Project dependencies
├── run.py                   # Development server runner
└── PROJECT_PLAN.md          # Architecture & plan documentation
```

---

## 6. Authentication Architecture

### 1. Password Hashing with SHA-256 (PBKDF2-HMAC-SHA256)
- **Why Salted PBKDF2-SHA256 instead of raw SHA-256?**
  - *Raw SHA-256 Vulnerability*: Plain SHA-256 (e.g. `hashlib.sha256(password).hexdigest()`) is designed for fast file integrity checks, not passwords. A standard modern GPU can test over 10 billion raw SHA-256 hashes per second, making dictionary and precomputed rainbow table attacks trivial.
  - *Salted SHA-256 Solution*: We use **PBKDF2** (Password-Based Key Derivation Function 2) with **SHA-256** as the cryptographic pseudorandom function:
    1. **Random Salt**: A cryptographically secure 16-byte random salt (`secrets.token_bytes(16)`) is generated per user. This guarantees that two identical passwords produce completely different hashes, destroying rainbow table attacks.
    2. **Key Stretching (Iterations)**: 600,000 iterations of HMAC-SHA256 are computed per password hash (in line with OWASP recommendations). This deliberately slows down attackers by orders of magnitude while remaining instantaneous for legitimate single-user logins.
    3. **Constant-Time Comparison**: Hash verification uses `secrets.compare_digest` / `hmac.compare_digest` to eliminate side-channel timing attacks.
- **Implementation**:
  Uses Python's standard library `hashlib.pbkdf2_hmac('sha256', ...)` and `secrets`.
  - Format stored in DB: `pbkdf2_sha256$600000$<hex_salt>$<hex_hash>`.
  - Zero external C dependencies needed!

### 2. Session Management & Cookies
- Sessions are stored in signed, HTTP-only, secure cookies.
- Flags configured:
  - `SESSION_COOKIE_HTTPONLY = True` (Prevents client-side scripts from reading session cookies via JavaScript/XSS).
  - `SESSION_COOKIE_SAMESITE = 'Lax'` (Protects against CSRF attacks).
  - Session regeneration upon login to prevent **Session Fixation**.
- Decorator `@login_required` verifies active user session and validates user active status on every protected route.

---

## 7. Encryption Architecture (AES-256-GCM)

For sensitive demonstration data (such as simulated card credentials or fake identity data):

### 1. Authenticated Encryption (AEAD)
Standard AES in CBC or ECB mode only encrypts data; it does not protect against deliberate bit-flipping (tampering). 
**AES-GCM (Galois/Counter Mode)** provides:
- **Confidentiality**: 256-bit symmetric encryption.
- **Authenticity/Integrity**: Generates a 128-bit authentication tag (`mac`). If an attacker alters even a single bit of the stored ciphertext, decryption fails with an `InvalidTag` exception.

### 2. Cryptographic Workflow
1. **Key Management**:
   - Master key is loaded from an environment variable (`ENCRYPTION_KEY_BASE64`).
   - Must be exactly 32 bytes (256 bits), stored safely outside version control.
2. **Encryption Process**:
   - Generate a fresh, cryptographically secure 12-byte (96-bit) random **Nonce** (`os.urandom(12)`).
   - Never reuse a Nonce with the same key.
   - Encrypt the plaintext using AES-256-GCM.
   - Package output as: `Base64(Nonce + Ciphertext + Tag)`.
3. **Decryption Process**:
   - Unpack Base64 string into Nonce (first 12 bytes), Ciphertext, and Tag (last 16 bytes).
   - Decrypt and verify tag.
   - If tag fails, raise a custom `DecryptionIntegrityError` and record an audit log.

---

## 8. Wallet Transaction Architecture

### 1. Atomicity & Invariants
Money transfer is a classic two-phase operation:
1. Deduct \$X from Alice's wallet.
2. Add \$X to Bob's wallet.
3. Record transaction log.

If step 1 succeeds but step 2 fails (e.g., system crash or exception), money is permanently lost.
**Solution**:
- All operations execute inside an explicit **SQLAlchemy Transaction block** (`with db.session.begin_nested():` or session transaction).
- Either *all three steps succeed*, or the entire operation rolls back.

### 2. Guarding Invariants & Preventing Overdraft
- Database constraint: `CHECK (balance_cents >= 0)` ensures the database engine itself rejects negative balances even if application logic were somehow bypassed.
- Application check: `sender.balance_cents >= amount_cents` checked before deduction.
- Target check: Sender cannot transfer to their own wallet (`sender_id != receiver_id`).
- Strict positive amounts: Transfers and deposits must be `> 0`.

### 3. Concurrency & Double-Spending Protection
In SQLite, write locks serialize database changes. The service layer wraps transaction logic in a single atomic transaction. In testing, concurrent transfers will be tested to confirm that race conditions cannot lead to double spending.

---

## 9. Security Risks & Mitigations (OWASP Top 10 Context)

| Threat | Description | Specific Project Mitigation |
| :--- | :--- | :--- |
| **Insecure Direct Object Reference (IDOR)** | User modifies wallet ID in request to spend another user's balance. | All wallet operations retrieve the wallet strictly by the authenticated `session['user_id']`, never trusting user-supplied wallet IDs. |
| **Race Conditions (Double Spend)** | Rapidly submitting two transfer requests to spend more than available. | Database transactions with strict balance verification and `CHECK` constraints on `balance_cents >= 0`. |
| **SQL Injection** | Attacker injects raw SQL queries into form inputs. | 100% parameterized queries via SQLAlchemy ORM; zero raw string SQL queries. |
| **Cross-Site Request Forgery (CSRF)** | Malicious site tricks user's browser into submitting a transfer request. | Flask-WTF CSRF protection validating cryptographic tokens on every state-changing POST request. |
| **Cross-Site Scripting (XSS)** | Malicious script injected via description field or cardholder name. | Automatic HTML escaping by Jinja2 template engine; Content Security Policy (CSP) headers. |
| **Floating-Point Rounding Error** | Inaccurate money representation over time. | Integer-only arithmetic (amounts measured in cents). |
| **Secret Key Exposure** | Hardcoded keys checked into Git repository. | `.env` file management with `.gitignore` and validation on startup. |

---

## 10. Staged Implementation Plan

The project will be built in **7 structured phases**, each accompanied by verification tests before moving to the next:

### Phase 1: Environment & Cryptographic Foundation
- Initialize project structure and `requirements.txt` (`Flask`, `Flask-SQLAlchemy`, `cryptography`, `pytest`, `python-dotenv`, `Flask-WTF`).
- Implement `CryptoService`:
  - Salted SHA-256 password hashing and verification using PBKDF2 (`hashlib.pbkdf2_hmac` with 600,000 iterations).
  - AES-256-GCM encryption, decryption, and integrity tag validation.
- Automated tests (`test_crypto.py`) verifying SHA-256 PBKDF2 hashing/verification and AES-GCM tamper rejection.

### Phase 2: Database Models & Persistence
- Configure SQLite and SQLAlchemy in `app/extensions.py` and `app/config.py`.
- Define database models: `User`, `Wallet`, `Transaction`, `DemoCard`, `AuditLog`.
- Add `CheckConstraint('balance_cents >= 0')` on the `Wallet` model.
- Write tests verifying schema creation, model relationships, and constraints.

### Phase 3: Authentication & User Accounts
- Build `AuthService` and `routes/auth.py`.
- Implement registration with password complexity requirements and initial simulated wallet provisioning ($100.00 demo bonus).
- Implement login with rate-limiting and session fixation protection.
- Build responsive HTML templates for Login and Register.
- Automated tests (`test_auth.py`) verifying valid/invalid credentials, password hashing, and session management.

### Phase 4: Wallet Engine & Atomic Transactions
- Build `WalletService` and `routes/wallet.py`.
- Implement simulated deposit mechanism.
- Implement peer-to-peer transfer with atomic transactions, recipient validation, and fee calculations.
- Implement transaction history ledger with pagination.
- Automated tests (`test_wallet.py`) validating transfers, insufficient fund rejection, self-transfer prevention, and atomic rollbacks on error.

### Phase 5: Demo Sensitive Data Vault (AES-256-GCM)
- Build `routes/cards.py` and card management UI.
- Allow users to store simulated demo cards.
- Encrypt card billing details with AES-256-GCM before saving to database.
- Provide a secure "Reveal" view demonstrating authenticated decryption and audit log generation.
- Automated tests verifying encrypted storage and decryption.

### Phase 6: Frontend Interface & Security Hardening
- Develop clean, accessible Jinja2 templates (`base.html`, `dashboard.html`, `transfer.html`, `deposit.html`, `history.html`).
- Integrate CSRF protection across all forms.
- Configure security HTTP response headers (X-Content-Type-Options, X-Frame-Options, CSP).
- Add user-friendly flash messages for errors and success states.

### Phase 7: Comprehensive Security Audit & Final Testing
- Run complete `pytest` test suite across all modules.
- Perform security tests: IDOR attempts, negative amount submissions, double-spend simulations, and CSRF token tampering.
- Finalize documentation and user guide.
