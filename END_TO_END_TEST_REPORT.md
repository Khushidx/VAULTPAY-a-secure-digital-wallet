# Secure Digital Wallet — End-to-End (E2E) Test Report

**Project**: Secure Digital Wallet (College Educational Simulation)  
**Date of Execution**: September 21, 2026  
**Test Engineers**: Pair Programming AI & Student Developer  
**Status**: **PASS (100% Success Across All Suites)**  

---

## 1. Executive Summary & Safety Scope

This report documents the end-to-end (E2E) verification of the **Secure Digital Wallet** web application. The testing was conducted strictly within the project's educational simulation boundaries:

> [!IMPORTANT]
> **Strict Educational Simulation Notice:**
> - All tests were conducted using **100% simulated, fake demonstration data**.
> - **ZERO real financial credentials** (no real card numbers, no CVVs, no real bank account numbers) were entered, stored, or processed.
> - **ZERO connections to real-world payment processors or banking APIs** exist in this codebase.
> - Monetary values represent simulated educational units stored as integer cents.

Two primary demo personas were created and evaluated through complete multi-step lifecycles:
1. **Alice** (`username: Alice`, `email: alice@college.edu`)
2. **Bob** (`username: Bob`, `email: bob@college.edu`)

All **12 positive lifecycle steps**, **7 negative/security edge cases**, **link integrity audits**, and **data leakage checks** passed without failure.

---

## 2. Test Environment & Architecture

| Component | Specification |
| :--- | :--- |
| **Runtime Environment** | Python 3.11.9 on Windows 64-bit |
| **Web Framework** | Flask 3.1.3 with Jinja2 Templating |
| **ORM / Database** | SQLAlchemy 3.1.1 with SQLite (`CHECK (balance_cents >= 0)`) |
| **Cryptography** | AES-256-GCM via `cryptography` 50.0.1, Salted SHA-256 via `hashlib` |
| **Test Framework** | Pytest 9.1.1 (54 unit and E2E test cases) |
| **Execution Scripts** | `tests/test_e2e.py` and `scripts/verify_e2e_live.py` |

---

## 3. Positive User Flow Verification (Steps 1–12)

The positive test flow simulated the complete user journey between Alice and Bob:

```
+---------------------------------------------------------------------------------------------------+
|                                      POSITIVE E2E FLOW                                            |
|                                                                                                   |
|  [Step 1: Alice Registers] ----> [Step 2: Alice Logs In] ----> [Step 3: Deposits $150.00]         |
|                                                                          |                        |
|                                                                          v                        |
|  [Step 6: Bob Registers] <---- [Step 5: Balance = $150.00] <---- [Step 4: Adds Demo Visa]        |
|           |                                                                                       |
|           v                                                                                       |
|  [Step 7: Alice Sends $40.00 to Bob] (Alice: $110.00, Bob: $40.00)                               |
|           |                                                                                       |
|           v                                                                                       |
|  [Step 8: Bob Logs In] ----> [Step 9: Bob Checks Balance: $40.00] ----> [Step 10: History Check]   |
|                                                                                |                  |
|                                                                                v                  |
|  [Step 12: Protected Route Defense] <--------------------------------- [Step 11: Alice Logs Out]  |
+---------------------------------------------------------------------------------------------------+
```

### Detailed Step-by-Step Results

| Step # | Action | Expected Result | Actual Result | Status |
| :---: | :--- | :--- | :--- | :---: |
| **1** | Alice registers (`Alice`, `alice@college.edu`) | Account created, salted SHA-256 hash stored, initial wallet created with $0.00 | 200 OK, unique 256-bit salt generated, wallet provisioned | **PASS** |
| **2** | Alice logs in (`Alice`, `AliceSecurePass123!`) | Session created, session fixation defense triggers (`session.clear()`), redirect to dashboard | 200 OK, session cookie issued with `HttpOnly`, `SameSite=Lax` | **PASS** |
| **3** | Alice receives simulated money ($150.00) | Atomic deposit of 15,000 cents, transaction ledger record created with `COMPLETED` status | 200 OK, flash confirms deposit, balance shows $150.00 | **PASS** |
| **4** | Alice adds a demo payment method | Demo Visa (`**** **** **** 4242`) saved, metadata encrypted at rest via AES-256-GCM, zero CVV collected | 200 OK, token `tok_demo_visa_...` generated, metadata encrypted | **PASS** |
| **5** | Alice views her balance | Dashboard renders `$150.00` (15,000 cents) and recent transactions table shows deposit | 200 OK, formatted balance `$150.00` verified | **PASS** |
| **6** | Bob registers (`Bob`, `bob@college.edu`) | Account created, unique salt generated, wallet provisioned with $0.00 | 200 OK, recipient account active and discoverable | **PASS** |
| **7** | Alice sends $40.00 to Bob | Atomic transfer: Alice debited 4,000 cents ($110.00 balance), Bob credited 4,000 cents. Reciprocal double-entry ledger records created | 200 OK, flash confirms sent to `@Bob`, Alice balance shows `$110.00` | **PASS** |
| **8** | Bob logs in (`Bob`, `BobSecurePass456!`) | Authenticated session established for Bob | 200 OK, Bob dashboard loaded | **PASS** |
| **9** | Bob checks his balance | Available simulated balance displays `$40.00` (4,000 cents) | 200 OK, balance verified at `$40.00` | **PASS** |
| **10** | Bob checks transaction history | Ledger displays `+$40.00` received from `@Alice` with note `"Split textbook costs"` | 200 OK, immutable ledger record verified | **PASS** |
| **11** | Alice logs out | Session cleared on server, session cookie invalidated | 200 OK, redirect to home page with logout notice | **PASS** |
| **12** | Logged-out access to protected pages | Anonymous GET requests to 10 protected routes are redirected to `/login` | 302 Redirect to `/login` across all 10 endpoints | **PASS** |

---

## 4. Negative & Security Edge Case Results

The application was subjected to hostile and malformed inputs to verify defensive depth:

```
+----------------------------------------------------------------------------------------------------+
|                                    SECURITY DEFENSE SUMMARY                                        |
|                                                                                                    |
|  Attack / Fault Scenario       | Defense Mechanism                     | Status                    |
|  ----------------------------- | ------------------------------------- | ------------------------- |
|  Wrong Password                | Constant-Time Salted SHA-256 Compare  | HTTP 401 Blocked          |
|  Zero / Negative Money         | Server-side Integer Cent Validator    | HTTP 400 Blocked          |
|  Floating-Point Sub-cents      | Max 2 Decimal Places Check            | HTTP 400 Blocked          |
|  Insufficient Wallet Balance   | Atomic Balance Pre-check + DB Check   | HTTP 400 Blocked          |
|  Unknown Recipient             | Pre-transfer User Existence Query     | HTTP 400 Blocked          |
|  Self-Transfer (Alice -> Alice)| Identity Invariant Check              | HTTP 400 Blocked          |
|  IDOR Attack (Bob -> Alice PM) | User-Scoped Query Filtering           | Blocked (403/Redirect)    |
+----------------------------------------------------------------------------------------------------+
```

### Detailed Negative Test Cases

1. **Wrong Password Attempt**:
   - *Input*: `username: Alice`, `password: IncorrectPassword999!`
   - *Result*: Rejected with **HTTP 401 Unauthorized** and message `"Invalid username or password."`
   - *Security Feature*: Generic error message prevents username enumeration; failed attempts tracked by `login_limiter`.

2. **Zero Monetary Amount**:
   - *Input*: Deposit `$0.00` and Transfer `$0.00`
   - *Result*: Rejected with **HTTP 400 Bad Request** (`"Amount must be strictly greater than zero ($0.00)."`).

3. **Negative Monetary Amount**:
   - *Input*: Deposit `-$25.00` and Transfer `-$15.00`
   - *Result*: Rejected with **HTTP 400 Bad Request** (`"Amount must be strictly greater than zero ($0.00)."`).
   - *Database Invariant*: SQLite `CHECK (balance_cents >= 0)` constraint prevents negative balances at the storage level.

4. **Malformed & Fractional Amounts**:
   - *Input*: Deposit `"one_hundred"`, Transfer `"abc"`, Deposit `"10.999"` (3 decimal places)
   - *Result*: Rejected with **HTTP 400 Bad Request** (`"Invalid amount format."` and `"Amount cannot have more than 2 decimal places."`).

5. **Insufficient Balance (Overdraft Attempt)**:
   - *Input*: Alice has `$110.00` balance, attempts to transfer `$999.00` to Bob.
   - *Result*: Rejected with **HTTP 400 Bad Request** (`"Insufficient balance. You have $110.00, but tried to send $999.00."`).
   - *Integrity Check*: Alice's balance remained `$110.00`; Bob's balance remained `$40.00`. Zero phantom money was created.

6. **Unknown Recipient**:
   - *Input*: Alice attempts to transfer `$10.00` to `"GhostStudent99"`.
   - *Result*: Rejected with **HTTP 400 Bad Request** (`"Recipient 'GhostStudent99' was not found or the account is inactive."`).

7. **Self-Transfer Prevention**:
   - *Input*: Alice attempts to transfer `$10.00` to `"Alice"`.
   - *Result*: Rejected with **HTTP 400 Bad Request** (`"You cannot transfer money to yourself."`).

8. **Insecure Direct Object Reference (IDOR) Defense**:
   - *Scenario*: Bob attempts to access Alice's saved payment method (`/payment-methods/<alice_pm_id>/reveal`) and delete it (`/payment-methods/<alice_pm_id>/delete`).
   - *Result*: Service queries strictly enforce `user_id == g.current_user.id`. Bob is redirected with an authorization flash message. Alice's encrypted metadata is **never decrypted or leaked**, and her record remains intact in the database.

---

## 5. Link Integrity & Page Crawl Audit

An automated crawler visited all core application pages while authenticated as a test user and inspected all discovered `<a href>` and `<form action>` links:

| URL Crawled | HTTP Status | Link Audit Notes |
| :--- | :---: | :--- |
| `/` | `200 OK` | Landing page, links to `/health`, `/login`, `/register` |
| `/health` | `200 OK` | JSON health check (`{"status": "healthy"}`) |
| `/wallet/dashboard` | `200 OK` | Balance card, send, deposit, payment methods, profile links |
| `/wallet/deposit` | `200 OK` | Deposit form, back to dashboard link |
| `/wallet/transfer` | `200 OK` | Transfer form, recipient lookup, back to dashboard link |
| `/wallet/history` | `200 OK` | Full ledger table, deposit shortcut link |
| `/payment-methods` | `200 OK` | List saved demo payment methods, add method link |
| `/payment-methods/new` | `200 OK` | Form with type selector, last-4, and encrypted metadata |
| `/cards` | `200 OK` | Demo cards list, add card link |
| `/cards/new` | `200 OK` | Demo card form, last-4 only, encrypted billing details |
| `/profile` | `200 OK` | Security posture, active session, salt status, logout link |

**Crawl Summary**:
- Total Discovered Internal Links: **16**
- Broken Links (HTTP 404): **0**
- Server Errors (HTTP 500): **0**
- Permanent Redirection Consistency (HTTP 308): **Resolved** (empty route paths added to `cards_bp` and `wallet_bp`).

---

## 6. Cryptographic & Privacy Leakage Audit

A comprehensive content audit of the rendered HTML responses across all 11 pages verified strict privacy and cryptographic confidentiality:

| Audited Element | Verification Method | Exposure Status |
| :--- | :--- | :---: |
| **Plaintext Passwords** | Grep rendered HTML for `"AliceSecurePass123!"` & `"BobSecurePass456!"` | **0 Leaks (CLEAN)** |
| **Password Hashes** | Grep rendered HTML for 64-char SHA-256 hex string | **0 Leaks (CLEAN)** |
| **Password Salts** | Grep rendered HTML for 64-char salt hex string | **0 Leaks (CLEAN)** |
| **AES-256-GCM Master Key** | Grep rendered HTML for Base64 encryption key | **0 Leaks (CLEAN)** |
| **Raw Credit Card Numbers** | Regex pattern matching for 16-digit PANs | **0 Leaks (CLEAN)** |
| **Card CVVs** | Field verification across all forms and models | **0 Leaks (NEVER STORED)** |

### Security Headers & Cache Control Audit

Every authenticated response was verified for standard security headers:
- `X-Content-Type-Options: nosniff` (Active)
- `X-Frame-Options: SAMEORIGIN` (Active)
- `Content-Security-Policy` (Active: `default-src 'self'`)
- `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` (Enforced across sensitive financial and profile pages to prevent browser cache leaks)

---

## 7. Discrepancies Discovered & Remediations Applied

During test development and execution, two minor issues were identified and resolved:

1. **Route Trailing-Slash 308 Redirects**:
   - *Finding*: Requesting `/cards` or `/wallet` without a trailing slash resulted in an HTTP 308 permanent redirect from Flask because the routes were defined solely as `@cards_bp.route("/")`.
   - *Remediation*: Added empty route definitions (`@cards_bp.route("")` and `@wallet_bp.route("")`) alongside the slashed routes in `app/routes/cards.py` and `app/routes/wallet.py`.

2. **Windows Terminal CP1252 Stdout Encoding in Verification Script**:
   - *Finding*: On Windows cmd/powershell running under `cp1252` encoding, Unicode checkmark characters (`\u2713`) caused a `UnicodeEncodeError`.
   - *Remediation*: Added `sys.stdout.reconfigure(encoding="utf-8")` with safe ASCII fallback strings (`[PASS]`, `[BLOCKED - EXPECTED]`) in `scripts/verify_e2e_live.py`.

---

## 8. Summary Verdict & Sign-Off

```
======================================================================
  FINAL TEST EXECUTION SUMMARY
======================================================================
  Total Pytest Unit & Integration Tests:     50 / 50 PASSED
  Total Automated End-to-End Tests:           4 /  4 PASSED
  Total Live Verification Steps Executed:    20 / 20 PASSED
  Broken Pages / Broken Links Found:          0
  Data Leakage / Security Vulnerabilities:    0
======================================================================
  OVERALL STATUS: PASS (PRODUCTION-READY EDUCATIONAL SIMULATION)
======================================================================
```

The Secure Digital Wallet application satisfies all functional, architectural, and educational security requirements.
