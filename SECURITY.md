# Security Architecture & Cryptographic Analysis
*Secure Digital Wallet — Educational Simulation Project*

---

## 1. Password Storage Architecture (Salted SHA-256)

In this project, password storage is implemented using **SHA-256 combined with a unique, cryptographically secure random salt** per user.

### The Storage & Verification Workflow

```
[ Registration Workflow ]

User Plaintext Password
         +
Cryptographically Secure Random Unique Salt (32 bytes via secrets.token_hex)
         ↓
      SHA-256
         ↓
64-character Hexadecimal Password Hash

Stored in SQLite:
  - users.password_hash (64 characters)
  - users.password_salt (64 characters)
  * Plaintext password is immediately discarded from memory.
```

```
[ Login Verification Workflow ]

Entered Plaintext Password
         +
User's Stored Salt (retrieved from database by username/email)
         ↓
      SHA-256
         ↓
Candidate Hash ────[ Constant-Time Comparison (hmac.compare_digest) ]──── Stored Hash
                                  │
                       ┌──────────┴──────────┐
                       ▼                     ▼
                  Match: Grant          Mismatch: Deny
```

### Why a Unique Salt is Essential
1. **Destroys Rainbow Tables**: A rainbow table is a precomputed database of plaintext passwords and their corresponding hashes. Because every user has a globally unique 256-bit salt, precomputed tables become useless. An attacker would have to generate a brand new rainbow table for each individual user's salt ($2^{256}$ possibilities).
2. **Hides Identical Passwords**: If two users choose the same password (e.g. `Password123!`), their stored hashes are completely different because their salts are unique.
3. **No Hardcoded / Global Salts**: Global salts (pepper) without per-user salts still allow identical passwords to produce identical hashes. A unique salt is generated per user using Python's `secrets.token_hex(32)`.

---

## 2. Critical Analysis: Limitations of Single-Round SHA-256 in Real-World Production

While Salted SHA-256 satisfies the educational requirements of this academic project, **it is NOT recommended for production financial systems**. Below is an analysis of its cryptographic limitations:

### 1. High Computation Speed (The GPU Threat)
* **Design Purpose**: SHA-256 (part of the SHA-2 family published by NIST) was engineered for high-throughput data integrity verification (e.g., verifying multi-gigabyte ISO images or TLS packets), not password storage. It is intentionally fast to compute.
* **Attack Feasibility**: Modern consumer graphics processing units (GPUs) such as an NVIDIA RTX 4090 can compute **over 10 billion raw SHA-256 hashes per second**. If an attacker obtains a database leak, they can brute-force 8-character alphanumeric passwords across dictionary wordlists in minutes, despite the salt.

### 2. Lack of Memory-Hardness
* SHA-256 requires almost zero RAM (a few internal 32-bit registers).
* Attackers can manufacture inexpensive Application-Specific Integrated Circuits (ASICs) or use Field-Programmable Gate Arrays (FPGAs) to parallelize billions of password guesses without running into memory bandwidth bottlenecks.

### 3. Absence of Key Stretching (Single-Round Execution)
* In our scheme, the hash function runs exactly **once** per password check.
* Modern password hashing schemes use **Key Derivation Functions (KDFs)** that iterate hundreds of thousands of times (e.g., PBKDF2 with 600,000 rounds) or use memory-hard matrices (Argon2id, scrypt, bcrypt) to intentionally slow down attackers while keeping single-user login times negligible (~0.1s).

### Summary Comparison Table

| Algorithm | Type | GPU Cracking Resistance | Memory-Hard? | Production Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Plain SHA-256** | Hash | ❌ Very Poor (Instant) | No | ❌ Forbidden for passwords |
| **Salted SHA-256 (Current)** | Hash + Salt | ⚠️ Moderate (Defeats rainbow tables, but fast for GPUs) | No | ⚠️ Educational / Academic Use Only |
| **PBKDF2-HMAC-SHA256** | KDF (600k rounds) | ✅ Strong | No | ✅ Acceptable (FIPS compliant) |
| **bcrypt** | KDF (Cost 12+) | ✅ Strong | Minor | ✅ Recommended for web apps |
| **Argon2id** | Memory-hard KDF | 🏆 State-of-the-Art | Yes (Configurable RAM) | 🏆 Industry Standard (PHC Winner) |

---

## 3. Defense-in-Depth Implementation in Step 2

To maximize security within the project's educational framework, the following defensive controls are enforced:

### 1. Constant-Time Hash Comparison
Standard string equality (`hash_a == hash_b`) terminates as soon as the first differing character is encountered, leaking execution timing information (a **timing side-channel attack**). 
We use `hmac.compare_digest()` which executes in constant time regardless of where or if characters match.

### 2. Brute-Force Rate Limiting
To counter automated password guessing against the login endpoint:
* An in-memory rate limiter tracks consecutive failed attempts per IP address and per username.
* After **5 failed attempts**, the endpoint returns `HTTP 429 Too Many Requests` and locks the target account/IP for **300 seconds (5 minutes)**.

### 3. Account Enumeration Defense
The login endpoint returns a generic error message:
> `"Invalid username or password."`
It never indicates whether the username exists or if only the password was incorrect.

### 4. Session Security & Fixation Defense
* Upon successful authentication, `session.clear()` is called before setting `session['user_id']`. This regenerates session state and destroys any pre-existing unauthenticated session identifier, mitigating **Session Fixation**.
* Cookies are configured with:
  * `SESSION_COOKIE_HTTPONLY = True`: Blocks JavaScript `document.cookie` access, mitigating session theft via XSS.
  * `SESSION_COOKIE_SAMESITE = 'Lax'`: Mitigates Cross-Site Request Forgery (CSRF).

### 5. Cache-Control for Authenticated Views
Authenticated views (such as the `/dashboard`) and authentication forms issue:
```http
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
Pragma: no-cache
```
This ensures browsers do not cache private account pages in local browser history, preventing unauthorized viewing via the browser "Back" button after a user logs out.

### 6. Cross-Site Request Forgery (CSRF) Protection
All authentication forms (`/register` and `/login`) utilize `Flask-WTF` with cryptographic CSRF tokens embedded as hidden input fields. State-modifying POST requests without a valid token are rejected.

---

## 4. Symmetric Data Encryption Architecture (AES-256-GCM)

For sensitive demonstration data (such as simulated payment card billing metadata and account notes), the system uses **AES-256-GCM** (Advanced Encryption Standard in Galois/Counter Mode) via Python's reputable `cryptography` library.

### 1. Authenticated Encryption with Associated Data (AEAD)

Standard encryption modes like AES-CBC or AES-ECB provide confidentiality but lack cryptographic integrity:
* **ECB (Electronic Codebook)**: Encrypts identical plaintext blocks to identical ciphertext blocks, leaking structural patterns.
* **CBC (Cipher Block Chaining)**: Susceptible to bit-flipping attacks and padding oracle attacks if not paired with an explicit HMAC (Encrypt-then-MAC).

**AES-GCM** is an **AEAD** (Authenticated Encryption with Associated Data) mode that simultaneously provides:
1. **Confidentiality**: High-speed symmetric encryption using counter mode.
2. **Integrity & Authenticity**: A 128-bit (16-byte) authentication tag computed using Galois field multiplication ($\text{GF}(2^{128})$). If even a single bit in the ciphertext, nonce, or associated data is altered, decryption fails immediately with `cryptography.exceptions.InvalidTag` (surfaced as `TamperedDataError`).

### 2. Cryptographic Workflow & Data Packaging

```
[ Encryption Process ]

Plaintext Sensitive Metadata
         │
         ├─── Fresh 12-byte Nonce (os.urandom(12))
         ├─── 256-bit Key (loaded from ENCRYPTION_KEY env var)
         └─── Optional Authenticated Associated Data (AAD)
         │
         ▼
    AES-256-GCM
         │
         ▼
[ Nonce (12 bytes) ] + [ Ciphertext ] + [ Auth Tag (16 bytes) ]
         │
         ▼
Base64-Encoded String (Safe for SQLite TEXT persistence)
```

```
[ Decryption & Verification Process ]

Base64 Payload from Database
         │
         ▼
Unpack into Nonce (12 bytes) + Ciphertext + Tag (16 bytes)
         │
         ├─── 256-bit Key
         └─── Authenticated Associated Data (AAD)
         │
         ▼
   AES-256-GCM Decrypt & Tag Verification
         │
   ┌─────┴─────────────────────────┐
   ▼                               ▼
Tag Matches: Plaintext Recovered   Tag Mismatch: TamperedDataError Raised
```

### 3. The Critical Importance of Nonce Uniqueness (Preventing Nonce Reuse)

In AES-GCM, the **nonce** (Number used Once) must **NEVER** be repeated under the same encryption key:
* **Confidentiality Loss**: If two messages are encrypted with the same key and nonce, the XOR of the two plaintexts is revealed: $C_1 \oplus C_2 = P_1 \oplus P_2$.
* **Authenticity Loss**: Nonce reuse enables an attacker to solve for the internal authentication hash key ($H$), allowing them to forge valid authentication tags for arbitrary forged ciphertexts.

**Our Mitigation**:
Every call to `encrypt()` generates a fresh, cryptographically secure 12-byte (96-bit) random nonce using `os.urandom(12)`. With 96 bits of entropy, the probability of a random collision is negligible ($< 10^{-14}$ for billions of operations), ensuring strict nonce uniqueness.

### 4. Key Management & Environment Isolation

* **Never Hard-Coded**: The 256-bit key is loaded strictly from the `ENCRYPTION_KEY` environment variable.
* **No Insecure Defaults**: In `ProductionConfig`, an unset `ENCRYPTION_KEY` causes an explicit error rather than falling back to an insecure default.
* **Zero API Exposure**: The encryption key is strictly kept in backend memory and is never exposed in HTTP responses, error messages, or logs.
* **Safe Representation**: The `DemoCard` model's `__repr__` method explicitly excludes sensitive metadata and ciphertexts to prevent accidental leakage in debug logs or terminal traces.

### 5. PCI-DSS Educational Compliance & Zero CVV Policy

To model real-world Payment Card Industry Data Security Standards (PCI-DSS):
1. **Zero CVV Storage**: Card Verification Values (CVV / CVC) are never requested on any form, accepted in any service method, or stored in any database column.
2. **Zero Full Card Number Storage**: Full Primary Account Numbers (PANs) are never stored. Only the last 4 digits are retained for masked UI display (`**** **** **** 1234`).
3. **Simulated Scope Only**: All card numbers and billing addresses are strictly simulated demo records.
