"""
Database Migration Script.

Ensures that existing SQLite databases have all required columns added,
specifically `security_key_salt` and `security_key_hash` in `payment_methods`.
"""

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"


def migrate_database(db_path: Path):
    if not db_path.exists():
        print(f"[SKIP] {db_path} does not exist.")
        return

    print(f"[MIGRATE] Checking database: {db_path}")
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Check payment_methods table columns
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='payment_methods';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(payment_methods);")
        columns = [col[1] for col in cursor.fetchall()]
        print(f"Current columns in payment_methods: {columns}")

        if "security_key_salt" not in columns:
            print("Adding column 'security_key_salt' to payment_methods...")
            cursor.execute("ALTER TABLE payment_methods ADD COLUMN security_key_salt VARCHAR(64);")
            print("Added 'security_key_salt'.")

        if "security_key_hash" not in columns:
            print("Adding column 'security_key_hash' to payment_methods...")
            cursor.execute("ALTER TABLE payment_methods ADD COLUMN security_key_hash VARCHAR(64);")
            print("Added 'security_key_hash'.")

    # Check wallets table currency column
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='wallets';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(wallets);")
        wallet_cols = [col[1] for col in cursor.fetchall()]
        if "currency" not in wallet_cols:
            print("Adding column 'currency' to wallets...")
            cursor.execute("ALTER TABLE wallets ADD COLUMN currency VARCHAR(3) DEFAULT 'INR';")
            print("Added 'currency'.")

    conn.commit()
    conn.close()
    print(f"[DONE] Migration completed for {db_path}\n")


if __name__ == "__main__":
    for db_file in INSTANCE_DIR.glob("*.sqlite"):
        migrate_database(db_file)
