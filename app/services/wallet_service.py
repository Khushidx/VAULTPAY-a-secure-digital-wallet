"""
Wallet Service Module.

Orchestrates all simulated wallet financial operations with ACID atomicity,
invariants enforcement, and ledger consistency.
"""

from app.extensions import db
from app.models.user import User
from app.models.wallet import Wallet
from app.models.transaction import Transaction
from app.utils.money_integer_cents import format_cents


def create_wallet_for_user(user_id: int, initial_balance_cents: int = 0) -> Wallet:
    """
    Creates a new wallet for a user.
    
    Args:
        user_id (int): ID of the user.
        initial_balance_cents (int): Initial balance in cents (default 0).
        
    Returns:
        Wallet: The newly created wallet instance.
    """
    existing_wallet = Wallet.query.filter_by(user_id=user_id).first()
    if existing_wallet:
        return existing_wallet

    wallet = Wallet(user_id=user_id, balance_cents=initial_balance_cents)
    db.session.add(wallet)
    db.session.flush()
    return wallet


def get_or_create_user_wallet(user_id: int) -> Wallet:
    """
    Retrieves the wallet belonging to the specified user.
    If no wallet exists yet, automatically provisions one.
    """
    wallet = Wallet.query.filter_by(user_id=user_id).first()
    if not wallet:
        wallet = create_wallet_for_user(user_id, initial_balance_cents=0)
        db.session.commit()
    return wallet


def deposit_funds(
    user_id: int, 
    amount_cents: int, 
    description: str = "Simulated Deposit"
) -> Transaction:
    """
    Executes a simulated deposit into the user's wallet.
    
    All operations are executed within an atomic database transaction:
    1. Validate amount > 0.
    2. Retrieve user's wallet.
    3. Increment wallet balance.
    4. Record immutable transaction ledger entry.
    
    Args:
        user_id (int): User ID making the deposit.
        amount_cents (int): Positive integer amount in cents.
        description (str): Description of the deposit.
        
    Returns:
        Transaction: The completed transaction record.
        
    Raises:
        ValueError: If amount_cents is not a positive integer or user wallet not found.
    """
    if not isinstance(amount_cents, int) or amount_cents <= 0:
        raise ValueError("Deposit amount must be a positive integer in cents.")

    try:
        wallet = Wallet.query.filter_by(user_id=user_id).first()
        if not wallet:
            wallet = Wallet(user_id=user_id, balance_cents=0)
            db.session.add(wallet)
            db.session.flush()

        # Increment balance
        wallet.balance_cents += amount_cents

        # Create immutable ledger entry
        tx = Transaction(
            wallet_id=wallet.id,
            amount_cents=amount_cents,
            transaction_type="DEPOSIT",
            status="COMPLETED",
            description=description.strip() if description else "Deposit",
        )
        db.session.add(tx)

        # Commit transaction
        db.session.commit()
        return tx

    except Exception:
        db.session.rollback()
        raise


def get_wallet_transactions(wallet_id: int, limit: int = 50) -> list[Transaction]:
    """
    Retrieves the transaction history for a given wallet, ordered newest first.
    """
    return (
        Transaction.query.filter_by(wallet_id=wallet_id)
        .order_by(Transaction.created_at.desc())
        .limit(limit)
        .all()
    )


def transfer_funds(
    sender_user_id: int,
    recipient_identifier: str,
    amount_cents: int,
    note: str = "",
) -> tuple[Transaction, Transaction]:
    """
    Executes an atomic peer-to-peer money transfer between two registered users.
    
    Invariants & Security Rules:
    1. Recipient must exist and have an active account.
    2. Sender cannot transfer to themselves (sender_id != recipient.id).
    3. Amount must be a positive integer > 0.
    4. Sender must have sufficient balance (sender_wallet.balance_cents >= amount_cents).
    5. Balance updates and ledger records execute inside an atomic database transaction.
    6. If any step fails, the entire transaction rolls back completely.
    
    Args:
        sender_user_id (int): ID of the sending user.
        recipient_identifier (str): Username or email of the recipient.
        amount_cents (int): Amount to transfer in integer cents.
        note (str): Optional transfer description.
        
    Returns:
        tuple[Transaction, Transaction]: (sender_transaction, recipient_transaction)
        
    Raises:
        ValueError: If validation fails (insufficient funds, self-transfer, unknown recipient).
    """
    # 1. Validate amount
    if not isinstance(amount_cents, int) or amount_cents <= 0:
        raise ValueError("Transfer amount must be a positive integer in cents.")

    # 2. Retrieve sender and recipient
    sender = db.session.get(User, sender_user_id)
    if not sender or not sender.is_active:
        raise ValueError("Sender account is invalid or inactive.")

    clean_id = recipient_identifier.strip()
    recipient = User.query.filter(
        (User.username == clean_id) | (User.email == clean_id.lower())
    ).first()

    if not recipient or not recipient.is_active:
        raise ValueError(f"Recipient '{clean_id}' was not found or the account is inactive.")

    # 3. Prevent self-transfer
    if recipient.id == sender_user_id:
        raise ValueError("You cannot transfer money to yourself.")

    # 4. Retrieve wallets
    sender_wallet = get_or_create_user_wallet(sender_user_id)
    recipient_wallet = get_or_create_user_wallet(recipient.id)

    # 5. Check sufficient balance
    if sender_wallet.balance_cents < amount_cents:
        raise ValueError(
            f"Insufficient balance. You have {format_cents(sender_wallet.balance_cents)}, "
            f"but tried to send {format_cents(amount_cents)}."
        )

    # 6. Atomic transfer execution
    try:
        # Deduct from sender
        sender_wallet.balance_cents -= amount_cents

        # Credit to recipient
        recipient_wallet.balance_cents += amount_cents

        clean_note = note.strip() if note else ""
        memo_suffix = f" — {clean_note}" if clean_note else ""

        # Immutable ledger entry for sender (debit)
        tx_sender = Transaction(
            wallet_id=sender_wallet.id,
            amount_cents=-amount_cents,
            transaction_type="TRANSFER_OUT",
            status="COMPLETED",
            description=f"Sent to @{recipient.username}{memo_suffix}",
        )
        db.session.add(tx_sender)

        # Immutable ledger entry for recipient (credit)
        tx_recipient = Transaction(
            wallet_id=recipient_wallet.id,
            amount_cents=amount_cents,
            transaction_type="TRANSFER_IN",
            status="COMPLETED",
            description=f"Received from @{sender.username}{memo_suffix}",
        )
        db.session.add(tx_recipient)

        # Commit transaction
        db.session.commit()
        return tx_sender, tx_recipient

    except Exception:
        db.session.rollback()
        raise

