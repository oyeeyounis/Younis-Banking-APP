#!/usr/bin/env python3
import os
import sqlite3
import getpass
import secrets
import hashlib
import datetime
from dataclasses import dataclass
from typing import Optional, Tuple, List

# Database in the current working directory (you can override with BANK_DB env var)
DB_FILE = os.environ.get("BANK_DB", os.path.join(os.getcwd(), "bank.db"))
PBKDF2_ROUNDS = 120_000

def now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def to_cents(amount_str: str) -> int:
    amount_str = amount_str.strip().replace(",", "")
    if amount_str.startswith("$"):
        amount_str = amount_str[1:]
    if amount_str.count(".") > 1:
        raise ValueError("Invalid amount format")
    parts = amount_str.split(".")
    if len(parts) == 1:
        whole = parts[0]
        frac = "00"
    else:
        whole, frac = parts
        if len(frac) > 2:
            raise ValueError("Too many decimal places; use at most 2")
        frac = (frac + "00")[:2]
    if whole == "":
        whole = "0"
    if (whole.startswith("-") and whole[1:].isdigit()) or whole.isdigit():
        pass
    else:
        raise ValueError("Invalid amount")
    if not frac.isdigit():
        raise ValueError("Invalid cents")
    sign = -1 if whole.startswith("-") else 1
    whole_abs = int(whole.lstrip("-"))
    return sign * (whole_abs * 100 + int(frac))

def from_cents(cents: int) -> str:
    sign = "-" if cents < 0 else ""
    cents = abs(cents)
    return f"{sign}{cents//100}.{cents%100:02d}"

def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return salt, dk

def verify_password(password: str, salt: bytes, hashed: bytes) -> bool:
    _, dk = hash_password(password, salt)
    return secrets.compare_digest(dk, hashed)

def prompt_password(prompt: str) -> str:
    """Prompt for a password; if getpass can't control the terminal, fall back to input()."""
    try:
        return getpass.getpass(prompt)
    except Exception:
        # Some IDEs/online editors don't support getpass and raise OSError: [Errno 29] I/O error
        print("(Note: password input not hidden in this environment.)")
        return input(prompt)

def get_conn():
    try:
        # ensure the directory exists
        db_dir = os.path.dirname(DB_FILE) or "."
        os.makedirs(db_dir, exist_ok=True)
        return sqlite3.connect(DB_FILE)
    except OSError as e:
        print(f"I/O error opening database at {DB_FILE}: {e}")
        raise

def init_db():
    with get_conn() as conn:
        cur = conn.cursor()
        cur.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                type TEXT NOT NULL CHECK (type IN ('checking','savings')),
                balance_cents INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, name)
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                kind TEXT NOT NULL CHECK (kind IN ('deposit','withdraw','transfer_in','transfer_out')),
                amount_cents INTEGER NOT NULL,
                balance_after_cents INTEGER NOT NULL,
                note TEXT,
                created_at TEXT NOT NULL
            );
            """
        )

@dataclass
class User:
    id: int
    username: str

@dataclass
class Account:
    id: int
    user_id: int
    name: str
    type: str
    balance_cents: int

def create_user(username: str, password: str) -> User:
    salt, pw_hash = hash_password(password)
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, salt, password_hash, created_at) VALUES (?,?,?,?)",
            (username, salt, pw_hash, now_iso()),
        )
        user_id = cur.lastrowid
        cur.execute(
            "INSERT INTO accounts (user_id, name, type, balance_cents, created_at) VALUES (?,?,?,?,?)",
            (user_id, "Checking", "checking", 0, now_iso()),
        )
        conn.commit()
        return User(user_id, username)

def get_user_by_username(username: str) -> Optional[tuple]:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, salt, password_hash FROM users WHERE username=?",
            (username,),
        )
        return cur.fetchone()

def list_accounts(user_id: int) -> List[Account]:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, user_id, name, type, balance_cents FROM accounts WHERE user_id=? ORDER BY id",
            (user_id,),
        )
        rows = cur.fetchall()
        return [Account(*row) for row in rows]

def get_account(user_id: int, name: str) -> Optional[Account]:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, user_id, name, type, balance_cents FROM accounts WHERE user_id=? AND name=?",
            (user_id, name),
        )
        row = cur.fetchone()
        return Account(*row) if row else None

def create_account(user_id: int, name: str, type_: str) -> Account:
    if type_ not in {"checking", "savings"}:
        raise ValueError("type must be 'checking' or 'savings'")
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO accounts (user_id, name, type, balance_cents, created_at) VALUES (?,?,?,?,?)",
            (user_id, name, type_, 0, now_iso()),
        )
        conn.commit()
        acc_id = cur.lastrowid
        return Account(acc_id, user_id, name, type_, 0)

def add_tx(conn: sqlite3.Connection, account_id: int, kind: str, amount_cents: int, note: str = ""):
    cur = conn.cursor()
    cur.execute("SELECT balance_cents FROM accounts WHERE id=?", (account_id,))
    row = cur.fetchone()
    if not row:
        raise ValueError("Account not found")
    balance = row[0]
    new_balance = balance + amount_cents
    if new_balance < 0:
        raise ValueError("Insufficient funds")
    cur.execute("UPDATE accounts SET balance_cents=? WHERE id=?", (new_balance, account_id))
    cur.execute(
        "INSERT INTO transactions (account_id, kind, amount_cents, balance_after_cents, note, created_at) VALUES (?,?,?,?,?,?)",
        (account_id, kind, amount_cents, new_balance, note, now_iso()),
    )

def deposit(user_id: int, account_name: str, amount_cents: int, note: str = ""):
    if amount_cents <= 0:
        raise ValueError("Deposit must be positive")
    acc = get_account(user_id, account_name)
    if not acc:
        raise ValueError("Account not found")
    with get_conn() as conn:
        add_tx(conn, acc.id, "deposit", amount_cents, note)
        conn.commit()

def withdraw(user_id: int, account_name: str, amount_cents: int, note: str = ""):
    if amount_cents <= 0:
        raise ValueError("Withdrawal must be positive")
    acc = get_account(user_id, account_name)
    if not acc:
        raise ValueError("Account not found")
    with get_conn() as conn:
        add_tx(conn, acc.id, "withdraw", -amount_cents, note)
        conn.commit()

def transfer(user_id: int, from_acc: str, to_acc: str, amount_cents: int, note: str = ""):
    if amount_cents <= 0:
        raise ValueError("Transfer amount must be positive")
    src = get_account(user_id, from_acc)
    dst = get_account(user_id, to_acc)
    if not src or not dst:
        raise ValueError("Account not found")
    if src.id == dst.id:
        raise ValueError("Cannot transfer to the same account")
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        add_tx(conn, src.id, "transfer_out", -amount_cents, note)
        add_tx(conn, dst.id, "transfer_in", amount_cents, note)
        conn.commit()

def get_history(user_id: int, account_name: str, limit: int = 20):
    acc = get_account(user_id, account_name)
    if not acc:
        raise ValueError("Account not found")
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT kind, amount_cents, balance_after_cents, note, created_at FROM transactions WHERE account_id=? ORDER BY id DESC LIMIT ?",
            (acc.id, limit),
        )
        return cur.fetchall()

class Session:
    def __init__(self, user: "User"):
        self.user = user

    def menu(self):
        while True:
            print("\n=== Younis Bank Menu ===")
            print("1) Accounts")
            print("2) Deposit")
            print("3) Withdraw")
            print("4) Transfer")
            print("5) History")
            print("6) Create Account")
            print("7) Logout")
            choice = input("Choose: ").strip()
            try:
                if choice == "1":
                    self.show_accounts()
                elif choice == "2":
                    self.do_deposit()
                elif choice == "3":
                    self.do_withdraw()
                elif choice == "4":
                    self.do_transfer()
                elif choice == "5":
                    self.do_history()
                elif choice == "6":
                    self.do_create_account()
                elif choice == "7":
                    print("Logged out.")
                    return
                else:
                    print("Invalid choice")
            except Exception as e:
                print(f"Error: {e}")

    def show_accounts(self):
        accounts = list_accounts(self.user.id)
        print("\nYour Accounts:")
        for a in accounts:
            print(f"- {a.name} ({a.type}): $ {from_cents(a.balance_cents)}")

    def do_deposit(self):
        name = input("Account name: ").strip()
        amount = to_cents(input("Amount: "))
        note = input("Note (optional): ").strip()
        deposit(self.user.id, name, amount, note)
        print("Deposited.")

    def do_withdraw(self):
        name = input("Account name: ").strip()
        amount = to_cents(input("Amount: "))
        note = input("Note (optional): ").strip()
        withdraw(self.user.id, name, amount, note)
        print("Withdrawn.")

    def do_transfer(self):
        src = input("From account: ").strip()
        dst = input("To account: ").strip()
        amount = to_cents(input("Amount: "))
        note = input("Note (optional): ").strip()
        transfer(self.user.id, src, dst, amount, note)
        print("Transferred.")

    def do_history(self):
        name = input("Account name: ").strip()
        limit_str = input("How many rows (default 20): ").strip() or "20"
        limit = max(1, min(200, int(limit_str)))
        rows = get_history(self.user.id, name, limit)
        if not rows:
            print("No transactions.")
            return
        print("kind | amount | balance_after | note | created_at")
        print("-" * 70)
        for kind, amt, bal, note, ts in rows:
            print(f"{kind:12s} | {from_cents(amt):>8s} | {from_cents(bal):>13s} | {note[:20]:20s} | {ts}")

    def do_create_account(self):
        name = input("New account name: ").strip()
        type_ = input("Type (checking/savings): ").strip().lower()
        acc = create_account(self.user.id, name, type_)
        print(f"Created account '{acc.name}' ({acc.type}).")

def signup_flow() -> Optional["User"]:
    print("\n=== Sign Up ===")
    username = input("Choose a username: ").strip()
    if not username:
        print("Username required")
        return None
    if get_user_by_username(username):
        print("Username already exists")
        return None
    pw1 = prompt_password("Choose a password: ")
    pw2 = prompt_password("Confirm password: ")
    if pw1 != pw2 or len(pw1) < 6:
        print("Passwords must match and be at least 6 characters")
        return None
    user = create_user(username, pw1)
    print("Account created. A 'Checking' account has been added for you.")
    return user

def login_flow() -> Optional["User"]:
    print("\n=== Login ===")
    username = input("Username: ").strip()
    row = get_user_by_username(username)
    if not row:
        print("User not found")
        return None
    user_id, username, salt, pw_hash = row
    password = prompt_password("Password: ")
    if verify_password(password, salt, pw_hash):
        return User(user_id, username)
    else:
        print("Invalid password")
        return None

def main():
    init_db()
    print("Welcome to Younis Bank")
    while True:
        print("\n1) Login\n2) Sign Up\n3) Exit")
        choice = input("Choose: ").strip()
        if choice == "1":
            user = login_flow()
            if user:
                Session(user).menu()
        elif choice == "2":
            user = signup_flow()
            if user:
                Session(user).menu()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    try:
        main()
    except OSError as e:
        print(f"I/O error: {e}")
