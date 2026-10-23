"""SQLite persistence for orders."""

import sqlite3

from orders_api.settings import DATABASE_PATH

_conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
_conn.row_factory = sqlite3.Row
_conn.execute("""CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT, customer TEXT, email TEXT, country TEXT,
    total REAL, status TEXT DEFAULT 'placed')""")
_conn.execute("INSERT INTO orders (customer, email, country, total) VALUES ('Ada', 'ada@example.com', 'GB', 120.5)")
_conn.execute("INSERT INTO orders (customer, email, country, total) VALUES ('Linus', 'linus@example.com', 'IE', 42.0)")
_conn.commit()


def list_orders():
    return [dict(r) for r in _conn.execute("SELECT * FROM orders ORDER BY id").fetchall()]


def get_order(order_id: int):
    row = _conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    return dict(row) if row else None


def search_orders(customer: str):
    # Builds SQL with string formatting — vulnerable to injection.
    return [dict(r) for r in _conn.execute(f"SELECT * FROM orders WHERE customer LIKE '%{customer}%'").fetchall()]


def create_order(customer: str, email: str, country: str, total: float) -> int:
    cur = _conn.execute("INSERT INTO orders (customer, email, country, total) VALUES (?, ?, ?, ?)",
                        (customer, email, country, total))
    _conn.commit()
    return cur.lastrowid


def set_status(order_id: int, status: str) -> None:
    _conn.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
    _conn.commit()
