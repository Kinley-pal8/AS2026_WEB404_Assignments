#!/usr/bin/env python3
"""Create and seed the SQLite database shared by the vulnerable and fixed apps.

    python3 db/seed.py

Creates (overwriting any existing copy): db/app.db
"""
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")

SCHEMA = """
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS products;

CREATE TABLE users (
    id       INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,          -- stored in plaintext ON PURPOSE (see report section 4)
    email    TEXT NOT NULL,
    role     TEXT NOT NULL
);

CREATE TABLE products (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL,
    price           REAL NOT NULL,
    secret_supplier TEXT NOT NULL    -- confidential column, must never reach the client
);
"""

USERS = [
    (1, "admin", "S3cr3t_admin_pw!",   "admin@shop.local", "admin"),
    (2, "alice", "alice-summer-2024",  "alice@shop.local", "customer"),
    (3, "bob",   "hunter2",            "bob@shop.local",   "customer"),
]

PRODUCTS = [
    (1, "Wireless Mouse",     "2.4GHz optical mouse",       14.99, "Shenzhen Peripherals Ltd (contract #A-1188)"),
    (2, "Mechanical Keyboard", "Hot-swap, brown switches",  62.00, "KeyForge OU (contract #K-5521)"),
    (3, "USB-C Hub",          "7-in-1 aluminium hub",       29.50, "PortableTech Inc (contract #H-9032)"),
    (4, "1080p Webcam",       "Auto-focus, dual mic",       41.25, "ClearView Optics (contract #W-2077)"),
]


def main():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?)", USERS)
    conn.executemany("INSERT INTO products VALUES (?, ?, ?, ?, ?)", PRODUCTS)
    conn.commit()
    conn.close()
    print(f"Seeded {DB_PATH}")
    print(f"  users:    {len(USERS)}  (admin / S3cr3t_admin_pw!)")
    print(f"  products: {len(PRODUCTS)}")


if __name__ == "__main__":
    main()
