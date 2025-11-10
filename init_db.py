import sqlite3
import os

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "cards.db")

if os.path.exists(DB_PATH):
    print("Removing existing database:", DB_PATH)
    os.remove(DB_PATH)

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# Create tables
c.executescript("""
PRAGMA foreign_keys = ON;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    credits INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT,
    price INTEGER DEFAULT 0,
    description TEXT,
    image TEXT
);

CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id INTEGER NOT NULL,
    user TEXT,
    text TEXT,
    FOREIGN KEY(card_id) REFERENCES cards(id) ON DELETE CASCADE
);
""")

# Seed users (passwords stored in PLAINTEXT)
users = [
    ("admin", "admin123", "admin", 0),
    ("test", "test123", "user", 0),
    ("nancy", "password", "user", 0),
]
c.executemany("INSERT INTO users (username, password, role, credits) VALUES (?, ?, ?, ?)", users)

cards = [
    ("Picu",    "Electric", 120, "The smallest fakemon!", "/static/images/card_01.jpg"),
    ("Ganger",  "Ghost",     90, "Scary!",                 "/static/images/card_02.jpg"),
    ("Xantu",   "Flying",    85, "Very cute!",            "/static/images/card_03.jpg"),
    ("Chorizo", "Fire",      8000, "Legendary card!!!",      "/static/images/card_00.jpg"),
    ("Eievui",  "Normal",   100, "May change if unattended!", "/static/images/card_04.jpg"),
]
c.executemany(
    "INSERT INTO cards (name, type, price, description, image) VALUES (?, ?, ?, ?, ?)",
    cards
)

conn.commit()
conn.close()
