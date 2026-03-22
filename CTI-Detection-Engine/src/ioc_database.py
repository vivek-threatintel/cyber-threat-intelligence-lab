import sqlite3
import os
from datetime import datetime

# Ek hi jagah path define karo taaki spelling mistake na ho
DB_PATH = "data/ioc_database.db" 

def init_db(db_path=DB_PATH):
    if not os.path.exists("data"):
        os.makedirs("data")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ioc_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc TEXT UNIQUE,
            type TEXT,
            source TEXT,
            confidence INTEGER,
            first_seen TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print(f"✅ Database initialized at {db_path}")

def insert_ioc(ioc, ioc_type, source="Threat Feed", confidence=50):
    conn = sqlite3.connect(DB_PATH) # Variable use karo
    cursor = conn.cursor()
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        cursor.execute('''
            INSERT OR IGNORE INTO ioc_table (ioc, type, source, confidence, first_seen)
            VALUES (?, ?, ?, ?, ?)
        ''', (ioc, ioc_type, source, confidence, current_time))
        conn.commit()
    finally:
        conn.close()

def lookup_ioc(ioc_value):
    conn = sqlite3.connect(DB_PATH) # Variable use karo
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM ioc_table WHERE ioc = ?", (ioc_value,))
        return cursor.fetchone()
    finally:
        conn.close()
