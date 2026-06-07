import sqlite3

conn = sqlite3.connect("database.db")

cursor = conn.cursor()

# =========================================
# USERS TABLE
# =========================================

cursor.execute("""

CREATE TABLE IF NOT EXISTS users (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    fullname TEXT,

    username TEXT UNIQUE,

    contact TEXT,

    password TEXT

)

""")

# =========================================
# HISTORY TABLE
# =========================================

cursor.execute("""

CREATE TABLE IF NOT EXISTS history (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT,

    email TEXT,

    score INTEGER,

    result TEXT,

    attack_type TEXT,

    status TEXT DEFAULT 'Under Review',

    analyst_note TEXT DEFAULT ''

)

""")

conn.commit()

conn.close()

print("Database initialized successfully")