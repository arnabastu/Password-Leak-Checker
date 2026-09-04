from sqlite3 import Cursor
import sqlite3
import os
from datetime import datetime

DB_File = 'breach_history.db'
def init_database():
    """Create the database and table if they don't exist"""
    conn = sqlite3.connect(DB_File)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS breach_checks(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    is_breached INTEGER,
    breach_count INTEGER,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    )'''
        
    )
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS passward_checks(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password_hash TEXT NOT NULL,
    is_pwned INTEGER,
    pwned_count INTEGER,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    )''')

    conn.commit()
    conn.close()

def save_email_check(email , is_breached , breach_count):
    """Save an email breach check result to the database"""
    conn = sqlite3.connect(DB_File)
    cursor = conn.cursor()

    cursor.execute('''
    INSERT INTO breach_checks (email , is_breached, breach_count)
    VALUES (?, ?, ?)
    ''', (email,is_breached,breach_count))

    conn.commit()
    conn.close()

def save_password_check(password_hash , is_pwned , pwned_count):
    """Save a password breach check result to the database"""
    conn = sqlite3.connect(DB_File)
    cursor = conn.cursor()

    cursor.execute('''
    INSERT INTO password_checks (password_hash , is_pwned, pwned_count)
    VALUES (?, ?, ?)
    ''', (password_hash,is_pwned,pwned_count))

    conn.commit()
    conn.close()

def get_email_history():
    """Check if an email has been checked before"""
    conn = sqlite3.connect(DB_File)
    cursor = conn.cursor()

    cursor.execute('''
    SELECT is_breached, breach_count , checked_at
    FROM breach_checks
    ORDER BY checked_at DESC LIMIT 20''')

    result = cursor.fetchall()
    conn.close()
    return result

def get_passward_history():
    """Retrieve all password checks from history"""
    conn = sqlite3.connect(DB_File)
    cursor = conn.cursor()
    cursor.execute('''
    SELECT is_pwned, pwned_count , checked_at
    FROM password_checks
    ORDER BY checked_at DESC LIMIT 20''')

    result = cursor.fetchall()
    conn.close()
    return result

def clear_history():
    """Clear the breach history database"""
    conn = sqlite3.connect(DB_File)
    cursor = conn.cursor()

    cursor.execute('DELETE FROM breach_checks')
    cursor.execute('DELETE FROM password_checks')

    conn.commit()
    conn.close()