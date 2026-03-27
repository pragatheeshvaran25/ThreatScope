# modules/database.py
# Job: Save scan history to a SQLite database

import sqlite3
import pandas as pd
from datetime import datetime

DB_FILE = 'cyberscan.db'


def init_db():
    """Create database table if it doesn't exist yet."""
    conn = sqlite3.connect(DB_FILE)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time   TEXT,
            targets     TEXT,
            total_hosts INTEGER,
            total_ports INTEGER,
            high_risk   INTEGER,
            max_score   REAL,
            results     TEXT
        )
    ''')
    conn.commit()
    conn.close()


def save_scan(df: pd.DataFrame, targets: list):
    """Save a completed scan to the database."""
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        'INSERT INTO scans VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)',
        (
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ', '.join(targets),
            int(df['ip'].nunique()),
            len(df),
            int(df['severity'].isin(['High', 'Critical']).sum()),
            float(df['risk_score'].max()),
            df.to_json(orient='records'),
        )
    )
    conn.commit()
    conn.close()


def load_history() -> pd.DataFrame:
    """Load all past scans (newest first)."""
    conn = sqlite3.connect(DB_FILE)
    df   = pd.read_sql_query(
        'SELECT id, scan_time, targets, total_hosts, total_ports, high_risk, max_score '
        'FROM scans ORDER BY id DESC',
        conn
    )
    conn.close()
    return df


def load_scan_by_id(scan_id: int) -> pd.DataFrame:
    """Load full results of one specific past scan."""
    conn = sqlite3.connect(DB_FILE)
    row  = conn.execute(
        'SELECT results FROM scans WHERE id = ?', (scan_id,)
    ).fetchone()
    conn.close()
    return pd.read_json(row[0]) if row else pd.DataFrame()


# Create the database when this file is imported
init_db()