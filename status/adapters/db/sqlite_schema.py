"""Схема базы знаний SQLite: создание и обновление таблиц."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 2

CREATE_RULES_TABLE = """
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL DEFAULT '',
    match_type TEXT NOT NULL DEFAULT 'contains',
    vendor_pattern TEXT NOT NULL DEFAULT '',
    vendor_match_type TEXT NOT NULL DEFAULT 'contains',
    status TEXT NOT NULL CHECK(status IN ('ДА', 'НЕТ', 'ЛИНУКС', 'УСЛОВНО')),
    ppts_id TEXT,
    vector_threshold REAL,
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_matched_at TIMESTAMP,
    match_count INTEGER DEFAULT 0
);
"""

CREATE_SCRIPTS_CONFIG_TABLE = """
CREATE TABLE IF NOT EXISTS scripts_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    script_path TEXT NOT NULL,
    condition TEXT NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1
);
"""

CREATE_PROCESSING_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS processing_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER,
    vulnerability_cve TEXT,
    matched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE SET NULL
);
"""

CREATE_SCHEMA_VERSION_TABLE = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);
"""

ALL_TABLES = [
    CREATE_SCHEMA_VERSION_TABLE,
    CREATE_RULES_TABLE,
    CREATE_SCRIPTS_CONFIG_TABLE,
    CREATE_PROCESSING_LOG_TABLE,
]

_MIGRATIONS = {
    2: [
        "ALTER TABLE rules ADD COLUMN vendor_pattern TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE rules ADD COLUMN vendor_match_type TEXT NOT NULL DEFAULT 'contains'",
    ],
}


def _run_migrations(conn: sqlite3.Connection, current_version: int) -> None:
    cursor = conn.cursor()
    for ver in range(current_version + 1, SCHEMA_VERSION + 1):
        if ver in _MIGRATIONS:
            logger.info("Running migration to schema v%d", ver)
            for sql in _MIGRATIONS[ver]:
                try:
                    cursor.execute(sql)
                except sqlite3.OperationalError as exc:
                    if "duplicate column" in str(exc).lower():
                        logger.debug("Column already exists, skipping: %s", exc)
                    else:
                        raise
    cursor.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))
    conn.commit()


def get_connection(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str | Path) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(db_path)
    cursor = conn.cursor()

    for ddl in ALL_TABLES:
        cursor.execute(ddl)

    row = cursor.execute("SELECT COUNT(*) FROM schema_version").fetchone()
    if row[0] == 0:
        cursor.execute(
            "INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,)
        )
        conn.commit()
    else:
        ver_row = cursor.execute("SELECT version FROM schema_version").fetchone()
        current = ver_row[0] if ver_row else 1
        if current < SCHEMA_VERSION:
            _run_migrations(conn, current)

    logger.info("Database initialized at %s (schema v%d)", db_path, SCHEMA_VERSION)
    return conn
