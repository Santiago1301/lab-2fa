"""
Repositorio de usuarios y configuración 2FA sobre SQLite.

La guía permite SQLite o un dict en memoria. Toda la persistencia pasa por
este módulo, así que cambiar a Supabase solo implica reescribir este archivo.
"""
import json
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.getenv("LAB2FA_DB", Path(__file__).resolve().parent.parent / "lab2fa.db"))


@dataclass
class User:
    id: int
    username: str
    password_hash: str


@dataclass
class MfaConfig:
    user_id: int
    secret: str
    status: str
    backup_code_hashes: list[str]
    created_at: str
    activated_at: str | None


@contextmanager
def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mfa_configs (
                user_id            INTEGER PRIMARY KEY REFERENCES users(id),
                secret             TEXT NOT NULL,
                status             TEXT NOT NULL,
                backup_code_hashes TEXT NOT NULL,
                created_at         TEXT NOT NULL,
                activated_at       TEXT
            );
            """
        )


# --- Usuarios ---------------------------------------------------------------

def create_user(username: str, password_hash: str) -> User:
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, _now()),
        )
        return User(cur.lastrowid, username, password_hash)


def get_user_by_username(username: str) -> User | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    return User(**dict(row)) if row else None


def get_user(user_id: int) -> User | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    return User(**dict(row)) if row else None


# --- Configuración 2FA ------------------------------------------------------

def get_mfa_config(user_id: int) -> MfaConfig | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM mfa_configs WHERE user_id = ?", (user_id,)).fetchone()
    if not row:
        return None
    data = dict(row)
    data["backup_code_hashes"] = json.loads(data["backup_code_hashes"])
    return MfaConfig(**data)


def save_pending_config(user_id: int, secret: str, status: str, backup_code_hashes: list[str]) -> None:
    """Crea o reemplaza la configuración (solo se usa mientras no esté ACTIVE)."""
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO mfa_configs (user_id, secret, status, backup_code_hashes, created_at, activated_at)
            VALUES (?, ?, ?, ?, ?, NULL)
            ON CONFLICT(user_id) DO UPDATE SET
                secret = excluded.secret,
                status = excluded.status,
                backup_code_hashes = excluded.backup_code_hashes,
                created_at = excluded.created_at,
                activated_at = NULL
            """,
            (user_id, secret, status, json.dumps(backup_code_hashes), _now()),
        )


def update_status(user_id: int, status: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE mfa_configs SET status = ?, activated_at = ? WHERE user_id = ?",
            (status, _now(), user_id),
        )


def consume_backup_code(user_id: int, code_hash: str) -> bool:
    """Elimina el código de respaldo. Devuelve False si ya no existía (un solo uso)."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT backup_code_hashes FROM mfa_configs WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not row:
            return False
        hashes = json.loads(row["backup_code_hashes"])
        if code_hash not in hashes:
            return False
        hashes.remove(code_hash)
        conn.execute(
            "UPDATE mfa_configs SET backup_code_hashes = ? WHERE user_id = ?",
            (json.dumps(hashes), user_id),
        )
        return True
