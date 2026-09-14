from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "cyberlens.db"

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgres://"):]
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgresql://"):]

USE_POSTGRES = bool(DATABASE_URL)

if USE_POSTGRES:
    ENGINE = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        future=True,
    )
else:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ENGINE = create_engine(
        f"sqlite:///{DB_PATH.as_posix()}",
        future=True,
        connect_args={"check_same_thread": False},
    )


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_username(username: str) -> str:
    return str(username or "").strip().lower()


def _to_dict(row: Any) -> dict[str, Any] | None:
    if row is None:
        return None
    if isinstance(row, dict):
        return dict(row)
    if hasattr(row, "_mapping"):
        return dict(row._mapping)
    return dict(row)


def _int_value(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def _json_loads(value: Any, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def _sqlite_columns(connection, table_name: str) -> set[str]:
    rows = connection.execute(text(f"PRAGMA table_info({table_name});")).fetchall()
    return {row._mapping["name"] for row in rows}


def init_database() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with ENGINE.begin() as connection:
        if USE_POSTGRES:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    is_active INTEGER NOT NULL DEFAULT 1
                );
            """))
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS scans (
                    id SERIAL PRIMARY KEY,
                    scan_type TEXT NOT NULL,
                    target_name TEXT NOT NULL,
                    security_score INTEGER NOT NULL,
                    highest_severity TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL
                );
            """))
            connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin INTEGER NOT NULL DEFAULT 0;"))
            connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active INTEGER NOT NULL DEFAULT 1;"))
            connection.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;"))
        else:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    is_active INTEGER NOT NULL DEFAULT 1
                );
            """))
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    target_name TEXT NOT NULL,
                    security_score INTEGER NOT NULL,
                    highest_severity TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    user_id INTEGER
                );
            """))
            user_columns = _sqlite_columns(connection, "users")
            if "is_admin" not in user_columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;"))
            if "is_active" not in user_columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;"))
            scan_columns = _sqlite_columns(connection, "scans")
            if "user_id" not in scan_columns:
                connection.execute(text("ALTER TABLE scans ADD COLUMN user_id INTEGER;"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type);"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);"))


def create_user(username: str, password_hash: str, is_admin: int = 0, is_active: int = 1) -> int:
    username = clean_username(username)
    if not username:
        raise ValueError("Username is required.")
    values = {
        "username": username,
        "password_hash": password_hash,
        "created_at": now_utc_iso(),
        "is_admin": int(is_admin),
        "is_active": int(is_active),
    }
    with ENGINE.begin() as connection:
        if USE_POSTGRES:
            row = connection.execute(text("""
                INSERT INTO users (username, password_hash, created_at, is_admin, is_active)
                VALUES (:username, :password_hash, :created_at, :is_admin, :is_active)
                RETURNING id;
            """), values).fetchone()
            return int(row._mapping["id"])
        result = connection.execute(text("""
            INSERT INTO users (username, password_hash, created_at, is_admin, is_active)
            VALUES (:username, :password_hash, :created_at, :is_admin, :is_active);
        """), values)
        return int(result.lastrowid)


def _normalize_user(row: Any, include_password: bool = False) -> dict[str, Any] | None:
    data = _to_dict(row)
    if not data:
        return None
    user = {
        "id": _int_value(data.get("id")),
        "username": data.get("username"),
        "created_at": data.get("created_at"),
        "is_admin": _int_value(data.get("is_admin"), 0),
        "is_active": _int_value(data.get("is_active"), 1),
    }
    if include_password:
        user["password_hash"] = data.get("password_hash")
    return user


def get_user_by_username(username: str) -> dict[str, Any] | None:
    username = clean_username(username)
    with ENGINE.connect() as connection:
        row = connection.execute(text("""
            SELECT id, username, password_hash, created_at, is_admin, is_active
            FROM users
            WHERE username = :username
            LIMIT 1;
        """), {"username": username}).fetchone()
    return _normalize_user(row, include_password=True)


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    with ENGINE.connect() as connection:
        row = connection.execute(text("""
            SELECT id, username, created_at, is_admin, is_active
            FROM users
            WHERE id = :user_id
            LIMIT 1;
        """), {"user_id": int(user_id)}).fetchone()
    return _normalize_user(row)


def list_users_with_stats() -> list[dict[str, Any]]:
    with ENGINE.connect() as connection:
        rows = connection.execute(text("""
            SELECT u.id, u.username, u.created_at, u.is_admin, u.is_active,
                   COUNT(s.id) AS scans_count
            FROM users u
            LEFT JOIN scans s ON s.user_id = u.id
            GROUP BY u.id, u.username, u.created_at, u.is_admin, u.is_active
            ORDER BY u.id ASC;
        """)).fetchall()
    users = []
    for row in rows:
        data = _to_dict(row) or {}
        users.append({
            "id": _int_value(data.get("id")),
            "username": data.get("username"),
            "created_at": data.get("created_at"),
            "is_admin": _int_value(data.get("is_admin"), 0),
            "is_active": _int_value(data.get("is_active"), 1),
            "scans_count": _int_value(data.get("scans_count"), 0),
        })
    return users


def set_user_active(user_id: int, is_active: bool) -> dict[str, Any] | None:
    with ENGINE.begin() as connection:
        connection.execute(text("""
            UPDATE users
            SET is_active = :is_active
            WHERE id = :user_id;
        """), {"is_active": int(bool(is_active)), "user_id": int(user_id)})
    return get_user_by_id(user_id)


def save_scan_result(
    scan_type: str,
    target_name: str,
    security_score: int,
    highest_severity: str,
    findings: list[dict[str, Any]] | None,
    metadata: dict[str, Any] | None = None,
    user_id: int | None = None,
) -> int:
    findings = findings or []
    metadata = metadata or {}
    values = {
        "scan_type": scan_type,
        "target_name": target_name,
        "security_score": int(security_score),
        "highest_severity": highest_severity,
        "findings_json": json.dumps(findings, ensure_ascii=False),
        "metadata_json": json.dumps(metadata, ensure_ascii=False),
        "created_at": now_utc_iso(),
        "user_id": user_id,
    }
    with ENGINE.begin() as connection:
        if USE_POSTGRES:
            row = connection.execute(text("""
                INSERT INTO scans (
                    scan_type, target_name, security_score, highest_severity,
                    findings_json, metadata_json, created_at, user_id
                )
                VALUES (
                    :scan_type, :target_name, :security_score, :highest_severity,
                    :findings_json, :metadata_json, :created_at, :user_id
                )
                RETURNING id;
            """), values).fetchone()
            return int(row._mapping["id"])
        result = connection.execute(text("""
            INSERT INTO scans (
                scan_type, target_name, security_score, highest_severity,
                findings_json, metadata_json, created_at, user_id
            )
            VALUES (
                :scan_type, :target_name, :security_score, :highest_severity,
                :findings_json, :metadata_json, :created_at, :user_id
            );
        """), values)
        return int(result.lastrowid)


def scan_row_to_dict(row: Any) -> dict[str, Any]:
    data = _to_dict(row) or {}
    return {
        "id": _int_value(data.get("id")),
        "scan_type": data.get("scan_type"),
        "target_name": data.get("target_name"),
        "security_score": _int_value(data.get("security_score")),
        "highest_severity": data.get("highest_severity"),
        "findings": _json_loads(data.get("findings_json"), []),
        "metadata": _json_loads(data.get("metadata_json"), {}),
        "created_at": data.get("created_at"),
        "user_id": data.get("user_id"),
    }


def get_scan_history(limit: int = 20, user_id: int | None = None) -> list[dict[str, Any]]:
    params = {"limit": int(limit)}
    where = ""
    if user_id is not None:
        where = "WHERE user_id = :user_id"
        params["user_id"] = int(user_id)
    query = text(f"""
        SELECT id, scan_type, target_name, security_score, highest_severity,
               findings_json, metadata_json, created_at, user_id
        FROM scans
        {where}
        ORDER BY id DESC
        LIMIT :limit;
    """)
    with ENGINE.connect() as connection:
        rows = connection.execute(query, params).fetchall()
    return [scan_row_to_dict(row) for row in rows]


def get_scan_by_id(scan_id: int) -> dict[str, Any] | None:
    with ENGINE.connect() as connection:
        row = connection.execute(text("""
            SELECT id, scan_type, target_name, security_score, highest_severity,
                   findings_json, metadata_json, created_at, user_id
            FROM scans
            WHERE id = :scan_id
            LIMIT 1;
        """), {"scan_id": int(scan_id)}).fetchone()
    if row is None:
        return None
    return scan_row_to_dict(row)


def get_dashboard_summary(user_id: int | None = None) -> dict[str, Any]:
    scans = get_scan_history(limit=1000, user_id=user_id)
    total_scans = len(scans)
    total_findings = sum(len(scan.get("findings") or []) for scan in scans)
    scores = [int(scan.get("security_score") or 0) for scan in scans]
    average_score = int(sum(scores) / len(scores)) if scores else 0
    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "average_score": average_score,
        "latest_scan": scans[0] if scans else None,
        "recent_scans": scans[:5],
    }


init_database()


def get_dashboard_statistics(user_id=None):
    scans = get_scan_history(
        limit=1000,
        user_id=user_id,
    )

    total_scans = len(scans)

    total_findings = 0
    scores = []
    scan_type_counts = {}
    highest_severity_counts = {}

    for scan in scans:
        findings = scan.get("findings") or []
        total_findings += len(findings)

        score = int(scan.get("security_score") or 0)
        scores.append(score)

        scan_type = scan.get("scan_type") or "unknown"
        scan_type_counts[scan_type] = scan_type_counts.get(scan_type, 0) + 1

        severity = scan.get("highest_severity") or "none"
        highest_severity_counts[severity] = highest_severity_counts.get(severity, 0) + 1

    average_score = int(sum(scores) / len(scores)) if scores else 0

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "average_score": average_score,
        "lowest_score": min(scores) if scores else 0,
        "highest_score": max(scores) if scores else 0,
        "scan_type_counts": scan_type_counts,
        "highest_severity_counts": highest_severity_counts,
        "severity_counts": highest_severity_counts,
        "latest_scan": scans[0] if scans else None,
        "recent_scans": scans[:5],
    }
