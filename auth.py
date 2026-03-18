"""
auth.py — SQLite-backed API key authentication for code-exec-api.
Inline vendor pattern: no external vendor directory.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import time
from typing import Optional

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware

AUTH_DB_PATH = os.environ.get("AUTH_DB_PATH", "/tmp/code_exec_auth.db")

# ---------------------------------------------------------------------------
# DB bootstrap
# ---------------------------------------------------------------------------

def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(AUTH_DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_auth_store() -> None:
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id          TEXT PRIMARY KEY,
                key_hash    TEXT UNIQUE NOT NULL,
                label       TEXT,
                tier        TEXT DEFAULT 'free',
                calls_used  INTEGER DEFAULT 0,
                calls_limit INTEGER DEFAULT 500,
                created_at  REAL NOT NULL,
                revoked     INTEGER DEFAULT 0
            )
        """)
        c.commit()


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def create_key(label: str = "", tier: str = "free", calls_limit: int = 500) -> dict:
    key = "cex_" + secrets.token_urlsafe(32)
    kid = secrets.token_hex(8)
    limits = {"free": 500, "starter": 10_000, "pro": 100_000}.get(tier, calls_limit)
    with _conn() as c:
        c.execute(
            "INSERT INTO api_keys VALUES (?,?,?,?,0,?,?,0)",
            (kid, _hash(key), label, tier, limits, time.time()),
        )
        c.commit()
    return {"id": kid, "key": key, "tier": tier, "calls_limit": limits}


def get_key_info(key: str) -> Optional[dict]:
    row = _conn().execute(
        "SELECT * FROM api_keys WHERE key_hash=? AND revoked=0", (_hash(key),)
    ).fetchone()
    return dict(row) if row else None


def list_keys() -> list:
    rows = _conn().execute(
        "SELECT id, label, tier, calls_used, calls_limit, created_at, revoked FROM api_keys"
    ).fetchall()
    return [dict(r) for r in rows]


def get_key_by_id(kid: str) -> Optional[dict]:
    row = _conn().execute(
        "SELECT id, label, tier, calls_used, calls_limit, created_at, revoked FROM api_keys WHERE id=?",
        (kid,),
    ).fetchone()
    return dict(row) if row else None


def revoke_key(kid: str) -> bool:
    with _conn() as c:
        c.execute("UPDATE api_keys SET revoked=1 WHERE id=?", (kid,))
        c.commit()
    return True


def increment_usage(key: str) -> None:
    with _conn() as c:
        c.execute(
            "UPDATE api_keys SET calls_used=calls_used+1 WHERE key_hash=?",
            (_hash(key),),
        )
        c.commit()


# ---------------------------------------------------------------------------
# FastAPI middleware
# ---------------------------------------------------------------------------

ADMIN_KEY = os.environ.get("ADMIN_KEY", "dev_admin_key_change_in_production")


class ApiKeyMiddleware(BaseHTTPMiddleware):
    EXEMPT = {"/", "/health", "/docs", "/openapi.json", "/redoc", "/_help"}

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.EXEMPT or request.method == "OPTIONS":
            return await call_next(request)

        raw = (
            request.headers.get("X-API-Key")
            or request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        )

        if not raw:
            raise HTTPException(status_code=401, detail="Missing API key — pass X-API-Key header.")

        # Admin key bypass
        if raw == ADMIN_KEY:
            request.state.api_key = raw
            request.state.tier = "admin"
            return await call_next(request)

        info = get_key_info(raw)
        if not info:
            raise HTTPException(status_code=401, detail="Invalid or revoked API key.")

        if info["calls_used"] >= info["calls_limit"]:
            raise HTTPException(
                status_code=429,
                detail=f"Quota exhausted ({info['calls_limit']} calls). Upgrade your plan.",
            )

        increment_usage(raw)
        request.state.api_key = raw
        request.state.tier = info["tier"]
        return await call_next(request)
