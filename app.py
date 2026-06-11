from __future__ import annotations

import asyncio
import base64
import binascii
import hmac
import hashlib
import io
import json
import os
import re
import secrets
import sqlite3
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from xml.sax.saxutils import escape as xml_escape
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, StreamingResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from py_vapid import Vapid01, sign as vapid_sign, b64urlencode as vapid_b64urlencode
from pywebpush import webpush, WebPushException
import qrcode
from qrcode.image.svg import SvgPathImage
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from cryptography.hazmat.primitives import serialization

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "poker.db"

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", secrets.token_hex(32)),
    same_site="strict",
    https_only=os.getenv("SESSION_SECURE", "true").lower() == "true",
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

TRUSTED_DEVICE_DAYS = 30
TRUSTED_DEVICE_COOKIE = "poker_trusted_device"
INVITEE_TOKEN_COOKIE = "poker_invitee_token"
CO_ORG_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,31}$")
CO_ORG_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
TOTP_ISSUER = "Poker Invite Manager"
CSRF_SIGNED_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60


def get_request_csp_nonce(request: Request) -> str:
    existing = getattr(getattr(request, "state", None), "csp_nonce", None)
    if existing:
        return existing
    nonce = secrets.token_urlsafe(16)
    try:
        request.state.csp_nonce = nonce
    except Exception:
        pass
    return nonce


def public_base_url(request: Request) -> str:
    configured = (os.getenv("APP_BASE_URL") or "").strip()
    if configured:
        return configured.rstrip("/")
    scheme = (request.url.scheme or "https").strip().lower()
    host = (request.url.netloc or "").strip()
    if not host:
        host = "localhost"
    return f"{scheme}://{host}"


def configured_public_base_url() -> str:
    configured = (os.getenv("APP_BASE_URL") or "").strip()
    if configured:
        return configured.rstrip("/")
    return "http://127.0.0.1:8000"


def web_push_enabled() -> bool:
    return bool(
        (os.getenv("WEB_PUSH_VAPID_PUBLIC_KEY") or "").strip()
        and (
            (os.getenv("WEB_PUSH_VAPID_PRIVATE_KEY") or "").strip()
            or (os.getenv("WEB_PUSH_VAPID_PRIVATE_KEY_PATH") or "").strip()
        )
        and (os.getenv("WEB_PUSH_SUBJECT") or "").strip()
    )

# Python 3.8 environment: implement America/Thunder_Bay (EST/EDT) without zoneinfo.
def _thunder_bay_dst_bounds(year: int):
    # DST starts 2nd Sunday in March at 2:00, ends 1st Sunday in November at 2:00.
    march = datetime(year, 3, 1)
    march_weekday = march.weekday()  # Mon=0..Sun=6
    first_sunday_march = march + timedelta(days=(6 - march_weekday) % 7)
    second_sunday_march = first_sunday_march + timedelta(days=7)
    dst_start = datetime(year, 3, second_sunday_march.day, 2, 0, 0)

    november = datetime(year, 11, 1)
    nov_weekday = november.weekday()
    first_sunday_nov = november + timedelta(days=(6 - nov_weekday) % 7)
    dst_end = datetime(year, 11, first_sunday_nov.day, 2, 0, 0)
    return dst_start, dst_end


def _is_thunder_bay_dst(local_dt: datetime) -> bool:
    dst_start, dst_end = _thunder_bay_dst_bounds(local_dt.year)
    return dst_start <= local_dt < dst_end


def thunder_bay_now() -> datetime:
    now_utc = datetime.utcnow()
    local_guess = now_utc + timedelta(hours=-5)
    if _is_thunder_bay_dst(local_guess):
        local = now_utc + timedelta(hours=-4)
        return local.replace(tzinfo=timezone(timedelta(hours=-4)))
    return local_guess.replace(tzinfo=timezone(timedelta(hours=-5)))


def thunder_bay_localize(local_dt: datetime) -> datetime:
    offset_hours = -4 if _is_thunder_bay_dst(local_dt) else -5
    return local_dt.replace(tzinfo=timezone(timedelta(hours=offset_hours)))


def thunder_bay_from_utc(dt_utc: datetime) -> datetime:
    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
    else:
        dt_utc = dt_utc.astimezone(timezone.utc)
    standard_local = (dt_utc + timedelta(hours=-5)).replace(tzinfo=None)
    if _is_thunder_bay_dst(standard_local):
        local_naive = (dt_utc + timedelta(hours=-4)).replace(tzinfo=None)
        return local_naive.replace(tzinfo=timezone(timedelta(hours=-4)))
    return standard_local.replace(tzinfo=timezone(timedelta(hours=-5)))


def format_ts(value: str) -> str:
    try:
        raw = str(value or "").strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(raw)
        return thunder_bay_from_utc(dt).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return value


def format_game_time(value: str) -> str:
    if not value:
        return ""
    raw = str(value).strip()
    for fmt in ("%H:%M", "%H:%M:%S", "%I:%M %p", "%I:%M%p"):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.strftime("%I:%M %p").lstrip("0")
        except Exception:
            pass
    return raw


def format_phone(value: Optional[str]) -> str:
    if not value:
        return "-"
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10:
        return value
    return f"+1 ({digits[0:3]}) {digits[3:6]}-{digits[6:10]}"


templates.env.filters["fmt_ts"] = format_ts
templates.env.filters["fmt_game_time"] = format_game_time
templates.env.filters["fmt_phone"] = format_phone
templates.env.globals["csp_nonce"] = get_request_csp_nonce
templates.env.globals["public_base_url"] = public_base_url
templates.env.globals["web_push_enabled"] = web_push_enabled


def static_asset(path: str) -> str:
    raw = str(path or "").strip()
    normalized = raw[1:] if raw.startswith("/") else raw
    target = BASE_DIR / normalized
    try:
        version = int(target.stat().st_mtime)
        return f"/{normalized}?v={version}"
    except Exception:
        return f"/{normalized}"


templates.env.globals["static_asset"] = static_asset

def _csrf_secret() -> str:
    return (os.getenv("SESSION_SECRET") or "").strip() or "dev-csrf-secret"


def create_signed_csrf_token() -> str:
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(12)
    payload = f"{ts}.{nonce}"
    sig = hmac.new(_csrf_secret().encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_signed_csrf_token(token: Optional[str]) -> bool:
    value = (token or "").strip()
    parts = value.split(".")
    if len(parts) != 3:
        return False
    ts, nonce, provided_sig = parts
    if not ts or not nonce or not provided_sig:
        return False
    if not ts.isdigit():
        return False
    try:
        issued_at = int(ts)
    except Exception:
        return False
    if issued_at + CSRF_SIGNED_TOKEN_TTL_SECONDS < int(time.time()):
        return False
    payload = f"{ts}.{nonce}"
    expected_sig = hmac.new(_csrf_secret().encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided_sig, expected_sig)


def get_csrf_token(request: Request) -> str:
    session_token = request.session.get("csrf_token")
    if not session_token:
        request.session["csrf_token"] = secrets.token_urlsafe(32)
    return create_signed_csrf_token()

templates.env.globals["csrf_token"] = get_csrf_token


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        nonce = get_request_csp_nonce(request)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        )
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.limits = {
            "/login": (10, 60),
            "/register": (5, 60),
            "/g/": (30, 60),  # RSVP/standby
        }

    async def dispatch(self, request: Request, call_next):
        if request.method == "POST":
            path = request.url.path
            key = None
            for prefix in self.limits:
                if path == prefix or path.startswith(prefix):
                    key = prefix
                    break
            if key:
                limit, window = self.limits[key]
                ip = rate_limit_client_ip(request)
                now = _utc_now_iso()
                window_start = _utc_minus_seconds_iso(window)
                conn = get_db()
                cur = conn.cursor()
                try:
                    cur.execute(
                        """
                        DELETE FROM rate_limit_hits
                        WHERE endpoint = ?
                          AND ip = ?
                          AND created_at < ?
                        """,
                        (key, ip, window_start),
                    )
                    cur.execute(
                        """
                        SELECT COUNT(*) AS c
                        FROM rate_limit_hits
                        WHERE endpoint = ?
                          AND ip = ?
                          AND created_at >= ?
                        """,
                        (key, ip, window_start),
                    )
                    if int(cur.fetchone()["c"] or 0) >= limit:
                        conn.commit()
                        return PlainTextResponse("Too many requests", status_code=429)
                    cur.execute(
                        """
                        INSERT INTO rate_limit_hits (endpoint, ip, created_at)
                        VALUES (?, ?, ?)
                        """,
                        (key, ip, now),
                    )
                    conn.commit()
                finally:
                    conn.close()
        return await call_next(request)


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)


# ------------------------
# Database helpers
# ------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _rsvp_status_rank(value: Optional[str]) -> int:
    status = (value or "").upper().strip()
    if status == "HOST":
        return 4
    if status == "IN":
        return 3
    if status == "LATE":
        return 2
    if status == "OUT":
        return 1
    return 0


def dedupe_rsvps_by_phone(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT game_id, phone, COUNT(*) AS c
        FROM rsvps
        WHERE phone IS NOT NULL
          AND TRIM(phone) != ''
        GROUP BY game_id, phone
        HAVING COUNT(*) > 1
        """
    )
    groups = cur.fetchall()
    for grp in groups:
        cur.execute(
            """
            SELECT id, name, status, late_eta, seat_number, created_at, rsvp_token
            FROM rsvps
            WHERE game_id = ? AND phone = ?
            ORDER BY id DESC
            """,
            (int(grp["game_id"]), grp["phone"]),
        )
        rows = cur.fetchall()
        if len(rows) < 2:
            continue
        keep = rows[0]
        keep_id = int(keep["id"])
        merged_status = (keep["status"] or "").upper().strip()
        if merged_status not in {"HOST", "IN", "LATE", "OUT"}:
            merged_status = "OUT"
        merged_late_eta = (keep["late_eta"] or "").strip() or None
        if merged_status == "LATE" and not merged_late_eta:
            for row in rows:
                if str(row["status"] or "").upper().strip() == "LATE" and (row["late_eta"] or "").strip():
                    merged_late_eta = (row["late_eta"] or "").strip()
                    break
        merged_seat = keep["seat_number"]
        if merged_seat is None and merged_status in {"HOST", "IN", "LATE"}:
            for row in rows:
                if str(row["status"] or "").upper().strip() == merged_status and row["seat_number"] is not None:
                    merged_seat = row["seat_number"]
                    break
        if merged_seat is None:
            ranked = sorted(rows, key=lambda row: (_rsvp_status_rank(row["status"]), int(row["id"])), reverse=True)
            for row in ranked:
                if row["seat_number"] is not None and _rsvp_status_rank(row["status"]) >= 2:
                    merged_seat = row["seat_number"]
                    break
        merged_token = (keep["rsvp_token"] or "").strip() or None
        if not merged_token:
            for row in rows:
                candidate = (row["rsvp_token"] or "").strip()
                if candidate:
                    merged_token = candidate
                    break
        cur.execute(
            """
            UPDATE rsvps
            SET status = ?, late_eta = ?, seat_number = ?, rsvp_token = ?
            WHERE id = ?
            """,
            (merged_status, merged_late_eta, merged_seat, merged_token, keep_id),
        )
        remove_ids = [int(row["id"]) for row in rows[1:]]
        if remove_ids:
            cur.execute(
                "DELETE FROM rsvps WHERE id IN (%s)" % ",".join("?" * len(remove_ids)),
                remove_ids,
            )


def dedupe_standby_by_phone(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT game_id, phone, COUNT(*) AS c
        FROM standby
        WHERE phone IS NOT NULL
          AND TRIM(phone) != ''
        GROUP BY game_id, phone
        HAVING COUNT(*) > 1
        """
    )
    groups = cur.fetchall()
    for grp in groups:
        cur.execute(
            """
            SELECT id
            FROM standby
            WHERE game_id = ? AND phone = ?
            ORDER BY datetime(created_at) ASC, id ASC
            """,
            (int(grp["game_id"]), grp["phone"]),
        )
        ids = [int(row["id"]) for row in cur.fetchall()]
        if len(ids) < 2:
            continue
        cur.execute(
            "DELETE FROM standby WHERE id IN (%s)" % ",".join("?" * len(ids[1:])),
            ids[1:],
        )


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    # Ensure optional admin fields exist
    cur.execute("PRAGMA table_info(users)")
    existing_cols = {row["name"] for row in cur.fetchall()}
    if "username" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN username TEXT")
    if "is_admin" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
    if "is_disabled" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN is_disabled INTEGER DEFAULT 0")
    if "phone" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN phone TEXT")
    if "phone_verified_at" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN phone_verified_at TEXT")
    if "mfa_enabled" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0")
    if "totp_secret" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
    if "totp_enabled" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0")
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organizer_id INTEGER NOT NULL,
            code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            location TEXT NOT NULL,
            game_date TEXT NOT NULL,
            game_time TEXT NOT NULL,
            total_players INTEGER NOT NULL,
            multiple_tables INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (organizer_id) REFERENCES users(id)
        )
        """
    )
    cur.execute("PRAGMA table_info(games)")
    game_cols = {row["name"] for row in cur.fetchall()}
    if "is_cancelled" not in game_cols:
        cur.execute("ALTER TABLE games ADD COLUMN is_cancelled INTEGER DEFAULT 0")
    if "cancelled_at" not in game_cols:
        cur.execute("ALTER TABLE games ADD COLUMN cancelled_at TEXT")
    if "host_code" not in game_cols:
        cur.execute("ALTER TABLE games ADD COLUMN host_code TEXT")
    if "multiple_tables" not in game_cols:
        cur.execute("ALTER TABLE games ADD COLUMN multiple_tables INTEGER DEFAULT 0")
    if "manual_seat_assignment" not in game_cols:
        cur.execute("ALTER TABLE games ADD COLUMN manual_seat_assignment INTEGER DEFAULT 0")
    if "game_type" not in game_cols:
        cur.execute("ALTER TABLE games ADD COLUMN game_type TEXT")
    cur.execute("UPDATE games SET game_type = ? WHERE game_type IS NULL OR TRIM(game_type) = ''", (GAME_TYPE_OPTIONS["texas_holdem_cash"],))
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_games_host_code ON games(host_code)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS game_co_organizers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            invited_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (game_id) REFERENCES games(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (invited_by) REFERENCES users(id)
        )
        """
    )
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_game_co_org_unique ON game_co_organizers(game_id, user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_game_co_org_user ON game_co_organizers(user_id)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS rsvps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            phone TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            late_eta TEXT,
            FOREIGN KEY (game_id) REFERENCES games(id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS standby (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            phone TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (game_id) REFERENCES games(id)
        )
        """
    )
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_rsvps_game_name ON rsvps(game_id, lower(name))")
    cur.execute("PRAGMA table_info(rsvps)")
    rsvp_cols = {row["name"] for row in cur.fetchall()}
    if "invitee_id" not in rsvp_cols:
        cur.execute("ALTER TABLE rsvps ADD COLUMN invitee_id INTEGER")
    if "seat_number" not in rsvp_cols:
        cur.execute("ALTER TABLE rsvps ADD COLUMN seat_number INTEGER")
    if "rsvp_token" not in rsvp_cols:
        cur.execute("ALTER TABLE rsvps ADD COLUMN rsvp_token TEXT")
    dedupe_rsvps_by_phone(conn)
    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_rsvps_game_seat ON rsvps(game_id, seat_number) WHERE seat_number IS NOT NULL"
    )
    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_rsvps_game_token ON rsvps(game_id, rsvp_token) WHERE rsvp_token IS NOT NULL"
    )
    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_rsvps_game_phone_unique ON rsvps(game_id, phone) WHERE phone IS NOT NULL AND TRIM(phone) != ''"
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_rsvps_invitee_id ON rsvps(invitee_id)")
    cur.execute("PRAGMA table_info(standby)")
    standby_cols = {row["name"] for row in cur.fetchall()}
    if "invitee_id" not in standby_cols:
        cur.execute("ALTER TABLE standby ADD COLUMN invitee_id INTEGER")
    dedupe_standby_by_phone(conn)
    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_standby_game_phone_unique ON standby(game_id, phone) WHERE phone IS NOT NULL AND TRIM(phone) != ''"
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_standby_invitee_id ON standby(invitee_id)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_mfa_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_user_mfa_codes_user_created_at ON user_mfa_codes(user_id, created_at)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_trusted_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            ua_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen_at TEXT,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_user_trusted_devices_user ON user_trusted_devices(user_id)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS organizer_invitees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organizer_id INTEGER NOT NULL,
            phone TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            FOREIGN KEY (organizer_id) REFERENCES users(id)
        )
        """
    )
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_organizer_invitees_org_phone ON organizer_invitees(organizer_id, phone)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_organizer_invitees_phone ON organizer_invitees(phone)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS organizer_invitee_lists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organizer_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (organizer_id) REFERENCES users(id)
        )
        """
    )
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_invitee_lists_org_name ON organizer_invitee_lists(organizer_id, name)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS organizer_invitee_list_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            list_id INTEGER NOT NULL,
            phone TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (list_id) REFERENCES organizer_invitee_lists(id)
        )
        """
    )
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_invitee_list_members_list_phone ON organizer_invitee_list_members(list_id, phone)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS invitee_browser_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_invitee_browser_tokens_phone ON invitee_browser_tokens(phone)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS rate_limit_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint TEXT NOT NULL,
            ip TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_rate_limit_hits_endpoint_ip_created ON rate_limit_hits(endpoint, ip, created_at)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS web_push_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            phone TEXT,
            invitee_token_hash TEXT,
            endpoint TEXT NOT NULL UNIQUE,
            p256dh TEXT NOT NULL,
            auth TEXT NOT NULL,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_success_at TEXT,
            last_error_at TEXT,
            last_error_detail TEXT,
            disabled_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_web_push_subscriptions_user ON web_push_subscriptions(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_web_push_subscriptions_phone ON web_push_subscriptions(phone)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_web_push_subscriptions_token ON web_push_subscriptions(invitee_token_hash)")
    cur.execute("SELECT id FROM games WHERE host_code IS NULL OR host_code = ''")
    for row in cur.fetchall():
        cur.execute("UPDATE games SET host_code = ? WHERE id = ?", (generate_host_code(conn), row["id"]))
    conn.commit()
    backfill_game_invitee_links(conn)
    backfill_legacy_rsvp_identity(conn)
    backfill_seats(conn)
    conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ------------------------
# Auth helpers
# ------------------------

def current_user_id(request: Request) -> Optional[int]:
    return request.session.get("user_id")

def current_user_is_admin(request: Request) -> bool:
    return bool(request.session.get("is_admin"))

def require_login(request: Request) -> Optional[int]:
    user_id = current_user_id(request)
    return user_id


def require_admin(request: Request) -> bool:
    return current_user_is_admin(request)


def game_is_owner(game_row, user_id: Optional[int]) -> bool:
    return bool(game_row and user_id and int(game_row["organizer_id"]) == int(user_id))


def user_is_game_co_organizer(conn: sqlite3.Connection, game_id: int, user_id: Optional[int]) -> bool:
    if not user_id:
        return False
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM game_co_organizers WHERE game_id = ? AND user_id = ?", (game_id, int(user_id)))
    return cur.fetchone() is not None


def get_game_for_manager(conn: sqlite3.Connection, game_id: int, user_id: Optional[int]):
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE id = ?", (game_id,))
    game = cur.fetchone()
    if not game:
        return None, False
    is_owner = game_is_owner(game, user_id)
    if is_owner or user_is_game_co_organizer(conn, game_id, user_id):
        return game, is_owner
    return None, False


# ------------------------
# Utility
# ------------------------

def _generate_unique_game_value(conn: sqlite3.Connection, column: str, length: int) -> str:
    if column not in {"code", "host_code"}:
        raise ValueError("Invalid games column for code generation")
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    while True:
        code = "".join(secrets.choice(alphabet) for _ in range(length))
        cur = conn.cursor()
        cur.execute(f"SELECT id FROM games WHERE {column} = ?", (code,))
        exists = cur.fetchone()
        if not exists:
            return code


def generate_code(length: int = 8, conn: Optional[sqlite3.Connection] = None) -> str:
    own_conn = conn is None
    if conn is None:
        conn = get_db()
    try:
        return _generate_unique_game_value(conn, "code", length)
    finally:
        if own_conn:
            conn.close()


def generate_host_code(conn: Optional[sqlite3.Connection] = None, length: int = 16) -> str:
    own_conn = conn is None
    if conn is None:
        conn = get_db()
    try:
        return _generate_unique_game_value(conn, "host_code", length)
    finally:
        if own_conn:
            conn.close()


def count_in(conn: sqlite3.Connection, game_id: int) -> int:
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM rsvps WHERE game_id = ? AND status IN ('IN', 'LATE', 'HOST')", (game_id,))
    row = cur.fetchone()
    return int(row["c"]) if row else 0


def game_uses_multiple_tables(game_row) -> bool:
    return bool(game_row and int(game_row["multiple_tables"] or 0) == 1)


def table_sizes(total_players: int, multiple_tables: bool = False) -> list:
    if total_players <= 0:
        return []
    if not multiple_tables:
        return [total_players]
    if total_players <= 9:
        return [total_players]
    table_count = (total_players + 8) // 9
    base = total_players // table_count
    remainder = total_players % table_count
    return [base + 1 if idx < remainder else base for idx in range(table_count)]


def table_labels(count: int) -> list:
    labels = []
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for idx in range(count):
        n = idx
        label = ""
        while True:
            label = alphabet[n % 26] + label
            n = n // 26 - 1
            if n < 0:
                break
        labels.append(label)
    return labels


def seat_assignment(seat_number: Optional[int], total_players: int, multiple_tables: bool = False) -> tuple[Optional[str], Optional[int]]:
    if not seat_number or total_players <= 0:
        return None, None
    sizes = table_sizes(total_players, multiple_tables)
    labels = table_labels(len(sizes))
    idx = seat_number - 1
    for label, size in zip(labels, sizes):
        if idx < size:
            return label, idx + 1
        idx -= size
    return None, None


def seat_display(seat_number: Optional[int], total_players: int, multiple_tables: bool = False) -> Optional[str]:
    label, seat_in_table = seat_assignment(seat_number, total_players, multiple_tables)
    if not seat_in_table:
        return None
    if not multiple_tables:
        return str(seat_in_table)
    if not label:
        return None
    return f"{label}{seat_in_table}"


def seat_threshold_reached(conn: sqlite3.Connection, game_id: int, total_players: int) -> bool:
    if total_players <= 0:
        return False
    cur = conn.cursor()
    cur.execute("SELECT manual_seat_assignment, multiple_tables FROM games WHERE id = ?", (game_id,))
    game_row = cur.fetchone()
    if not game_row:
        return False
    if int(game_row["manual_seat_assignment"] or 0) == 1:
        return True
    if int(game_row["multiple_tables"] or 0) == 0 and count_in(conn, int(game_id)) >= int(total_players):
        return True
    return False


def assign_seats_if_ready(conn: sqlite3.Connection, game_id: int, total_players: int) -> None:
    reflow_game_seats(conn, game_id, total_players)


def reflow_game_seats(conn: sqlite3.Connection, game_id: int, total_players: int) -> None:
    cur = conn.cursor()
    if not seat_threshold_reached(conn, game_id, total_players):
        cur.execute("UPDATE rsvps SET seat_number = NULL WHERE game_id = ?", (game_id,))
        return

    cur.execute(
        """
        SELECT id, seat_number, created_at
        FROM rsvps
        WHERE game_id = ? AND status IN ('IN', 'LATE', 'HOST')
        ORDER BY datetime(created_at) ASC, id ASC
        """,
        (game_id,),
    )
    active_rows = cur.fetchall()
    if not active_rows:
        cur.execute("UPDATE rsvps SET seat_number = NULL WHERE game_id = ?", (game_id,))
        return

    # Keep first-time seat assignment random; compact/shift minimally on later updates.
    has_existing_seats = any(row["seat_number"] is not None for row in active_rows)
    if not has_existing_seats:
        active_ids = [int(row["id"]) for row in active_rows]
        seats = list(range(1, len(active_ids) + 1))
        for rsvp_id in active_ids:
            seat = secrets.choice(seats)
            seats.remove(seat)
            cur.execute("UPDATE rsvps SET seat_number = ? WHERE id = ?", (seat, rsvp_id))
    else:
        ordered_rows = sorted(
            active_rows,
            key=lambda row: (
                1 if row["seat_number"] is None else 0,
                row["seat_number"] if row["seat_number"] is not None else 10**9,
                row["created_at"] or "",
                int(row["id"]),
            ),
        )
        next_seat = 1
        for row in ordered_rows:
            cur.execute("UPDATE rsvps SET seat_number = ? WHERE id = ?", (next_seat, int(row["id"])))
            next_seat += 1
    cur.execute(
        "UPDATE rsvps SET seat_number = NULL WHERE game_id = ? AND status NOT IN ('IN', 'LATE', 'HOST')",
        (game_id,),
    )


def available_seats(conn: sqlite3.Connection, game_id: int, total_players: int) -> list:
    cur = conn.cursor()
    cur.execute(
        "SELECT seat_number FROM rsvps WHERE game_id = ? AND seat_number IS NOT NULL",
        (game_id,),
    )
    taken = {row["seat_number"] for row in cur.fetchall()}
    return [n for n in range(1, total_players + 1) if n not in taken]


def assign_random_seat(conn: sqlite3.Connection, game_id: int, total_players: int) -> Optional[int]:
    seats = available_seats(conn, game_id, total_players)
    if not seats:
        return None
    return secrets.choice(seats)


def backfill_seats(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute("SELECT id, total_players FROM games")
    games = cur.fetchall()
    for game in games:
        reflow_game_seats(conn, game["id"], game["total_players"])
    conn.commit()


def verify_csrf(request: Request, token: str) -> bool:
    if not token:
        return False
    session_token = request.session.get("csrf_token")
    if session_token and token == session_token:
        return True
    return verify_signed_csrf_token(token)


def clean_text(value: str, max_len: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > max_len:
        raise ValueError("Invalid input")
    return cleaned


def rate_limit_client_ip(request: Request) -> str:
    # Trust forwarded client IP only when explicitly enabled behind a trusted proxy.
    trust_proxy = (os.getenv("TRUST_PROXY_HEADERS", "false").strip().lower() in {"1", "true", "on", "yes"})
    if trust_proxy:
        xff = (request.headers.get("x-forwarded-for") or "").strip()
        if xff:
            candidate = xff.split(",")[0].strip()
            if candidate:
                return candidate
    return (request.client.host if request.client else None) or "unknown"


def parse_co_organizer_identifier(value: str) -> tuple[str, str]:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("Enter an email or username.")
    if len(raw) > 254:
        raise ValueError("Email or username is too long.")
    if any(ch.isspace() for ch in raw):
        raise ValueError("Email or username cannot contain spaces.")
    if "@" in raw:
        lowered = raw.lower()
        if not CO_ORG_EMAIL_RE.match(lowered):
            raise ValueError("Enter a valid email address.")
        return "email", lowered
    if not CO_ORG_USERNAME_RE.match(raw):
        raise ValueError("Enter a valid username (2-32 chars, letters/numbers/._-).")
    return "username", raw.lower()


def normalize_game_time(value: str) -> str:
    cleaned = clean_text(value, 32)
    normalized = " ".join(cleaned.upper().split())
    for fmt in ("%H:%M", "%H:%M:%S", "%I:%M %p", "%I:%M%p"):
        try:
            return datetime.strptime(normalized, fmt).strftime("%H:%M")
        except Exception:
            pass
    raise ValueError("Invalid game time")


GAME_TYPE_OPTIONS = {
    "texas_holdem_cash": "Texas Hold'em Cash",
    "texas_holdem_tournament": "Texas Hold'em Tournament",
    "plo_cash": "PLO Cash",
    "plo_tournament": "PLO Tournament",
}


def normalize_game_type(value: Optional[str]) -> str:
    raw = (value or "").strip().lower().replace(" ", "_").replace("-", "_")
    return GAME_TYPE_OPTIONS.get(raw, GAME_TYPE_OPTIONS["texas_holdem_cash"])


def normalize_phone_10(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10:
        raise ValueError("Invalid phone")
    return digits


def invite_link(request: Request, code: str) -> str:
    return f"{public_base_url(request)}/game?g={code}"


def game_host_name(conn: sqlite3.Connection, game_id: int, fallback: Optional[str] = None) -> Optional[str]:
    cur = conn.cursor()
    cur.execute("SELECT name FROM rsvps WHERE game_id = ? AND status = 'HOST' ORDER BY created_at ASC LIMIT 1", (int(game_id),))
    row = cur.fetchone()
    host_name = (row["name"] or "").strip() if row and row["name"] else ""
    if host_name:
        return host_name
    return (fallback or "").strip() or None


def _utc_now_iso() -> str:
    return datetime.utcnow().isoformat()


def _utc_in_minutes_iso(minutes: int) -> str:
    return (datetime.utcnow() + timedelta(minutes=minutes)).isoformat()


def _utc_minus_minutes_iso(minutes: int) -> str:
    return (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()


def _utc_minus_seconds_iso(seconds: int) -> str:
    return (datetime.utcnow() - timedelta(seconds=seconds)).isoformat()


def generate_phone_verification_code() -> str:
    return f"{secrets.randbelow(900000) + 100000}"


def otp_code_hash(code: str) -> str:
    return "sha256:" + hashlib.sha256(str(code or "").strip().encode("utf-8")).hexdigest()


def otp_code_matches(stored: str, candidate: str) -> bool:
    raw_stored = str(stored or "").strip()
    raw_candidate = str(candidate or "").strip()
    if raw_stored.startswith("sha256:"):
        expected = otp_code_hash(raw_candidate)
        return hmac.compare_digest(raw_stored, expected)
    # Backward compatibility for pre-hash rows still in DB.
    return hmac.compare_digest(raw_stored, raw_candidate)


def complete_login_session(request: Request, user_row) -> None:
    request.session["user_id"] = user_row["id"]
    request.session["is_admin"] = int(user_row["is_admin"] or 0)
    request.session["user_name"] = user_row["name"]
    request.session.pop("pending_mfa_user_id", None)
    request.session.pop("pending_mfa_name", None)
    request.session.pop("pending_mfa_method", None)
    request.session.pop("pending_totp_secret", None)


def trusted_device_ua_hash(request: Request) -> str:
    ua = (request.headers.get("user-agent") or "").strip()
    return hashlib.sha256(ua.encode("utf-8")).hexdigest()


def trusted_device_token_hash(token: str) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def has_valid_trusted_device(conn: sqlite3.Connection, request: Request, user_id: int) -> bool:
    token = request.cookies.get(TRUSTED_DEVICE_COOKIE)
    if not token:
        return False
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, expires_at, ua_hash
        FROM user_trusted_devices
        WHERE user_id = ?
          AND token_hash = ?
          AND revoked_at IS NULL
        LIMIT 1
        """,
        (user_id, trusted_device_token_hash(token)),
    )
    row = cur.fetchone()
    if not row:
        return False
    try:
        expires_at = datetime.fromisoformat(row["expires_at"])
    except Exception:
        return False
    if datetime.utcnow() > expires_at:
        return False
    current_ua_hash = trusted_device_ua_hash(request)
    if (row["ua_hash"] or "") != current_ua_hash:
        cur.execute(
            "UPDATE user_trusted_devices SET ua_hash = ?, last_seen_at = ? WHERE id = ?",
            (current_ua_hash, _utc_now_iso(), row["id"]),
        )
    else:
        cur.execute("UPDATE user_trusted_devices SET last_seen_at = ? WHERE id = ?", (_utc_now_iso(), row["id"]))
    return True


def create_trusted_device(conn: sqlite3.Connection, request: Request, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO user_trusted_devices (user_id, token_hash, ua_hash, created_at, last_seen_at, expires_at, revoked_at)
        VALUES (?, ?, ?, ?, ?, ?, NULL)
        """,
        (
            user_id,
            trusted_device_token_hash(token),
            trusted_device_ua_hash(request),
            _utc_now_iso(),
            _utc_now_iso(),
            _utc_in_minutes_iso(TRUSTED_DEVICE_DAYS * 24 * 60),
        ),
    )
    return token


def organizer_invitee_lists_with_members(conn: sqlite3.Connection, organizer_id: int) -> list[dict]:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT l.id, l.name, l.created_at, l.updated_at, COUNT(m.id) AS member_count
        FROM organizer_invitee_lists l
        LEFT JOIN organizer_invitee_list_members m ON m.list_id = l.id
        WHERE l.organizer_id = ?
        GROUP BY l.id, l.name, l.created_at, l.updated_at
        ORDER BY LOWER(l.name) ASC, l.id ASC
        """,
        (int(organizer_id),),
    )
    lists = [dict(row) for row in cur.fetchall()]
    for entry in lists:
        cur.execute(
            """
            SELECT id, name, phone
            FROM organizer_invitee_list_members
            WHERE list_id = ?
            ORDER BY LOWER(name) ASC, id ASC
            """,
            (int(entry["id"]),),
        )
        entry["members"] = [dict(row) for row in cur.fetchall()]
    return lists


def organizer_invitee_directory(conn: sqlite3.Connection, organizer_id: int, query: str = "") -> list[dict]:
    cur = conn.cursor()
    base_sql = """
        SELECT organizer_invitees.id, organizer_invitees.name, organizer_invitees.phone,
               organizer_invitees.created_at, organizer_invitees.updated_at, organizer_invitees.last_seen_at
        FROM organizer_invitees
        WHERE organizer_invitees.organizer_id = ?
    """
    params: list = [int(organizer_id)]
    if str(query or "").strip():
        like = f"%{str(query).strip().lower()}%"
        base_sql += " AND (LOWER(organizer_invitees.name) LIKE ? OR organizer_invitees.phone LIKE ?)"
        params.extend([like, like])
    base_sql += " ORDER BY LOWER(organizer_invitees.name) ASC, datetime(organizer_invitees.last_seen_at) DESC, organizer_invitees.id ASC LIMIT 500"
    cur.execute(base_sql, tuple(params))
    return [dict(row) for row in cur.fetchall()]


def organizer_invitee_row(conn: sqlite3.Connection, organizer_id: int, phone_10: Optional[str]) -> Optional[sqlite3.Row]:
    phone = (phone_10 or "").strip()
    if not phone:
        return None
    cur = conn.cursor()
    cur.execute(
        """
        SELECT *
        FROM organizer_invitees
        WHERE organizer_id = ? AND phone = ?
        LIMIT 1
        """,
        (int(organizer_id), phone),
    )
    return cur.fetchone()


def get_invitee_list_for_owner(conn: sqlite3.Connection, organizer_id: int, list_id: int):
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM organizer_invitee_lists WHERE id = ? AND organizer_id = ? LIMIT 1",
        (int(list_id), int(organizer_id)),
    )
    return cur.fetchone()


def selected_invite_list_rows(conn: sqlite3.Connection, organizer_id: int, list_ids: list[int]) -> list[sqlite3.Row]:
    cleaned_ids = [int(v) for v in list_ids if int(v) > 0]
    if not cleaned_ids:
        return []
    cur = conn.cursor()
    placeholders = ",".join("?" for _ in cleaned_ids)
    cur.execute(
        f"""
        SELECT *
        FROM organizer_invitee_lists
        WHERE organizer_id = ?
          AND id IN ({placeholders})
        ORDER BY LOWER(name) ASC, id ASC
        """,
        [int(organizer_id), *cleaned_ids],
    )
    return cur.fetchall()


def invitee_list_recipients(conn: sqlite3.Connection, organizer_id: int, list_ids: list[int]) -> list[dict[str, str]]:
    selected_lists = selected_invite_list_rows(conn, organizer_id, list_ids)
    if not selected_lists:
        return []
    cur = conn.cursor()
    recipients: list[dict[str, str]] = []
    seen: set[str] = set()
    for list_row in selected_lists:
        cur.execute(
            """
            SELECT name, phone
            FROM organizer_invitee_list_members
            WHERE list_id = ?
            ORDER BY LOWER(name) ASC, id ASC
            """,
            (int(list_row["id"]),),
        )
        for row in cur.fetchall():
            phone = (row["phone"] or "").strip()
            if not phone or phone in seen:
                continue
            seen.add(phone)
            recipients.append({"name": (row["name"] or "").strip(), "phone": phone})
    return recipients


def _totp_normalize_secret(secret: str) -> Optional[bytes]:
    cleaned = (secret or "").replace(" ", "").strip().upper()
    if not cleaned:
        return None
    pad_len = (8 - (len(cleaned) % 8)) % 8
    cleaned += "=" * pad_len
    try:
        return base64.b32decode(cleaned, casefold=True)
    except (binascii.Error, ValueError):
        return None


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def build_totp_uri(user_row, secret: str) -> str:
    label = f"{TOTP_ISSUER}:{user_row['email']}"
    return (
        f"otpauth://totp/{urllib.parse.quote(label)}"
        f"?secret={urllib.parse.quote(secret)}"
        f"&issuer={urllib.parse.quote(TOTP_ISSUER)}"
        "&algorithm=SHA1&digits=6&period=30"
    )


def build_totp_qr_svg(otpauth_uri: str) -> str:
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=3,
    )
    qr.add_data(otpauth_uri)
    qr.make(fit=True)
    img = qr.make_image(image_factory=SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


def _totp_code(secret: str, counter: int) -> Optional[str]:
    key = _totp_normalize_secret(secret)
    if not key:
        return None
    msg = struct.pack(">Q", int(counter))
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % 1_000_000).zfill(6)


def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    candidate = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(candidate) != 6:
        return False
    current_counter = int(time.time() // 30)
    for offset in range(-window, window + 1):
        if _totp_code(secret, current_counter + offset) == candidate:
            return True
    return False


def maybe_notify_organizer_when_out(
    conn: sqlite3.Connection,
    game_row,
    previous_status: Optional[str],
    new_status: str,
    player_name: str,
) -> None:
    return None


def normalize_rsvp_token(value: Optional[str]) -> Optional[str]:
    token = (value or "").strip()
    if not token:
        return None
    if len(token) < 8 or len(token) > 64:
        return None
    for ch in token:
        if not (ch.isalnum() or ch in {"-", "_"}):
            return None
    return token


def normalize_invitee_token(value: Optional[str]) -> Optional[str]:
    return normalize_rsvp_token(value)


def invitee_token_hash(token: str) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def create_invitee_token() -> str:
    return secrets.token_urlsafe(24)


def lookup_phone_by_invitee_token(conn: sqlite3.Connection, invitee_token: Optional[str]) -> Optional[str]:
    token = normalize_invitee_token(invitee_token)
    if not token:
        return None
    cur = conn.cursor()
    cur.execute(
        """
        SELECT phone
        FROM invitee_browser_tokens
        WHERE token_hash = ?
        LIMIT 1
        """,
        (invitee_token_hash(token),),
    )
    row = cur.fetchone()
    if not row:
        return None
    cur.execute(
        "UPDATE invitee_browser_tokens SET updated_at = ?, last_seen_at = ? WHERE token_hash = ?",
        (_utc_now_iso(), _utc_now_iso(), invitee_token_hash(token)),
    )
    return (row["phone"] or "").strip() or None


def ensure_invitee_token_for_phone(conn: sqlite3.Connection, phone_10: str, preferred_token: Optional[str]) -> str:
    now = _utc_now_iso()
    token = normalize_invitee_token(preferred_token)
    cur = conn.cursor()
    if token:
        token_hash = invitee_token_hash(token)
        cur.execute("SELECT phone FROM invitee_browser_tokens WHERE token_hash = ? LIMIT 1", (token_hash,))
        row = cur.fetchone()
        if row and str(row["phone"] or "").strip() == phone_10:
            cur.execute(
                "UPDATE invitee_browser_tokens SET updated_at = ?, last_seen_at = ? WHERE token_hash = ?",
                (now, now, token_hash),
            )
            return token
    fresh = create_invitee_token()
    cur.execute(
        """
        INSERT INTO invitee_browser_tokens (token_hash, phone, created_at, updated_at, last_seen_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (invitee_token_hash(fresh), phone_10, now, now, now),
    )
    return fresh


def web_push_rows_for_user(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT *
        FROM web_push_subscriptions
        WHERE user_id = ?
          AND disabled_at IS NULL
        ORDER BY id ASC
        """,
        (int(user_id),),
    )
    return cur.fetchall()


def web_push_rows_for_phones(conn: sqlite3.Connection, phones: list[str]) -> list[sqlite3.Row]:
    cleaned = sorted({str(v or "").strip() for v in phones if str(v or "").strip()})
    if not cleaned:
        return []
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT *
        FROM web_push_subscriptions
        WHERE phone IN ({",".join("?" for _ in cleaned)})
          AND disabled_at IS NULL
        ORDER BY id ASC
        """,
        cleaned,
    )
    return cur.fetchall()


def web_push_rows_for_invitee_phones(conn: sqlite3.Connection, phones: list[str]) -> list[sqlite3.Row]:
    cleaned = sorted({str(v or "").strip() for v in phones if str(v or "").strip()})
    if not cleaned:
        return []
    cur = conn.cursor()
    rows = []
    seen_ids = set()

    for row in web_push_rows_for_phones(conn, cleaned):
        row_id = int(row["id"])
        if row_id not in seen_ids:
            rows.append(row)
            seen_ids.add(row_id)

    cur.execute(
        f"""
        SELECT DISTINCT token_hash
        FROM invitee_browser_tokens
        WHERE phone IN ({",".join("?" for _ in cleaned)})
        """,
        cleaned,
    )
    token_hashes = [str(row["token_hash"] or "").strip() for row in cur.fetchall() if (row["token_hash"] or "").strip()]
    if not token_hashes:
        return rows
    cur.execute(
        f"""
        SELECT *
        FROM web_push_subscriptions
        WHERE invitee_token_hash IN ({",".join("?" for _ in token_hashes)})
          AND disabled_at IS NULL
        ORDER BY id ASC
        """,
        token_hashes,
    )
    for row in cur.fetchall():
        row_id = int(row["id"])
        if row_id not in seen_ids:
            rows.append(row)
            seen_ids.add(row_id)
    return rows


def upsert_web_push_subscription(
    conn: sqlite3.Connection,
    endpoint: str,
    p256dh: str,
    auth: str,
    user_id: Optional[int],
    phone_10: Optional[str],
    invitee_token: Optional[str],
    user_agent: Optional[str],
) -> None:
    now = _utc_now_iso()
    cur = conn.cursor()
    token_hash = invitee_token_hash(invitee_token) if normalize_invitee_token(invitee_token) else None
    cur.execute(
        """
        INSERT INTO web_push_subscriptions (
            user_id, phone, invitee_token_hash, endpoint, p256dh, auth, user_agent,
            created_at, updated_at, disabled_at, last_error_at, last_error_detail
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
        ON CONFLICT(endpoint) DO UPDATE SET
            user_id = excluded.user_id,
            phone = excluded.phone,
            invitee_token_hash = excluded.invitee_token_hash,
            p256dh = excluded.p256dh,
            auth = excluded.auth,
            user_agent = excluded.user_agent,
            updated_at = excluded.updated_at,
            disabled_at = NULL,
            last_error_at = NULL,
            last_error_detail = NULL
        """,
        (user_id, phone_10, token_hash, endpoint, p256dh, auth, user_agent, now, now),
    )


def disable_web_push_subscription(conn: sqlite3.Connection, endpoint: str, detail: Optional[str] = None) -> None:
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE web_push_subscriptions
        SET disabled_at = ?, updated_at = ?, last_error_at = ?, last_error_detail = ?
        WHERE endpoint = ?
        """,
        (_utc_now_iso(), _utc_now_iso(), _utc_now_iso(), (detail or "")[:500], endpoint),
    )


def build_apple_vapid_headers(endpoint: str, vapid_private_key: str, vapid_subject: str) -> dict[str, str]:
    parsed = urllib.parse.urlparse(endpoint)
    aud = f"{parsed.scheme}://{parsed.netloc}"
    claims = {"sub": vapid_subject, "aud": aud, "exp": int(time.time()) + 3600}
    if os.path.isfile(vapid_private_key):
        vapid = Vapid01.from_file(private_key_file=vapid_private_key)
    else:
        vapid = Vapid01.from_string(private_key=vapid_private_key)
    token = vapid_sign(vapid._base_sign(claims), vapid.private_key).strip("=")
    public_key = vapid.public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    public_key_b64 = vapid_b64urlencode(public_key)
    return {"Authorization": f"vapid t={token}, k={public_key_b64}"}


def send_web_push_rows(conn: sqlite3.Connection, rows: list[sqlite3.Row], title: str, body: str, url: str) -> int:
    if not web_push_enabled():
        return 0
    vapid_subject = (os.getenv("WEB_PUSH_SUBJECT") or "").strip()
    vapid_claims = {"sub": vapid_subject}
    vapid_private_key = (os.getenv("WEB_PUSH_VAPID_PRIVATE_KEY_PATH") or "").strip() or (os.getenv("WEB_PUSH_VAPID_PRIVATE_KEY") or "").strip()
    payload = json.dumps({"title": title, "body": body, "url": url})
    sent = 0
    cur = conn.cursor()
    for row in rows:
        endpoint = (row["endpoint"] or "").strip()
        if not endpoint:
            continue
        subscription_info = {
            "endpoint": endpoint,
            "keys": {
                "p256dh": row["p256dh"],
                "auth": row["auth"],
            },
        }
        try:
            if endpoint.startswith("https://web.push.apple.com/"):
                webpush(
                    subscription_info=subscription_info,
                    data=payload,
                    headers=build_apple_vapid_headers(endpoint, vapid_private_key, vapid_subject),
                    ttl=600,
                )
            else:
                webpush(
                    subscription_info=subscription_info,
                    data=payload,
                    vapid_private_key=vapid_private_key,
                    vapid_claims=vapid_claims,
                    ttl=600,
                )
            cur.execute(
                """
                UPDATE web_push_subscriptions
                SET updated_at = ?, last_success_at = ?, last_error_at = NULL, last_error_detail = NULL
                WHERE id = ?
                """,
                (_utc_now_iso(), _utc_now_iso(), int(row["id"])),
            )
            sent += 1
        except WebPushException as exc:
            status_code = None
            if getattr(exc, "response", None) is not None:
                status_code = getattr(exc.response, "status_code", None)
            detail = str(exc)
            if status_code in {404, 410}:
                disable_web_push_subscription(conn, endpoint, detail)
            else:
                cur.execute(
                    """
                    UPDATE web_push_subscriptions
                    SET updated_at = ?, last_error_at = ?, last_error_detail = ?
                    WHERE id = ?
                    """,
                    (_utc_now_iso(), _utc_now_iso(), detail[:500], int(row["id"])),
                )
    return sent


def notify_game_cancelled_push(conn: sqlite3.Connection, game_row) -> int:
    cur = conn.cursor()
    cur.execute("SELECT name FROM rsvps WHERE game_id = ? AND status = 'HOST' ORDER BY created_at ASC LIMIT 1", (int(game_row["id"]),))
    host_row = cur.fetchone()
    host_name = (host_row["name"] if host_row and host_row["name"] else "Organizer")
    cur.execute(
        """
        SELECT phone FROM rsvps WHERE game_id = ? AND phone IS NOT NULL AND TRIM(phone) != ''
        UNION
        SELECT phone FROM standby WHERE game_id = ? AND phone IS NOT NULL AND TRIM(phone) != ''
        """,
        (int(game_row["id"]), int(game_row["id"])),
    )
    phones = [str(row["phone"] or "").strip() for row in cur.fetchall()]
    rows = web_push_rows_for_user(conn, int(game_row["organizer_id"])) + web_push_rows_for_invitee_phones(conn, phones)
    unique_rows = {int(row["id"]): row for row in rows}.values()
    return send_web_push_rows(
        conn,
        list(unique_rows),
        "Game cancelled",
        f"{host_name}'s game was cancelled.",
        f"{configured_public_base_url()}/g/{game_row['code']}",
    )


def organizer_push_rows_for_game(conn: sqlite3.Connection, game_row, phones: Optional[list[str]] = None) -> list[sqlite3.Row]:
    rows = web_push_rows_for_user(conn, int(game_row["organizer_id"]))
    if phones:
        rows += web_push_rows_for_invitee_phones(conn, phones)
    return list({int(row["id"]): row for row in rows}.values())


def notify_rsvp_status_push(conn: sqlite3.Connection, game_row, actor_name: str, status: str, late_eta: Optional[str] = None) -> int:
    status_label = (status or "").upper().strip()
    if status_label == "LATE" and late_eta:
        body = f"{actor_name} is LATE ({late_eta}) for {game_row['title']}."
    else:
        body = f"{actor_name} is {status_label} for {game_row['title']}."
    return send_web_push_rows(
        conn,
        organizer_push_rows_for_game(conn, game_row),
        "RSVP update",
        body,
        f"{configured_public_base_url()}/games/{game_row['id']}",
    )


def notify_game_full_push(conn: sqlite3.Connection, game_row) -> int:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT phone
        FROM rsvps
        WHERE game_id = ?
          AND status IN ('HOST', 'IN', 'LATE')
          AND phone IS NOT NULL
          AND TRIM(phone) != ''
        """,
        (int(game_row["id"]),),
    )
    phones = [str(row["phone"] or "").strip() for row in cur.fetchall()]
    return send_web_push_rows(
        conn,
        organizer_push_rows_for_game(conn, game_row, phones),
        "Game is full",
        f"{game_row['title']} is now full.",
        f"{configured_public_base_url()}/g/{game_row['code']}",
    )


def seat_map_for_game(conn: sqlite3.Connection, game_id: int, total_players: int, multiple_tables: bool) -> dict[int, tuple[str, str, str]]:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, name, phone, seat_number
        FROM rsvps
        WHERE game_id = ?
          AND status IN ('HOST', 'IN', 'LATE')
          AND seat_number IS NOT NULL
        """,
        (int(game_id),),
    )
    out = {}
    for row in cur.fetchall():
        out[int(row["id"])] = (
            str(row["name"] or "").strip(),
            str(row["phone"] or "").strip(),
            seat_display(row["seat_number"], total_players, multiple_tables) or "",
        )
    return out


def notify_changed_seats_push(conn: sqlite3.Connection, game_row, previous_map: dict[int, tuple[str, str, str]]) -> int:
    current_map = seat_map_for_game(conn, int(game_row["id"]), int(game_row["total_players"]), game_uses_multiple_tables(game_row))
    sent = 0
    organizer_rows = organizer_push_rows_for_game(conn, game_row)
    for rsvp_id, (name, phone, seat_label) in current_map.items():
        if not seat_label:
            continue
        if previous_map.get(rsvp_id) == (name, phone, seat_label):
            continue
        if phone:
            player_rows = web_push_rows_for_invitee_phones(conn, [phone])
            if player_rows:
                sent += send_web_push_rows(
                    conn,
                    player_rows,
                    "Seat assigned",
                    f"Your seat is {seat_label} for {game_row['title']}.",
                    f"{configured_public_base_url()}/g/{game_row['code']}",
                )
        if organizer_rows:
            sent += send_web_push_rows(
                conn,
                organizer_rows,
                "Seat assigned",
                f"{name or 'Player'} seat is {seat_label} for {game_row['title']}.",
                f"{configured_public_base_url()}/games/{game_row['id']}",
            )
    return sent


def upsert_invitee_profiles(conn: sqlite3.Connection, organizer_id: int, phone_10: Optional[str], name: Optional[str]) -> None:
    phone = (phone_10 or "").strip()
    display_name = (name or "").strip()
    if not phone or not display_name:
        return
    now = _utc_now_iso()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO organizer_invitees (organizer_id, phone, name, created_at, updated_at, last_seen_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(organizer_id, phone) DO UPDATE SET
            name = excluded.name,
            updated_at = excluded.updated_at,
            last_seen_at = excluded.last_seen_at
        """,
        (int(organizer_id), phone, display_name, now, now, now),
    )


def ensure_organizer_invitee(conn: sqlite3.Connection, organizer_id: int, phone_10: Optional[str], name: Optional[str]) -> Optional[int]:
    phone = (phone_10 or "").strip()
    display_name = (name or "").strip()
    if not phone or not display_name:
        return None
    upsert_invitee_profiles(conn, organizer_id, phone, display_name)
    cur = conn.cursor()
    cur.execute(
        "SELECT id FROM organizer_invitees WHERE organizer_id = ? AND phone = ? LIMIT 1",
        (int(organizer_id), phone),
    )
    row = cur.fetchone()
    return int(row["id"]) if row else None


def lookup_invitee_profile(conn: sqlite3.Connection, organizer_id: int, phone_10: Optional[str]) -> Optional[sqlite3.Row]:
    phone = (phone_10 or "").strip()
    if not phone:
        return None
    cur = conn.cursor()
    cur.execute(
        "SELECT id, phone, name FROM organizer_invitees WHERE organizer_id = ? AND phone = ? LIMIT 1",
        (int(organizer_id), phone),
    )
    return cur.fetchone()


def lookup_unique_invitee_profile_by_name(conn: sqlite3.Connection, organizer_id: int, name: Optional[str]) -> Optional[sqlite3.Row]:
    display_name = (name or "").strip()
    if not display_name:
        return None
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, phone, name
        FROM organizer_invitees
        WHERE organizer_id = ?
          AND LOWER(name) = LOWER(?)
        ORDER BY id ASC
        """,
        (int(organizer_id), display_name),
    )
    rows = cur.fetchall()
    if len(rows) != 1:
        return None
    return rows[0]


def backfill_game_invitee_links(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT r.id, r.phone, r.name, g.organizer_id
        FROM rsvps r
        JOIN games g ON g.id = r.game_id
        WHERE (r.invitee_id IS NULL OR r.invitee_id = 0)
          AND r.phone IS NOT NULL
          AND TRIM(r.phone) != ''
        ORDER BY r.id ASC
        """
    )
    for row in cur.fetchall():
        invitee_id = ensure_organizer_invitee(conn, int(row["organizer_id"]), row["phone"], row["name"])
        if invitee_id:
            cur.execute("UPDATE rsvps SET invitee_id = ? WHERE id = ?", (invitee_id, int(row["id"])))
    cur.execute(
        """
        SELECT s.id, s.phone, s.name, g.organizer_id
        FROM standby s
        JOIN games g ON g.id = s.game_id
        WHERE (s.invitee_id IS NULL OR s.invitee_id = 0)
          AND s.phone IS NOT NULL
          AND TRIM(s.phone) != ''
        ORDER BY s.id ASC
        """
    )
    for row in cur.fetchall():
        invitee_id = ensure_organizer_invitee(conn, int(row["organizer_id"]), row["phone"], row["name"])
        if invitee_id:
            cur.execute("UPDATE standby SET invitee_id = ? WHERE id = ?", (invitee_id, int(row["id"])))


def backfill_legacy_rsvp_identity(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT r.id, r.name, g.organizer_id
        FROM rsvps r
        JOIN games g ON g.id = r.game_id
        WHERE (r.phone IS NULL OR TRIM(r.phone) = '')
          AND (r.invitee_id IS NULL OR r.invitee_id = 0)
          AND TRIM(COALESCE(r.name, '')) != ''
        ORDER BY r.id ASC
        """
    )
    for row in cur.fetchall():
        profile = lookup_unique_invitee_profile_by_name(conn, int(row["organizer_id"]), row["name"])
        if not profile:
            continue
        cur.execute(
            "UPDATE rsvps SET invitee_id = ?, phone = ? WHERE id = ?",
            (int(profile["id"]), profile["phone"], int(row["id"])),
        )
    cur.execute(
        """
        SELECT s.id, s.name, g.organizer_id
        FROM standby s
        JOIN games g ON g.id = s.game_id
        WHERE (s.phone IS NULL OR TRIM(s.phone) = '')
          AND (s.invitee_id IS NULL OR s.invitee_id = 0)
          AND TRIM(COALESCE(s.name, '')) != ''
        ORDER BY s.id ASC
        """
    )
    for row in cur.fetchall():
        profile = lookup_unique_invitee_profile_by_name(conn, int(row["organizer_id"]), row["name"])
        if not profile:
            continue
        cur.execute(
            "UPDATE standby SET invitee_id = ?, phone = ? WHERE id = ?",
            (int(profile["id"]), profile["phone"], int(row["id"])),
        )


def cleanup_old_games(conn: sqlite3.Connection, organizer_id: int) -> None:
    cutoff = (datetime.utcnow() - timedelta(days=365)).isoformat()
    cur = conn.cursor()
    cur.execute("SELECT id FROM games WHERE organizer_id = ? AND created_at < ?", (organizer_id, cutoff))
    old_ids = [row["id"] for row in cur.fetchall()]
    if not old_ids:
        return
    cur.execute("DELETE FROM game_co_organizers WHERE game_id IN (%s)" % ",".join("?" * len(old_ids)), old_ids)
    cur.execute("DELETE FROM rsvps WHERE game_id IN (%s)" % ",".join("?" * len(old_ids)), old_ids)
    cur.execute("DELETE FROM standby WHERE game_id IN (%s)" % ",".join("?" * len(old_ids)), old_ids)
    cur.execute("DELETE FROM games WHERE id IN (%s)" % ",".join("?" * len(old_ids)), old_ids)


def is_game_expired(game_row) -> bool:
    try:
        dt = datetime.fromisoformat(f"{game_row['game_date']}T{game_row['game_time']}")
        local_dt = thunder_bay_localize(dt)
        return thunder_bay_now() > (local_dt + timedelta(hours=6))
    except Exception:
        return False


def is_game_cancelled(game_row) -> bool:
    return bool(game_row and int(game_row["is_cancelled"] or 0) == 1)


def game_snapshot_payload(conn: sqlite3.Connection, game_row) -> dict:
    game_id = int(game_row["id"])
    cur = conn.cursor()
    cur.execute("SELECT * FROM rsvps WHERE game_id = ? ORDER BY created_at ASC", (game_id,))
    rsvp_rows = cur.fetchall()
    push_enabled_phones = set()
    for row in rsvp_rows:
        phone = str(row["phone"] or "").strip()
        if not phone:
            continue
        if web_push_rows_for_invitee_phones(conn, [phone]):
            push_enabled_phones.add(phone)
    cur.execute("SELECT 1 FROM web_push_subscriptions WHERE disabled_at IS NULL AND user_id = ? LIMIT 1", (int(game_row["organizer_id"]),))
    organizer_push_enabled = cur.fetchone() is not None
    rsvps = []
    for row in rsvp_rows:
        rsvps.append(
            {
                "id": int(row["id"]),
                "name": row["name"],
                "phone": row["phone"] or "",
                "phone_fmt": format_phone(row["phone"]),
                "status": row["status"],
                "late_eta": row["late_eta"] or "",
                "created_at": row["created_at"],
                "created_at_fmt": format_ts(row["created_at"]),
                "seat_number": row["seat_number"],
                "seat_label": seat_display(row["seat_number"], game_row["total_players"], game_uses_multiple_tables(game_row)) or "-",
                "push_enabled": bool(
                    str(row["phone"] or "").strip() in push_enabled_phones
                    or (str(row["status"] or "").upper() == "HOST" and organizer_push_enabled)
                ),
            }
        )
    payload = {
        "game_id": game_id,
        "is_cancelled": is_game_cancelled(game_row),
        "in_count": count_in(conn, game_id),
        "total_players": int(game_row["total_players"]),
        "rsvps": rsvps,
    }
    payload["signature"] = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return payload


def player_in_rate_percent(conn: sqlite3.Connection, game_row, player_row) -> Optional[int]:
    clauses = ["g.organizer_id = ?"]
    params: list = [int(game_row["organizer_id"])]
    invitee_id = player_row["invitee_id"] if "invitee_id" in player_row.keys() else None
    phone = str(player_row["phone"] or "").strip() if "phone" in player_row.keys() else ""
    if invitee_id:
        clauses.append("r.invitee_id = ?")
        params.append(int(invitee_id))
    elif phone:
        clauses.append("r.phone = ?")
        params.append(phone)
    else:
        clauses.append("LOWER(r.name) = LOWER(?)")
        params.append(player_row["name"])
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT
            COUNT(*) AS total_games,
            SUM(CASE WHEN r.status IN ('HOST', 'IN', 'LATE') THEN 1 ELSE 0 END) AS in_games
        FROM rsvps r
        JOIN games g ON g.id = r.game_id
        WHERE {" AND ".join(clauses)}
          AND r.status IN ('HOST', 'IN', 'LATE', 'OUT')
        """,
        params,
    )
    row = cur.fetchone()
    total = int(row["total_games"] or 0) if row else 0
    if total <= 0:
        return None
    in_games = int(row["in_games"] or 0)
    return round((in_games / total) * 100)


def host_snapshot_payload(conn: sqlite3.Connection, game_row) -> dict:
    game_id = int(game_row["id"])
    game_created_at = None
    try:
        raw_created = str(game_row["created_at"] or "").strip().replace("Z", "+00:00")
        game_created_at = datetime.fromisoformat(raw_created)
    except Exception:
        game_created_at = None
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, invitee_id, name, phone, status, late_eta, seat_number, created_at
        FROM rsvps
        WHERE game_id = ? AND status IN ('HOST', 'IN', 'LATE')
        ORDER BY
            CASE status WHEN 'HOST' THEN 0 WHEN 'IN' THEN 1 WHEN 'LATE' THEN 2 ELSE 9 END,
            datetime(created_at) ASC, id ASC
        """,
        (game_id,),
    )
    fetched_rows = cur.fetchall()
    response_rank_by_id = {}
    responder_rank = 1
    ranked_rows = sorted(
        fetched_rows,
        key=lambda row: (
            1 if (row["status"] or "").upper() == "HOST" else 0,
            row["created_at"] or "",
            int(row["id"]),
        ),
    )
    for row in ranked_rows:
        if (row["status"] or "").upper() == "HOST":
            continue
        response_rank_by_id[int(row["id"])] = responder_rank
        responder_rank += 1
    slowest_response_rank = responder_rank - 1 if responder_rank > 1 else None
    players = []
    for row in fetched_rows:
        response_elapsed_ms = None
        if game_created_at is not None:
            try:
                raw_rsvp_created = str(row["created_at"] or "").strip().replace("Z", "+00:00")
                rsvp_created_at = datetime.fromisoformat(raw_rsvp_created)
                delta_ms = int((rsvp_created_at - game_created_at).total_seconds() * 1000)
                response_elapsed_ms = max(0, delta_ms)
            except Exception:
                response_elapsed_ms = None
        players.append(
            {
                "id": int(row["id"]),
                "name": row["name"],
                "status": row["status"],
                "late_eta": row["late_eta"] or "",
                "seat_number": row["seat_number"],
                "seat_label": seat_display(row["seat_number"], game_row["total_players"], game_uses_multiple_tables(game_row)) or "-",
                "response_rank": response_rank_by_id.get(int(row["id"])),
                "response_elapsed_ms": response_elapsed_ms,
                "is_slowest_response": response_rank_by_id.get(int(row["id"])) == slowest_response_rank,
                "in_rate_percent": player_in_rate_percent(conn, game_row, row),
            }
        )
    player_count = sum(1 for p in players if p["status"] in {"HOST", "IN", "LATE"})
    late_count = sum(1 for p in players if p["status"] == "LATE")
    payload = {
        "game_id": game_id,
        "title": game_row["title"],
        "game_date": game_row["game_date"],
        "game_time": game_row["game_time"],
        "total_players": int(game_row["total_players"]),
        "is_cancelled": is_game_cancelled(game_row),
        "in_count": player_count,
        "player_count": player_count,
        "late_count": late_count,
        "players": players,
    }
    payload["signature"] = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return payload


def invitee_roster_payload(conn: sqlite3.Connection, game_row) -> list:
    game_id = int(game_row["id"])
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, name, status, late_eta, seat_number, created_at
        FROM rsvps
        WHERE game_id = ? AND status IN ('HOST', 'IN', 'LATE')
        ORDER BY
            CASE WHEN seat_number IS NULL THEN 1 ELSE 0 END,
            seat_number ASC,
            datetime(created_at) ASC, id ASC
        """,
        (game_id,),
    )
    rows = []
    for row in cur.fetchall():
        rows.append(
            {
                "id": int(row["id"]),
                "name": row["name"],
                "status": row["status"],
                "late_eta": row["late_eta"] or "",
                "seat_number": row["seat_number"],
                "seat_label": seat_display(row["seat_number"], game_row["total_players"], game_uses_multiple_tables(game_row)) or "-",
            }
        )
    return rows


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user_id = current_user_id(request)
    if user_id:
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/push/public-key")
def push_public_key():
    return JSONResponse(
        {
            "enabled": web_push_enabled(),
            "public_key": (os.getenv("WEB_PUSH_VAPID_PUBLIC_KEY") or "").strip(),
        }
    )


@app.post("/push/subscribe")
async def push_subscribe(request: Request):
    token = (request.headers.get("X-CSRF-Token") or "").strip()
    if not verify_signed_csrf_token(token):
        return JSONResponse({"ok": False, "error": "Bad CSRF token"}, status_code=400)
    if not web_push_enabled():
        return JSONResponse({"ok": False, "error": "Push is not configured"}, status_code=503)
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)
    subscription = payload.get("subscription") or {}
    keys = subscription.get("keys") or {}
    endpoint = str(subscription.get("endpoint") or "").strip()
    p256dh = str(keys.get("p256dh") or "").strip()
    auth = str(keys.get("auth") or "").strip()
    if not endpoint or not p256dh or not auth:
        return JSONResponse({"ok": False, "error": "Invalid subscription"}, status_code=400)
    invitee_token = normalize_invitee_token(payload.get("invitee_token"))
    phone_10 = None
    user_id = current_user_id(request)
    try:
        phone_10 = normalize_phone_10(payload.get("phone"))
    except ValueError:
        phone_10 = None
    conn = get_db()
    try:
        if not phone_10 and invitee_token:
            phone_10 = lookup_phone_by_invitee_token(conn, invitee_token)
        if not phone_10 and user_id:
            cur = conn.cursor()
            cur.execute("SELECT phone FROM users WHERE id = ?", (int(user_id),))
            user_row = cur.fetchone()
            if user_row:
                try:
                    phone_10 = normalize_phone_10(user_row["phone"])
                except ValueError:
                    phone_10 = None
        upsert_web_push_subscription(
            conn,
            endpoint=endpoint,
            p256dh=p256dh,
            auth=auth,
            user_id=user_id,
            phone_10=phone_10,
            invitee_token=invitee_token,
            user_agent=request.headers.get("user-agent"),
        )
        conn.commit()
    finally:
        conn.close()
    return JSONResponse({"ok": True})


@app.post("/push/unsubscribe")
async def push_unsubscribe(request: Request):
    token = (request.headers.get("X-CSRF-Token") or "").strip()
    if not verify_signed_csrf_token(token):
        return JSONResponse({"ok": False, "error": "Bad CSRF token"}, status_code=400)
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)
    endpoint = str((payload.get("subscription") or {}).get("endpoint") or payload.get("endpoint") or "").strip()
    if not endpoint:
        return JSONResponse({"ok": False, "error": "Missing endpoint"}, status_code=400)
    conn = get_db()
    try:
        disable_web_push_subscription(conn, endpoint, "user unsubscribed")
        conn.commit()
    finally:
        conn.close()
    return JSONResponse({"ok": True})


@app.post("/push/test")
def push_test(request: Request):
    user_id = require_login(request)
    if not user_id:
        return JSONResponse({"ok": False, "error": "Unauthorized"}, status_code=401)
    token = (request.headers.get("X-CSRF-Token") or "").strip()
    if not verify_signed_csrf_token(token):
        return JSONResponse({"ok": False, "error": "Bad CSRF token"}, status_code=400)
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM users WHERE id = ?", (int(user_id),))
        row = cur.fetchone()
        display_name = (row["name"] if row and row["name"] else "Organizer")
        sent = send_web_push_rows(
            conn,
            web_push_rows_for_user(conn, int(user_id)),
            "Push is working",
            f"Browser notifications are enabled for {display_name}.",
            f"{configured_public_base_url()}/dashboard",
        )
        conn.commit()
    finally:
        conn.close()
    return JSONResponse({"ok": True, "sent": sent})


@app.post("/push/test-device")
async def push_test_device(request: Request):
    token = (request.headers.get("X-CSRF-Token") or "").strip()
    if not verify_signed_csrf_token(token):
        return JSONResponse({"ok": False, "error": "Bad CSRF token"}, status_code=400)
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)
    endpoint = str((payload.get("subscription") or {}).get("endpoint") or payload.get("endpoint") or "").strip()
    if not endpoint:
        return JSONResponse({"ok": False, "error": "Missing endpoint"}, status_code=400)
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM web_push_subscriptions WHERE endpoint = ? AND disabled_at IS NULL LIMIT 1", (endpoint,))
        row = cur.fetchone()
        if not row:
            return JSONResponse({"ok": False, "error": "This device is not subscribed yet."}, status_code=404)
        sent = send_web_push_rows(
            conn,
            [row],
            "Push is working",
            "Browser notifications are enabled on this device.",
            configured_public_base_url(),
        )
        conn.commit()
    finally:
        conn.close()
    return JSONResponse({"ok": True, "sent": sent})


@app.get("/favicon.ico")
def favicon():
    return RedirectResponse(url="/static/favicon-app-32.png", status_code=302)


@app.get("/push-sw.js")
def push_service_worker():
    return FileResponse(
        BASE_DIR / "static" / "push-sw-v2.js",
        media_type="text/javascript",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


@app.head("/push-sw.js")
def push_service_worker_head():
    return PlainTextResponse(
        "",
        media_type="text/javascript",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


@app.get("/push-sw-v2.js")
def push_service_worker_v2():
    return FileResponse(
        BASE_DIR / "static" / "push-sw-v2.js",
        media_type="text/javascript",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


@app.head("/push-sw-v2.js")
def push_service_worker_v2_head():
    return PlainTextResponse(
        "",
        media_type="text/javascript",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


@app.get("/apple-touch-icon.png")
def apple_touch_icon():
    return RedirectResponse(url="/static/apple-touch-icon-app.png", status_code=302)


@app.get("/apple-touch-icon-precomposed.png")
def apple_touch_icon_precomposed():
    return RedirectResponse(url="/static/apple-touch-icon-app.png", status_code=302)


@app.get("/2436e4e916bd7e6bcd16ae6a02c01433.html")
def twilio_domain_verification():
    return PlainTextResponse(
        "twilio-domain-verification=2436e4e916bd7e6bcd16ae6a02c01433",
        media_type="text/plain",
    )


@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None})


@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    name: str = Form(...),
    csrf_token: str = Form(...),
):
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    if len(password) < 8 or len(password) > 128:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Password must be at least 8 characters."},
            status_code=400,
        )
    try:
        cleaned_name = clean_text(name, 50)
        cleaned_email = clean_text(email.lower().strip(), 254)
    except ValueError:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Invalid name or email."},
            status_code=400,
        )

    password_hash = pwd_context.hash(password)
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (email, password_hash, name, created_at, is_admin, is_disabled) VALUES (?, ?, ?, ?, 0, 0)",
            (cleaned_email, password_hash, cleaned_name, datetime.utcnow().isoformat()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Email already registered."},
            status_code=400,
        )
    conn.close()
    return RedirectResponse(url="/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
):
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    conn = get_db()
    cur = conn.cursor()
    identifier = email.strip()
    cur.execute(
        """
        SELECT id, password_hash, is_admin, is_disabled, name, mfa_enabled, totp_secret, totp_enabled
        FROM users
        WHERE email = ? OR username = ?
        """,
        (identifier.lower(), identifier),
    )
    row = cur.fetchone()
    if not row or not pwd_context.verify(password, row["password_hash"]):
        conn.close()
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid email or password."},
            status_code=401,
        )
    if row["is_disabled"]:
        conn.close()
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Account disabled. Contact admin."},
            status_code=403,
        )
    if int(row["mfa_enabled"] or 0) == 1:
        has_totp = int(row["totp_enabled"] or 0) == 1 and bool((row["totp_secret"] or "").strip())
        if not has_totp:
            conn.close()
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "MFA is enabled but no authenticator app is configured."},
                status_code=403,
            )
        if has_valid_trusted_device(conn, request, int(row["id"])):
            conn.commit()
            conn.close()
            complete_login_session(request, row)
            return RedirectResponse(url="/dashboard", status_code=302)
        request.session["pending_mfa_user_id"] = int(row["id"])
        request.session["pending_mfa_name"] = row["name"]
        request.session["pending_mfa_method"] = "totp"
        conn.commit()
        conn.close()
        return RedirectResponse(url="/mfa", status_code=302)
    conn.close()
    complete_login_session(request, row)
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/mfa", response_class=HTMLResponse)
def mfa_form(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/dashboard", status_code=302)
    pending_user_id = request.session.get("pending_mfa_user_id")
    if not pending_user_id:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        "mfa.html",
        {
            "request": request,
            "error": None,
            "success": None,
            "mfa_method": "totp",
            "pending_name": request.session.get("pending_mfa_name") or "Organizer",
        },
    )


@app.post("/mfa", response_class=HTMLResponse)
def mfa_verify(request: Request, code: str = Form(...), trust_device: str = Form(None), csrf_token: str = Form(...)):
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    pending_user_id = request.session.get("pending_mfa_user_id")
    if not pending_user_id:
        return RedirectResponse(url="/login", status_code=302)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, is_admin, name, totp_secret, totp_enabled FROM users WHERE id = ?", (int(pending_user_id),))
    row = cur.fetchone()
    verified = bool(row and int(row["totp_enabled"] or 0) == 1 and row["totp_secret"] and verify_totp_code(row["totp_secret"], code))
    if not verified:
        conn.commit()
        conn.close()
        return templates.TemplateResponse(
            "mfa.html",
            {
                "request": request,
                "error": "Invalid or expired MFA code.",
                "success": None,
                "mfa_method": "totp",
                "pending_name": request.session.get("pending_mfa_name") or "Organizer",
            },
            status_code=400,
        )
    conn.commit()
    trusted_token = None
    if row and str(trust_device or "").strip() in {"1", "true", "on", "yes"}:
        trusted_token = create_trusted_device(conn, request, int(row["id"]))
        conn.commit()
    conn.close()
    complete_login_session(request, row)
    response = RedirectResponse(url="/dashboard", status_code=302)
    if trusted_token:
        response.set_cookie(
            TRUSTED_DEVICE_COOKIE,
            trusted_token,
            max_age=TRUSTED_DEVICE_DAYS * 24 * 60 * 60,
            httponly=True,
            secure=os.getenv("SESSION_SECURE", "true").lower() == "true",
            samesite="lax",
            path="/",
        )
    return response


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    cur.execute(
        """
        SELECT g.*,
               CASE WHEN g.organizer_id = ? THEN 1 ELSE 0 END AS is_owner
        FROM games g
        LEFT JOIN game_co_organizers c
               ON c.game_id = g.id AND c.user_id = ?
        WHERE g.organizer_id = ? OR c.user_id IS NOT NULL
        ORDER BY datetime(g.created_at) DESC
        """,
        (user_id, user_id, user_id),
    )
    games = cur.fetchall()
    conn.close()

    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "user": user, "games": games},
    )


@app.get("/profile", response_class=HTMLResponse)
def profile_view(request: Request):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, email, name, phone, phone_verified_at, mfa_enabled, totp_enabled, totp_secret FROM users WHERE id = ?",
        (user_id,),
    )
    user = cur.fetchone()
    conn.close()
    if not user:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "user": user,
            "error": None,
            "success": None,
            "totp_qr_svg": None,
            "totp_secret_preview": None,
        },
    )


@app.post("/profile", response_class=HTMLResponse)
def profile_update(
    request: Request,
    action: str = Form(...),
    current_password: str = Form(None),
    new_password: str = Form(None),
    confirm_password: str = Form(None),
    phone: str = Form(None),
    verification_code: str = Form(None),
    mfa_enabled: str = Form(None),
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, email, name, phone, phone_verified_at, mfa_enabled, password_hash, totp_enabled, totp_secret
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    )
    user = cur.fetchone()
    if not user:
        conn.close()
        request.session.clear()
        return RedirectResponse(url="/login", status_code=302)

    error = None
    success = None
    totp_qr_svg = None
    totp_secret_preview = None

    if action == "change_password":
        if not current_password or not pwd_context.verify(current_password, user["password_hash"]):
            error = "Current password is incorrect."
        elif not new_password or len(new_password) < 8 or len(new_password) > 128:
            error = "New password must be 8-128 characters."
        elif new_password != (confirm_password or ""):
            error = "Password confirmation does not match."
        else:
            cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pwd_context.hash(new_password), user_id))
            success = "Password updated."

    elif action == "update_phone":
        try:
            cleaned_phone = normalize_phone_10(phone)
        except ValueError:
            cleaned_phone = None
            error = "Invalid phone number."
        if not error:
            cur.execute("UPDATE users SET phone = ? WHERE id = ?", (cleaned_phone, user_id))
            success = "Phone updated."

    elif action == "set_mfa":
        enable = str(mfa_enabled or "").strip() == "1"
        has_totp = int(user["totp_enabled"] or 0) == 1 and bool((user["totp_secret"] or "").strip())
        if enable and not has_totp:
            error = "Set up your authenticator app before enabling MFA."
        else:
            cur.execute("UPDATE users SET mfa_enabled = ? WHERE id = ?", (1 if enable else 0, user_id))
            success = "MFA updated."
    elif action == "start_totp_enroll":
        secret = generate_totp_secret()
        request.session["pending_totp_secret"] = secret
        uri = build_totp_uri(user, secret)
        totp_qr_svg = build_totp_qr_svg(uri)
        totp_secret_preview = secret
        success = "Scan the QR code with your authenticator app, then enter the 6-digit code to confirm."
    elif action == "confirm_totp_enroll":
        secret = (request.session.get("pending_totp_secret") or "").strip()
        code = (verification_code or "").strip()
        if not secret:
            error = "Start authenticator setup first."
        elif not verify_totp_code(secret, code):
            error = "Invalid authenticator code."
            uri = build_totp_uri(user, secret)
            totp_qr_svg = build_totp_qr_svg(uri)
            totp_secret_preview = secret
        else:
            cur.execute(
                "UPDATE users SET totp_secret = ?, totp_enabled = 1, mfa_enabled = 1 WHERE id = ?",
                (secret, user_id),
            )
            request.session.pop("pending_totp_secret", None)
            success = "Authenticator app MFA enabled."
    elif action == "disable_totp":
        cur.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?", (user_id,))
        request.session.pop("pending_totp_secret", None)
        success = "Authenticator app MFA disabled."
    else:
        error = "Unknown profile action."

    conn.commit()
    cur.execute(
        "SELECT id, email, name, phone, phone_verified_at, mfa_enabled, totp_enabled, totp_secret FROM users WHERE id = ?",
        (user_id,),
    )
    fresh = cur.fetchone()
    conn.close()

    pending_secret = (request.session.get("pending_totp_secret") or "").strip()
    if not totp_qr_svg and pending_secret and not error and not success:
        uri = build_totp_uri(fresh or user, pending_secret)
        totp_qr_svg = build_totp_qr_svg(uri)
        totp_secret_preview = pending_secret
    elif not totp_secret_preview and pending_secret and totp_qr_svg:
        totp_secret_preview = pending_secret

    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "user": fresh,
            "error": error,
            "success": success,
            "totp_qr_svg": totp_qr_svg,
            "totp_secret_preview": totp_secret_preview,
        },
    )


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    if not require_admin(request):
        return RedirectResponse(url="/login", status_code=302)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT u.id, u.email, u.name, u.username, u.is_admin, u.is_disabled, u.mfa_enabled,
               (SELECT COUNT(*) FROM games g WHERE g.organizer_id = u.id) AS game_count
        FROM users u
        ORDER BY u.created_at DESC
        """
    )
    users = cur.fetchall()
    conn.close()
    return templates.TemplateResponse("admin.html", {"request": request, "users": users, "error": None, "success": None})


@app.post("/admin/users/{user_id}/disable")
def admin_disable_user(request: Request, user_id: int, csrf_token: str = Form(...)):
    if not require_admin(request):
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_disabled = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/users/{user_id}/enable")
def admin_enable_user(request: Request, user_id: int, csrf_token: str = Form(...)):
    if not require_admin(request):
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_disabled = 0 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/users/{user_id}/reset")
def admin_reset_user(request: Request, user_id: int, csrf_token: str = Form(...)):
    if not require_admin(request):
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    new_password = secrets.token_urlsafe(10)
    password_hash = pwd_context.hash(new_password)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
    conn.commit()
    # Re-render admin page with temp password
    cur.execute(
        """
        SELECT u.id, u.email, u.name, u.username, u.is_admin, u.is_disabled, u.mfa_enabled,
               (SELECT COUNT(*) FROM games g WHERE g.organizer_id = u.id) AS game_count
        FROM users u
        ORDER BY u.created_at DESC
        """
    )
    users = cur.fetchall()
    conn.close()
    return templates.TemplateResponse(
        "admin.html",
        {"request": request, "users": users, "error": None, "success": f"Temporary password: {new_password}"},
    )


@app.post("/admin/users/{user_id}/delete")
def admin_delete_user(request: Request, user_id: int, csrf_token: str = Form(...)):
    if not require_admin(request):
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    if user_id == current_user_id(request):
        return RedirectResponse(url="/admin", status_code=302)
    conn = get_db()
    cur = conn.cursor()
    # Delete games + related records
    cur.execute("SELECT id FROM games WHERE organizer_id = ?", (user_id,))
    game_ids = [row["id"] for row in cur.fetchall()]
    if game_ids:
        cur.execute("DELETE FROM game_co_organizers WHERE game_id IN (%s)" % ",".join("?" * len(game_ids)), game_ids)
        cur.execute("DELETE FROM rsvps WHERE game_id IN (%s)" % ",".join("?" * len(game_ids)), game_ids)
        cur.execute("DELETE FROM standby WHERE game_id IN (%s)" % ",".join("?" * len(game_ids)), game_ids)
        cur.execute("DELETE FROM games WHERE id IN (%s)" % ",".join("?" * len(game_ids)), game_ids)
    cur.execute("DELETE FROM game_co_organizers WHERE user_id = ?", (user_id,))
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=302)


@app.get("/games/new", response_class=HTMLResponse)
def new_game_form(request: Request):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    return templates.TemplateResponse("create_game.html", build_new_game_form_context(request, user_id))


def build_new_game_form_context(request: Request, user_id: int, error: Optional[str] = None) -> dict:
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM games WHERE organizer_id = ? ORDER BY created_at DESC LIMIT 1",
        (user_id,),
    )
    last_game = cur.fetchone()
    last_organizer_name = None
    last_organizer_phone = None
    if last_game:
        cur.execute(
            "SELECT name, phone FROM rsvps WHERE game_id = ? AND status = 'HOST' ORDER BY created_at ASC LIMIT 1",
            (last_game["id"],),
        )
        row = cur.fetchone()
        if row:
            last_organizer_name = row["name"]
            last_organizer_phone = row["phone"]

    cur.execute(
        """
        SELECT title
        FROM games
        WHERE organizer_id = ?
        GROUP BY title
        ORDER BY MAX(datetime(created_at)) DESC
        LIMIT 12
        """,
        (user_id,),
    )
    title_suggestions = [row["title"] for row in cur.fetchall() if row["title"]]

    cur.execute(
        """
        SELECT location
        FROM games
        WHERE organizer_id = ?
        GROUP BY location
        ORDER BY MAX(datetime(created_at)) DESC
        LIMIT 12
        """,
        (user_id,),
    )
    location_suggestions = [row["location"] for row in cur.fetchall() if row["location"]]

    cur.execute(
        """
        SELECT total_players
        FROM games
        WHERE organizer_id = ?
        GROUP BY total_players
        ORDER BY MAX(datetime(created_at)) DESC
        LIMIT 12
        """,
        (user_id,),
    )
    total_player_suggestions = [int(row["total_players"]) for row in cur.fetchall()]

    cur.execute(
        """
        SELECT r.name
        FROM rsvps r
        JOIN games g ON g.id = r.game_id
        WHERE g.organizer_id = ? AND r.status = 'HOST'
        GROUP BY r.name
        ORDER BY MAX(datetime(r.created_at)) DESC
        LIMIT 12
        """,
        (user_id,),
    )
    organizer_name_suggestions = [row["name"] for row in cur.fetchall() if row["name"]]
    invitee_lists = organizer_invitee_lists_with_members(conn, int(user_id))
    conn.close()
    default_game_date = thunder_bay_now().strftime("%Y-%m-%d")

    return {
        "request": request,
        "error": error,
        "last_game": last_game,
        "game_type_options": list(GAME_TYPE_OPTIONS.values()),
        "default_game_date": default_game_date,
        "last_organizer_name": last_organizer_name,
        "last_organizer_phone": last_organizer_phone,
        "title_suggestions": title_suggestions,
        "location_suggestions": location_suggestions,
        "total_player_suggestions": total_player_suggestions,
        "organizer_name_suggestions": organizer_name_suggestions,
        "invitee_lists": invitee_lists,
    }


@app.post("/games/new", response_class=HTMLResponse)
def new_game(
    request: Request,
    title: str = Form(...),
    location: str = Form(...),
    game_type: str = Form(None),
    game_date: str = Form(...),
    game_time: str = Form(...),
    total_players: int = Form(...),
    organizer_name: str = Form(...),
    organizer_phone: str = Form(None),
    co_organizers: str = Form(None),
    multiple_tables: str = Form(None),
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    if total_players < 1 or total_players > 100:
        return templates.TemplateResponse("create_game.html", build_new_game_form_context(request, user_id, "Total players must be at least 1."), status_code=400)

    now = datetime.utcnow().isoformat()

    try:
        cleaned_title = clean_text(title, 100)
        cleaned_location = clean_text(location, 120)
        cleaned_game_type = normalize_game_type(game_type)
        cleaned_game_time = normalize_game_time(game_time)
        cleaned_organizer = clean_text(organizer_name, 50)
    except ValueError:
        return templates.TemplateResponse("create_game.html", build_new_game_form_context(request, user_id, "Invalid title, location, or organizer name."), status_code=400)
    try:
        cleaned_organizer_phone = normalize_phone_10(organizer_phone)
    except ValueError:
        return templates.TemplateResponse("create_game.html", build_new_game_form_context(request, user_id, "Invalid organizer phone number."), status_code=400)
    conn = get_db()
    cur = conn.cursor()
    cleanup_old_games(conn, user_id)
    code = generate_code(conn=conn)
    host_code = generate_host_code(conn=conn)
    is_multiple_tables = 1 if str(multiple_tables or "").strip().lower() in {"1", "true", "on", "yes"} else 0
    cur.execute(
        """
        INSERT INTO games (organizer_id, code, host_code, title, game_type, location, game_date, game_time, total_players, multiple_tables, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, code, host_code, cleaned_title, cleaned_game_type, cleaned_location, game_date, cleaned_game_time, total_players, is_multiple_tables, now),
    )
    game_id = cur.lastrowid

    # Organizer counts as IN (HOST) with seat
    seat_number = None

    organizer_invitee_id = ensure_organizer_invitee(conn, int(user_id), cleaned_organizer_phone, cleaned_organizer)
    cur.execute(
        "INSERT INTO rsvps (game_id, invitee_id, name, phone, status, seat_number, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (game_id, organizer_invitee_id, cleaned_organizer, cleaned_organizer_phone, "HOST", seat_number, now),
    )

    if is_multiple_tables:
        raw_co_orgs = str(co_organizers or "").strip()
        if raw_co_orgs:
            raw_entries = [part.strip() for part in re.split(r"[,\n;]+", raw_co_orgs) if part and part.strip()]
            if len(raw_entries) > 20:
                conn.rollback()
                conn.close()
                return templates.TemplateResponse(
                    "create_game.html",
                    build_new_game_form_context(request, user_id, "Too many co-organizers. Maximum is 20."),
                    status_code=400,
                )

            co_org_user_ids = set()
            for raw_entry in raw_entries:
                try:
                    lookup_kind, lookup_value = parse_co_organizer_identifier(raw_entry)
                except ValueError as e:
                    conn.rollback()
                    conn.close()
                    return templates.TemplateResponse(
                        "create_game.html",
                        build_new_game_form_context(request, user_id, f"Invalid co-organizer: {str(e)}"),
                        status_code=400,
                    )

                if lookup_kind == "email":
                    cur.execute(
                        """
                        SELECT id, is_disabled
                        FROM users
                        WHERE LOWER(email) = ?
                        LIMIT 1
                        """,
                        (lookup_value,),
                    )
                else:
                    cur.execute(
                        """
                        SELECT id, is_disabled
                        FROM users
                        WHERE LOWER(COALESCE(username, '')) = ?
                        LIMIT 1
                        """,
                        (lookup_value,),
                    )
                target = cur.fetchone()
                if not target or int(target["is_disabled"] or 0) == 1:
                    conn.rollback()
                    conn.close()
                    return templates.TemplateResponse(
                        "create_game.html",
                        build_new_game_form_context(request, user_id, f"Co-organizer not found: {raw_entry}"),
                        status_code=400,
                    )
                target_id = int(target["id"])
                if target_id == int(user_id):
                    continue
                co_org_user_ids.add(target_id)

            for target_id in sorted(co_org_user_ids):
                cur.execute(
                    "INSERT OR IGNORE INTO game_co_organizers (game_id, user_id, invited_by, created_at) VALUES (?, ?, ?, ?)",
                    (game_id, target_id, int(user_id), now),
                )

    assign_seats_if_ready(conn, game_id, total_players)
    cur.execute("SELECT * FROM games WHERE id = ?", (game_id,))
    created_game = cur.fetchone()
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/games/{game_id}", status_code=302)


@app.get("/invitee-lists", response_class=HTMLResponse)
def invitee_lists_page(request: Request):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    conn = get_db()
    invitee_directory = organizer_invitee_directory(conn, int(user_id))
    lists = organizer_invitee_lists_with_members(conn, int(user_id))
    conn.close()
    return templates.TemplateResponse(
        "invitee_lists.html",
        {
            "request": request,
            "lists": lists,
            "invitee_directory": invitee_directory,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@app.get("/invitee-lists/{list_id}", response_class=HTMLResponse)
def invitee_list_detail_page(request: Request, list_id: int):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    conn = get_db()
    try:
        list_row = get_invitee_list_for_owner(conn, int(user_id), int(list_id))
        if not list_row:
            return RedirectResponse(url="/invitee-lists?error=List%20not%20found", status_code=302)
        all_lists = organizer_invitee_lists_with_members(conn, int(user_id))
        target = next((item for item in all_lists if int(item["id"]) == int(list_id)), None)
        invitee_directory = organizer_invitee_directory(conn, int(user_id))
        return templates.TemplateResponse(
            "invitee_list_detail.html",
            {
                "request": request,
                "invitee_list": target or dict(list_row),
                "invitee_directory": invitee_directory,
                "error": request.query_params.get("error"),
                "success": request.query_params.get("success"),
            },
        )
    finally:
        conn.close()


@app.get("/invitees", response_class=HTMLResponse)
def invitees_page(request: Request, q: str = ""):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    conn = get_db()
    invitees = organizer_invitee_directory(conn, int(user_id), q)
    conn.close()
    return templates.TemplateResponse(
        "invitees.html",
        {
            "request": request,
            "invitees": invitees,
            "query": (q or "").strip(),
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@app.post("/invitees")
def create_invitee_directory_entry(
    request: Request,
    name: str = Form(...),
    phone: str = Form(...),
    private_use_only: str = Form(None),
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    try:
        cleaned_name = clean_text(name, 50)
        cleaned_phone = normalize_phone_10(phone)
        if not cleaned_phone:
            raise ValueError("invalid phone")
    except ValueError:
        return RedirectResponse(url="/invitees?error=Invalid%20name%20or%20phone", status_code=302)
    conn = get_db()
    upsert_invitee_profiles(conn, int(user_id), cleaned_phone, cleaned_name)
    conn.commit()
    conn.close()
    return RedirectResponse(url="/invitees?success=Invitee%20saved", status_code=302)


@app.post("/invitees/{invitee_id}/update")
def update_invitee_directory_entry(
    request: Request,
    invitee_id: int,
    name: str = Form(...),
    phone: str = Form(...),
    q: str = Form(None),
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    query_suffix = f"?q={urllib.parse.quote((q or '').strip())}" if str(q or "").strip() else ""
    try:
        cleaned_name = clean_text(name, 50)
        cleaned_phone = normalize_phone_10(phone)
        if not cleaned_phone:
            raise ValueError("invalid phone")
    except ValueError:
        return RedirectResponse(url=f"/invitees{query_suffix}&error=Invalid%20name%20or%20phone" if query_suffix else "/invitees?error=Invalid%20name%20or%20phone", status_code=302)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM organizer_invitees WHERE id = ? AND organizer_id = ? LIMIT 1", (int(invitee_id), int(user_id)))
    row = cur.fetchone()
    if not row:
        conn.close()
        return RedirectResponse(url=f"/invitees{query_suffix}&error=Invitee%20not%20found" if query_suffix else "/invitees?error=Invitee%20not%20found", status_code=302)
    old_phone = row["phone"]
    now = _utc_now_iso()
    try:
        cur.execute(
            """
            UPDATE organizer_invitees
            SET name = ?, phone = ?, updated_at = ?, last_seen_at = ?
            WHERE id = ? AND organizer_id = ?
            """,
            (cleaned_name, cleaned_phone, now, now, int(invitee_id), int(user_id)),
        )
    except sqlite3.IntegrityError:
        conn.close()
        return RedirectResponse(url=f"/invitees{query_suffix}&error=That%20phone%20already%20exists%20in%20your%20directory" if query_suffix else "/invitees?error=That%20phone%20already%20exists%20in%20your%20directory", status_code=302)
    if cleaned_phone != old_phone:
        cur.execute(
            """
            SELECT m.id, m.list_id
            FROM organizer_invitee_list_members m
            JOIN organizer_invitee_lists l ON l.id = m.list_id
            WHERE l.organizer_id = ? AND m.phone = ?
            """,
            (int(user_id), old_phone),
        )
        affected_members = cur.fetchall()
        for member in affected_members:
            cur.execute(
                "SELECT id FROM organizer_invitee_list_members WHERE list_id = ? AND phone = ? LIMIT 1",
                (int(member["list_id"]), cleaned_phone),
            )
            existing = cur.fetchone()
            if existing:
                cur.execute(
                    "UPDATE organizer_invitee_list_members SET name = ?, updated_at = ? WHERE id = ?",
                    (cleaned_name, now, int(existing["id"])),
                )
                cur.execute("DELETE FROM organizer_invitee_list_members WHERE id = ?", (int(member["id"]),))
            else:
                cur.execute(
                    "UPDATE organizer_invitee_list_members SET phone = ?, name = ?, updated_at = ? WHERE id = ?",
                    (cleaned_phone, cleaned_name, now, int(member["id"])),
                )
    else:
        cur.execute(
            """
            UPDATE organizer_invitee_list_members
            SET name = ?, updated_at = ?
            WHERE phone = ?
              AND list_id IN (SELECT id FROM organizer_invitee_lists WHERE organizer_id = ?)
            """,
            (cleaned_name, now, cleaned_phone, int(user_id)),
        )
    conn.commit()
    conn.close()
    success_url = f"/invitees{query_suffix}&success=Invitee%20updated" if query_suffix else "/invitees?success=Invitee%20updated"
    if query_suffix and success_url.startswith("/invitees?"):
        success_url = success_url.replace("?q=", "?q=")
    return RedirectResponse(url=success_url, status_code=302)


@app.post("/invitees/{invitee_id}/delete")
def delete_invitee_directory_entry(request: Request, invitee_id: int, q: str = Form(None), csrf_token: str = Form(...)):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    query_suffix = f"?q={urllib.parse.quote((q or '').strip())}" if str(q or "").strip() else ""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT phone FROM organizer_invitees WHERE id = ? AND organizer_id = ? LIMIT 1", (int(invitee_id), int(user_id)))
    row = cur.fetchone()
    if not row:
        conn.close()
        return RedirectResponse(url=f"/invitees{query_suffix}&error=Invitee%20not%20found" if query_suffix else "/invitees?error=Invitee%20not%20found", status_code=302)
    cur.execute(
        """
        DELETE FROM organizer_invitee_list_members
        WHERE phone = ?
          AND list_id IN (SELECT id FROM organizer_invitee_lists WHERE organizer_id = ?)
        """,
        (row["phone"], int(user_id)),
    )
    cur.execute("DELETE FROM organizer_invitees WHERE id = ? AND organizer_id = ?", (int(invitee_id), int(user_id)))
    conn.commit()
    conn.close()
    success_url = f"/invitees{query_suffix}&success=Invitee%20deleted" if query_suffix else "/invitees?success=Invitee%20deleted"
    return RedirectResponse(url=success_url, status_code=302)


@app.post("/invitee-lists")
def create_invitee_list(request: Request, name: str = Form(...), csrf_token: str = Form(...)):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    try:
        cleaned_name = clean_text(name, 60)
    except ValueError:
        return RedirectResponse(url="/invitee-lists?error=Invalid%20list%20name", status_code=302)
    conn = get_db()
    cur = conn.cursor()
    try:
        now = _utc_now_iso()
        cur.execute(
            """
            INSERT INTO organizer_invitee_lists (organizer_id, name, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            (int(user_id), cleaned_name, now, now),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return RedirectResponse(url="/invitee-lists?error=List%20name%20already%20exists", status_code=302)
    conn.close()
    return RedirectResponse(url="/invitee-lists?success=List%20created", status_code=302)


@app.post("/invitee-lists/{list_id}/delete")
def delete_invitee_list(request: Request, list_id: int, csrf_token: str = Form(...)):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    conn = get_db()
    list_row = get_invitee_list_for_owner(conn, int(user_id), int(list_id))
    if not list_row:
        conn.close()
        return RedirectResponse(url="/invitee-lists?error=List%20not%20found", status_code=302)
    cur = conn.cursor()
    cur.execute("DELETE FROM organizer_invitee_list_members WHERE list_id = ?", (int(list_id),))
    cur.execute("DELETE FROM organizer_invitee_lists WHERE id = ?", (int(list_id),))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/invitee-lists?success=List%20deleted", status_code=302)


@app.post("/invitee-lists/{list_id}/members/add")
def add_invitee_list_member(
    request: Request,
    list_id: int,
    name: str = Form(None),
    phone: str = Form(None),
    private_use_only: str = Form(None),
    existing_phone: List[str] = Form(None),
    existing_name: List[str] = Form(None),
    return_to: str = Form(None),
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    redirect_base = f"/invitee-lists/{list_id}" if str(return_to or "").strip() == "detail" else "/invitee-lists"
    conn = get_db()
    list_row = get_invitee_list_for_owner(conn, int(user_id), int(list_id))
    if not list_row:
        conn.close()
        return RedirectResponse(url=f"{redirect_base}?error=List%20not%20found", status_code=302)
    selected_phones = [str(v or "").strip() for v in (existing_phone or []) if str(v or "").strip()]
    selected_names = [str(v or "").strip() for v in (existing_name or [])]
    now = _utc_now_iso()
    cur = conn.cursor()
    saved_count = 0
    try:
        if selected_phones:
            for idx, raw_phone in enumerate(selected_phones):
                raw_name = selected_names[idx] if idx < len(selected_names) else ""
                cleaned_name = clean_text(raw_name, 50)
                cleaned_phone = normalize_phone_10(raw_phone)
                if not cleaned_phone:
                    continue
                cur.execute(
                    """
                    INSERT INTO organizer_invitee_list_members (list_id, phone, name, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(list_id, phone) DO UPDATE SET
                        name = excluded.name,
                        updated_at = excluded.updated_at
                    """,
                    (int(list_id), cleaned_phone, cleaned_name, now, now),
                )
                upsert_invitee_profiles(conn, int(user_id), cleaned_phone, cleaned_name)
                saved_count += 1
        else:
            raw_name = (name or "").strip()
            raw_phone = (phone or "").strip()
            cleaned_name = clean_text(raw_name, 50)
            cleaned_phone = normalize_phone_10(raw_phone)
            if not cleaned_phone:
                conn.close()
                return RedirectResponse(url=f"{redirect_base}?error=Phone%20is%20required", status_code=302)
            cur.execute(
                """
                INSERT INTO organizer_invitee_list_members (list_id, phone, name, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(list_id, phone) DO UPDATE SET
                    name = excluded.name,
                    updated_at = excluded.updated_at
                """,
                (int(list_id), cleaned_phone, cleaned_name, now, now),
            )
            upsert_invitee_profiles(conn, int(user_id), cleaned_phone, cleaned_name)
            saved_count = 1
    except ValueError:
        conn.close()
        return RedirectResponse(url=f"{redirect_base}?error=Invalid%20member%20name%20or%20phone", status_code=302)
    cur.execute("UPDATE organizer_invitee_lists SET updated_at = ? WHERE id = ?", (now, int(list_id)))
    conn.commit()
    conn.close()
    if selected_phones:
        return RedirectResponse(url=f"{redirect_base}?success=Saved%20{saved_count}%20member(s)", status_code=302)
    return RedirectResponse(url=f"{redirect_base}?success=Member%20saved", status_code=302)


@app.post("/invitee-lists/{list_id}/members/{member_id}/remove")
def remove_invitee_list_member(request: Request, list_id: int, member_id: int, return_to: str = Form(None), csrf_token: str = Form(...)):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    redirect_base = f"/invitee-lists/{list_id}" if str(return_to or "").strip() == "detail" else "/invitee-lists"
    conn = get_db()
    list_row = get_invitee_list_for_owner(conn, int(user_id), int(list_id))
    if not list_row:
        conn.close()
        return RedirectResponse(url=f"{redirect_base}?error=List%20not%20found", status_code=302)
    cur = conn.cursor()
    cur.execute("DELETE FROM organizer_invitee_list_members WHERE id = ? AND list_id = ?", (int(member_id), int(list_id)))
    cur.execute("UPDATE organizer_invitee_lists SET updated_at = ? WHERE id = ?", (_utc_now_iso(), int(list_id)))
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"{redirect_base}?success=Member%20removed", status_code=302)


@app.get("/games/{game_id}", response_class=HTMLResponse)
def view_game(request: Request, game_id: int):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db()
    game, is_owner = get_game_for_manager(conn, game_id, user_id)
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)
    cur = conn.cursor()

    cur.execute("SELECT * FROM rsvps WHERE game_id = ? ORDER BY created_at ASC", (game_id,))
    rsvp_rows = cur.fetchall()
    push_enabled_phones = set()
    for row in rsvp_rows:
        phone = str(row["phone"] or "").strip()
        if not phone:
            continue
        if web_push_rows_for_invitee_phones(conn, [phone]):
            push_enabled_phones.add(phone)
    cur.execute("SELECT 1 FROM web_push_subscriptions WHERE disabled_at IS NULL AND user_id = ? LIMIT 1", (int(game["organizer_id"]),))
    organizer_push_enabled = cur.fetchone() is not None
    rsvps = []
    for row in rsvp_rows:
        rsvp = dict(row)
        rsvp["seat_label"] = seat_display(row["seat_number"], game["total_players"], game_uses_multiple_tables(game))
        rsvp["push_enabled"] = bool(
            (rsvp.get("phone") or "").strip() in push_enabled_phones
            or (str(rsvp.get("status") or "").upper() == "HOST" and organizer_push_enabled)
        )
        rsvps.append(rsvp)

    cur.execute("SELECT * FROM standby WHERE game_id = ? ORDER BY created_at ASC", (game_id,))
    standby = cur.fetchall()
    cur.execute(
        """
        SELECT u.id, u.name, u.email, u.username
        FROM game_co_organizers c
        JOIN users u ON u.id = c.user_id
        WHERE c.game_id = ?
        ORDER BY datetime(c.created_at) ASC, c.id ASC
        """,
        (game_id,),
    )
    co_organizers = cur.fetchall()
    cur.execute(
        """
        SELECT name, phone
        FROM organizer_invitees
        WHERE organizer_id = ?
        ORDER BY LOWER(name) ASC, datetime(last_seen_at) DESC
        LIMIT 300
        """,
        (int(game["organizer_id"]),),
    )
    invitee_directory = cur.fetchall()

    in_count = count_in(conn, game_id)
    host_name = game_host_name(conn, int(game["id"]), game["organizer_name"] if "organizer_name" in game.keys() else None)
    conn.close()

    return templates.TemplateResponse(
        "game_view.html",
        {
            "request": request,
            "game": game,
            "host_name": host_name,
            "rsvps": rsvps,
            "standby": standby,
            "in_count": in_count,
            "is_owner": is_owner,
            "co_organizers": co_organizers,
            "invitee_directory": invitee_directory,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@app.get("/games/{game_id}/snapshot")
def game_snapshot(request: Request, game_id: int):
    user_id = require_login(request)
    if not user_id:
        return PlainTextResponse("Unauthorized", status_code=401)

    conn = get_db()
    game, _ = get_game_for_manager(conn, game_id, user_id)
    if not game:
        conn.close()
        return PlainTextResponse("Not found", status_code=404)
    payload = game_snapshot_payload(conn, game)
    conn.close()
    return payload


@app.get("/games/{game_id}/events")
async def game_events(request: Request, game_id: int):
    user_id = require_login(request)
    if not user_id:
        return PlainTextResponse("Unauthorized", status_code=401)

    conn = get_db()
    game, _ = get_game_for_manager(conn, game_id, user_id)
    conn.close()
    if not game:
        return PlainTextResponse("Not found", status_code=404)

    async def event_generator():
        last_sig = None
        while True:
            if await request.is_disconnected():
                break
            loop_conn = get_db()
            try:
                game_row, _ = get_game_for_manager(loop_conn, game_id, user_id)
                if not game_row:
                    break
                payload = game_snapshot_payload(loop_conn, game_row)
            finally:
                loop_conn.close()
            sig = payload["signature"]
            if sig != last_sig:
                yield f"id: {sig}\nevent: refresh\ndata: {json.dumps({'signature': sig})}\n\n"
                last_sig = sig
            else:
                # Keep the stream alive even when no changes occurred.
                yield "event: ping\ndata: {}\n\n"
            await asyncio.sleep(3)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/games/{game_id}/delete")
def delete_game(request: Request, game_id: int, csrf_token: str = Form(...)):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    conn = get_db()
    game, is_owner = get_game_for_manager(conn, game_id, user_id)
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)
    if not is_owner:
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=Only%20the%20owner%20can%20delete%20this%20game", status_code=302)

    cur = conn.cursor()
    cur.execute("DELETE FROM game_co_organizers WHERE game_id = ?", (game_id,))
    cur.execute("DELETE FROM rsvps WHERE game_id = ?", (game_id,))
    cur.execute("DELETE FROM standby WHERE game_id = ?", (game_id,))
    cur.execute("DELETE FROM games WHERE id = ?", (game_id,))
    conn.commit()
    conn.close()

    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/games/{game_id}/cancel")
def cancel_game(request: Request, game_id: int, csrf_token: str = Form(...)):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    conn = get_db()
    game, is_owner = get_game_for_manager(conn, game_id, user_id)
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)
    if not is_owner:
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=Only%20the%20owner%20can%20cancel%20or%20reopen%20this%20game", status_code=302)

    cur = conn.cursor()
    is_cancelled = int(game["is_cancelled"] or 0) == 1
    if not is_cancelled:
        cur.execute(
            """
            UPDATE games
            SET is_cancelled = 1,
                cancelled_at = ?
            WHERE id = ?
            """,
            (datetime.utcnow().isoformat(), game_id),
        )
        cur.execute("SELECT * FROM games WHERE id = ?", (game_id,))
        updated_game = cur.fetchone() or game
        notify_game_cancelled_push(conn, updated_game)
        conn.commit()
        message = "Game%20cancelled"
    else:
        cur.execute(
            """
            UPDATE games
            SET is_cancelled = 0,
                cancelled_at = NULL
            WHERE id = ?
            """,
            (game_id,),
        )
        conn.commit()
        message = "Game%20reopened"
    conn.close()
    return RedirectResponse(url=f"/games/{game_id}?success={message}", status_code=302)


@app.post("/games/{game_id}/seats/assign")
def assign_game_seats_now(request: Request, game_id: int, csrf_token: str = Form(...)):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    conn = get_db()
    game, _ = get_game_for_manager(conn, game_id, user_id)
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)

    cur = conn.cursor()
    previous_seats = seat_map_for_game(conn, int(game_id), int(game["total_players"]), game_uses_multiple_tables(game))
    cur.execute("UPDATE games SET manual_seat_assignment = 1 WHERE id = ?", (game_id,))
    assign_seats_if_ready(conn, game_id, int(game["total_players"]))
    cur.execute("SELECT * FROM games WHERE id = ?", (game_id,))
    updated_game = cur.fetchone() or game
    notify_changed_seats_push(conn, updated_game, previous_seats)
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/games/{game_id}?success=Seats%20assigned", status_code=302)


@app.post("/games/{game_id}/details/update")
def update_game_details(
    request: Request,
    game_id: int,
    location: str = Form(...),
    game_type: str = Form(None),
    game_date: str = Form(...),
    game_time: str = Form(...),
    multiple_tables: str = Form(None),
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    try:
        cleaned_location = clean_text(location, 120)
        cleaned_game_type = normalize_game_type(game_type)
        cleaned_game_date = clean_text(game_date, 32)
        cleaned_game_time = normalize_game_time(game_time)
    except ValueError:
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20date,%20time,%20or%20address", status_code=302)

    conn = get_db()
    game, _ = get_game_for_manager(conn, game_id, user_id)
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)
    cur = conn.cursor()

    cur.execute(
        "UPDATE games SET location = ?, game_type = ?, game_date = ?, game_time = ?, multiple_tables = ? WHERE id = ?",
        (
            cleaned_location,
            cleaned_game_type,
            cleaned_game_date,
            cleaned_game_time,
            1 if str(multiple_tables or "").strip().lower() in {"1", "true", "on", "yes"} else 0,
            game_id,
        ),
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/games/{game_id}?success=Game%20details%20updated", status_code=302)


@app.post("/games/{game_id}/rsvp/{rsvp_id}/update")
def update_rsvp(
    request: Request,
    game_id: int,
    rsvp_id: int,
    name: str = Form(...),
    status: str = Form(...),
    late_eta: str = Form(None),
    phone: str = Form(None),
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    status = status.upper().strip()
    if status not in {"IN", "LATE", "OUT", "HOST"}:
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20status", status_code=302)

    try:
        cleaned_name = clean_text(name, 50)
    except ValueError:
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20name", status_code=302)

    conn = get_db()
    game, _ = get_game_for_manager(conn, game_id, user_id)
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)
    cur = conn.cursor()

    cur.execute("SELECT * FROM rsvps WHERE id = ? AND game_id = ?", (rsvp_id, game_id))
    rsvp = cur.fetchone()
    if not rsvp:
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=RSVP%20not%20found", status_code=302)

    # Prevent duplicate names in same game
    cur.execute(
        "SELECT id FROM rsvps WHERE game_id = ? AND LOWER(name) = LOWER(?) AND id != ?",
        (game_id, cleaned_name, rsvp_id),
    )
    if cur.fetchone():
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=Name%20already%20exists", status_code=302)

    previous_status = (rsvp["status"] or "").upper()
    new_seat = rsvp["seat_number"]
    if status == "OUT":
        new_seat = None

    try:
        cleaned_phone = normalize_phone_10(phone)
    except ValueError:
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20phone%20number", status_code=302)
    if cleaned_phone:
        cur.execute(
            "SELECT id FROM rsvps WHERE game_id = ? AND phone = ? AND id != ? LIMIT 1",
            (game_id, cleaned_phone, rsvp_id),
        )
        if cur.fetchone():
            conn.close()
            return RedirectResponse(url=f"/games/{game_id}?error=Phone%20already%20exists%20for%20another%20invitee", status_code=302)
    if not cleaned_phone:
        profile_by_name = lookup_unique_invitee_profile_by_name(conn, int(game["organizer_id"]), cleaned_name)
        if profile_by_name:
            cleaned_phone = profile_by_name["phone"]
        else:
            conn.close()
            return RedirectResponse(url=f"/games/{game_id}?error=Phone%20required%20for%20new%20invitees", status_code=302)
    invitee_id = ensure_organizer_invitee(conn, int(game["organizer_id"]), cleaned_phone, cleaned_name)
    cur.execute(
        "UPDATE rsvps SET invitee_id = COALESCE(?, invitee_id), name = ?, phone = ?, status = ?, late_eta = ?, seat_number = ? WHERE id = ?",
        (invitee_id, cleaned_name, cleaned_phone, status, (late_eta or "").strip() or None, new_seat, rsvp_id),
    )
    upsert_invitee_profiles(conn, int(game["organizer_id"]), cleaned_phone, cleaned_name)
    assign_seats_if_ready(conn, game_id, game["total_players"])
    maybe_notify_organizer_when_out(conn, game, previous_status, status, cleaned_name)
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/games/{game_id}?success=Updated", status_code=302)


@app.post("/games/{game_id}/rsvp/add")
def add_rsvp(
    request: Request,
    game_id: int,
    name: str = Form(...),
    phone: str = Form(None),
    status: str = Form(...),
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    status = status.upper().strip()
    if status not in {"IN", "LATE", "OUT"}:
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20status", status_code=302)

    try:
        cleaned_name = clean_text(name, 50)
    except ValueError:
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20name", status_code=302)

    conn = get_db()
    game, _ = get_game_for_manager(conn, game_id, user_id)
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)
    cur = conn.cursor()

    cur.execute(
        "SELECT id FROM rsvps WHERE game_id = ? AND LOWER(name) = LOWER(?)",
        (game_id, cleaned_name),
    )
    if cur.fetchone():
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=Name%20already%20exists", status_code=302)

    total_players = int(game["total_players"])
    if status in {"IN", "LATE"} and count_in(conn, game_id) >= total_players:
        total_players += 1
        cur.execute("UPDATE games SET total_players = ? WHERE id = ?", (total_players, game_id))

    seat_number = None

    try:
        cleaned_phone = normalize_phone_10(phone)
    except ValueError:
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20phone%20number", status_code=302)
    if not cleaned_phone:
        profile_by_name = lookup_unique_invitee_profile_by_name(conn, int(game["organizer_id"]), cleaned_name)
        if profile_by_name:
            cleaned_phone = profile_by_name["phone"]
        else:
            conn.close()
            return RedirectResponse(url=f"/games/{game_id}?error=Phone%20required%20for%20new%20invitees", status_code=302)
    existing_by_phone = None
    if cleaned_phone:
        cur.execute(
            "SELECT * FROM rsvps WHERE game_id = ? AND phone = ? ORDER BY id DESC LIMIT 1",
            (game_id, cleaned_phone),
        )
        existing_by_phone = cur.fetchone()
    now = datetime.utcnow().isoformat()
    invitee_id = ensure_organizer_invitee(conn, int(game["organizer_id"]), cleaned_phone, cleaned_name)
    if existing_by_phone:
        current_seat = existing_by_phone["seat_number"]
        new_seat = None if status == "OUT" else current_seat
        cur.execute(
            """
            UPDATE rsvps
            SET invitee_id = COALESCE(?, invitee_id), name = ?, status = ?, late_eta = ?, seat_number = ?, created_at = ?
            WHERE id = ?
            """,
            (invitee_id, cleaned_name, status, None, new_seat, now, int(existing_by_phone["id"])),
        )
    else:
        cur.execute(
            "INSERT INTO rsvps (game_id, invitee_id, name, phone, status, late_eta, seat_number, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (game_id, invitee_id, cleaned_name, cleaned_phone, status, None, seat_number, now),
        )
    upsert_invitee_profiles(conn, int(game["organizer_id"]), cleaned_phone, cleaned_name)
    assign_seats_if_ready(conn, game_id, total_players)
    cur.execute("SELECT * FROM games WHERE id = ?", (game_id,))
    updated_game = cur.fetchone() or game
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/games/{game_id}?success=Added", status_code=302)


@app.post("/games/{game_id}/standby/{standby_id}/promote")
def promote_standby(
    request: Request,
    game_id: int,
    standby_id: int,
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    conn = get_db()
    game, _ = get_game_for_manager(conn, game_id, user_id)
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)
    cur = conn.cursor()

    cur.execute("SELECT * FROM standby WHERE id = ? AND game_id = ?", (standby_id, game_id))
    standby_row = cur.fetchone()
    if not standby_row:
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=Standby%20not%20found", status_code=302)

    try:
        cleaned_name = clean_text(standby_row["name"], 50)
    except ValueError:
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20name", status_code=302)

    cur.execute(
        "SELECT id FROM rsvps WHERE game_id = ? AND LOWER(name) = LOWER(?)",
        (game_id, cleaned_name),
    )
    if cur.fetchone():
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=Name%20already%20exists", status_code=302)

    total_players = int(game["total_players"])
    if count_in(conn, game_id) >= total_players:
        total_players += 1
        cur.execute("UPDATE games SET total_players = ? WHERE id = ?", (total_players, game_id))

    seat_number = None

    now = datetime.utcnow().isoformat()
    invitee_id = ensure_organizer_invitee(conn, int(game["organizer_id"]), standby_row["phone"], cleaned_name)
    cur.execute(
        "INSERT INTO rsvps (game_id, invitee_id, name, phone, status, late_eta, seat_number, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (game_id, invitee_id, cleaned_name, standby_row["phone"], "IN", None, seat_number, now),
    )
    upsert_invitee_profiles(conn, int(game["organizer_id"]), standby_row["phone"], cleaned_name)
    assign_seats_if_ready(conn, game_id, total_players)
    cur.execute("SELECT * FROM games WHERE id = ?", (game_id,))
    updated_game = cur.fetchone() or game
    cur.execute("DELETE FROM standby WHERE id = ?", (standby_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/games/{game_id}?success=Moved%20to%20IN", status_code=302)


@app.post("/games/{game_id}/co-organizers/add")
def add_co_organizer(
    request: Request,
    game_id: int,
    identifier: str = Form(...),
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    conn = get_db()
    game, _ = get_game_for_manager(conn, game_id, user_id)
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)
    if not game_uses_multiple_tables(game):
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=Co-organizers%20can%20only%20be%20added%20in%20Multiple%20Table%20Mode", status_code=302)

    try:
        lookup_kind, lookup_value = parse_co_organizer_identifier(identifier)
    except ValueError as e:
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error={urllib.parse.quote(str(e))}", status_code=302)

    cur = conn.cursor()
    if lookup_kind == "email":
        cur.execute(
            """
            SELECT id, email, username, name, is_disabled
            FROM users
            WHERE LOWER(email) = ?
            LIMIT 1
            """,
            (lookup_value,),
        )
    else:
        cur.execute(
            """
            SELECT id, email, username, name, is_disabled
            FROM users
            WHERE LOWER(COALESCE(username, '')) = ?
            LIMIT 1
            """,
            (lookup_value,),
        )
    target = cur.fetchone()
    if not target or int(target["is_disabled"] or 0) == 1:
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=Organizer%20account%20not%20found", status_code=302)
    if int(target["id"]) == int(user_id):
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=You%20already%20have%20access%20to%20this%20game", status_code=302)
    if int(target["id"]) == int(game["organizer_id"]):
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=That%20account%20already%20owns%20this%20game", status_code=302)

    cur.execute("SELECT 1 FROM game_co_organizers WHERE game_id = ? AND user_id = ?", (game_id, int(target["id"])))
    if cur.fetchone():
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=That%20co-organizer%20is%20already%20added", status_code=302)

    cur.execute(
        "INSERT INTO game_co_organizers (game_id, user_id, invited_by, created_at) VALUES (?, ?, ?, ?)",
        (game_id, int(target["id"]), int(user_id), datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/games/{game_id}?success=Co-organizer%20added", status_code=302)


@app.get("/game", response_class=HTMLResponse)
def game_by_query(request: Request, g: Optional[str] = None):
    if not g:
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "Missing game code."},
            status_code=404,
        )
    return RedirectResponse(url=f"/g/{g}", status_code=302)


@app.get("/g/{code}", response_class=HTMLResponse)
def game_by_code(request: Request, code: str):
    user_id = current_user_id(request)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE code = ?", (code,))
    game = cur.fetchone()
    if not game:
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "Game not found."},
            status_code=404,
        )

    if is_game_cancelled(game):
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "This game has been cancelled."},
            status_code=404,
        )

    if is_game_expired(game):
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "This game has expired."},
            status_code=404,
        )

    # If game manager opens invite link while logged in, send to organizer view
    can_manage = False
    if user_id:
        can_manage = game_is_owner(game, user_id) or user_is_game_co_organizer(conn, int(game["id"]), user_id)
    if can_manage:
        conn.close()
        return RedirectResponse(url=f"/games/{game['id']}", status_code=302)

    in_count = count_in(conn, game["id"])
    cur.execute("SELECT name FROM rsvps WHERE game_id = ? AND status = 'HOST' ORDER BY created_at ASC LIMIT 1", (game["id"],))
    host_row = cur.fetchone()
    host_name = host_row["name"] if host_row else None
    cur.execute("SELECT name FROM rsvps WHERE game_id = ? AND status = 'IN' ORDER BY created_at ASC", (game["id"],))
    in_players = [row["name"] for row in cur.fetchall()]
    cur.execute("SELECT name FROM rsvps WHERE game_id = ? AND status = 'LATE' ORDER BY created_at ASC", (game["id"],))
    late_players = [row["name"] for row in cur.fetchall()]
    cur.execute("SELECT name FROM rsvps WHERE game_id = ? AND status = 'OUT' ORDER BY created_at ASC", (game["id"],))
    out_players = [row["name"] for row in cur.fetchall()]
    cur.execute("SELECT COUNT(*) AS c FROM rsvps WHERE game_id = ? AND status = 'OUT'", (game["id"],))
    out_count = int(cur.fetchone()["c"])
    roster_players = invitee_roster_payload(conn, game)
    invitee_token_seed = normalize_invitee_token(request.cookies.get(INVITEE_TOKEN_COOKIE))
    conn.close()

    if in_count >= game["total_players"]:
        return templates.TemplateResponse(
            "game_full.html",
            {
                "request": request,
                "game": game,
                "title": "RSVP Here",
                "verify_required": False,
                "roster_players": roster_players,
                "invitee_token_seed": invitee_token_seed,
            },
        )

    return templates.TemplateResponse(
        "game.html",
        {
            "request": request,
            "title": "RSVP Here",
            "game": game,
            "in_count": in_count,
            "in_players": in_players,
            "late_players": late_players,
            "host_name": host_name,
            "out_count": out_count,
            "out_players": out_players,
            "roster_players": roster_players,
            "verify_required": False,
            "invitee_token_seed": invitee_token_seed,
        },
    )


@app.get("/h/{host_code}", response_class=HTMLResponse)
def host_view(request: Request, host_code: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE host_code = ?", (host_code,))
    game = cur.fetchone()
    if not game:
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "Roster link not found."},
            status_code=404,
        )
    if is_game_cancelled(game):
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "This game has been cancelled."},
            status_code=404,
        )
    if is_game_expired(game):
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "This game has expired."},
            status_code=404,
        )
    payload = host_snapshot_payload(conn, game)
    conn.close()
    return templates.TemplateResponse(
        "host_view.html",
        {
            "request": request,
            "game": game,
            "players": payload["players"],
            "in_count": payload["in_count"],
            "late_count": payload["late_count"],
        },
    )


@app.get("/h/{host_code}/snapshot")
def host_snapshot(host_code: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE host_code = ?", (host_code,))
    game = cur.fetchone()
    if not game or is_game_cancelled(game) or is_game_expired(game):
        conn.close()
        return PlainTextResponse("Not found", status_code=404)
    payload = host_snapshot_payload(conn, game)
    conn.close()
    return payload


@app.post("/g/{code}/rsvp", response_class=HTMLResponse)
def rsvp_game(
    request: Request,
    code: str,
    name: str = Form(...),
    phone: str = Form(None),
    status: str = Form(...),
    late_eta: str = Form(None),
    verification_code: str = Form(None),
    rsvp_token: str = Form(None),
    invitee_token: str = Form(None),
    csrf_token: str = Form(...),
):
    status = status.upper().strip()
    if status not in {"IN", "OUT", "LATE"}:
        return RedirectResponse(url=f"/g/{code}", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE code = ?", (code,))
    game = cur.fetchone()
    if not game:
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "Game not found."},
            status_code=404,
        )
    if is_game_cancelled(game):
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "This game has been cancelled."},
            status_code=404,
        )

    try:
        cleaned_name = clean_text(name, 50)
    except ValueError:
        return RedirectResponse(url=f"/g/{code}", status_code=302)
    try:
        cleaned_phone = normalize_phone_10(phone)
    except ValueError:
        return RedirectResponse(url=f"/g/{code}?error=Invalid%20phone%20number", status_code=302)
    cleaned_eta = (late_eta or "").strip() or None
    cleaned_token = normalize_rsvp_token(rsvp_token)
    cleaned_invitee_token = normalize_invitee_token(invitee_token)
    now = datetime.utcnow().isoformat()
    if not cleaned_phone:
        profile_by_name = lookup_unique_invitee_profile_by_name(conn, int(game["organizer_id"]), cleaned_name)
        if profile_by_name:
            cleaned_phone = profile_by_name["phone"]
    if not cleaned_phone:
        conn.close()
        return RedirectResponse(url=f"/g/{code}?error=Phone%20number%20required", status_code=302)
    invitee_id = ensure_organizer_invitee(conn, int(game["organizer_id"]), cleaned_phone, cleaned_name)
    previous_seats = seat_map_for_game(conn, int(game["id"]), int(game["total_players"]), game_uses_multiple_tables(game))
    was_full = count_in(conn, int(game["id"])) >= int(game["total_players"])

    existing = None
    if invitee_id:
        cur.execute(
            "SELECT id, status, seat_number FROM rsvps WHERE game_id = ? AND invitee_id = ? ORDER BY id DESC LIMIT 1",
            (game["id"], invitee_id),
        )
        existing = cur.fetchone()
    if cleaned_phone:
        if not existing:
            cur.execute(
                "SELECT id, status, seat_number FROM rsvps WHERE game_id = ? AND phone = ? ORDER BY id DESC LIMIT 1",
                (game["id"], cleaned_phone),
            )
            existing = cur.fetchone()
    if cleaned_token:
        if not existing:
            cur.execute(
                "SELECT id, status, seat_number FROM rsvps WHERE game_id = ? AND rsvp_token = ?",
                (game["id"], cleaned_token),
            )
            existing = cur.fetchone()
    if not existing:
        cur.execute(
            "SELECT id, status, seat_number FROM rsvps WHERE game_id = ? AND LOWER(name) = LOWER(?)",
            (game["id"], cleaned_name),
        )
        existing = cur.fetchone()
    existing_status = (existing["status"] or "").upper() if existing else ""
    already_active = existing_status in {"HOST", "IN", "LATE"}
    if status in {"IN", "LATE"} and not already_active and count_in(conn, game["id"]) >= game["total_players"]:
        roster_players = invitee_roster_payload(conn, game)
        conn.close()
        return templates.TemplateResponse(
            "game_full.html",
            {
                "request": request,
                "game": game,
                "verify_required": False,
                "roster_players": roster_players,
                "invitee_token_seed": cleaned_invitee_token,
            },
        )

    rsvp_id = None
    previous_status = None
    if existing:
        previous_status = (existing["status"] or "").upper()
        cur.execute(
            "SELECT id FROM rsvps WHERE game_id = ? AND LOWER(name) = LOWER(?) AND id != ?",
            (game["id"], cleaned_name, existing["id"]),
        )
        if cur.fetchone():
            conn.close()
            return RedirectResponse(url=f"/g/{code}?error=Name%20already%20exists", status_code=302)
        current_seat = existing["seat_number"]
        new_seat = current_seat
        if status == "OUT":
            new_seat = None
        cur.execute(
            """
            UPDATE rsvps
            SET invitee_id = COALESCE(?, invitee_id), name = ?, phone = ?, status = ?, late_eta = ?, seat_number = ?, created_at = ?, rsvp_token = COALESCE(rsvp_token, ?)
            WHERE id = ?
            """,
            (invitee_id, cleaned_name, cleaned_phone, status, cleaned_eta, new_seat, now, cleaned_token, existing["id"]),
        )
        rsvp_id = int(existing["id"])
    else:
        new_seat = None
        cur.execute(
            """
            INSERT INTO rsvps (game_id, invitee_id, name, phone, status, late_eta, seat_number, created_at, rsvp_token)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (game["id"], invitee_id, cleaned_name, cleaned_phone, status, cleaned_eta, new_seat, now, cleaned_token),
        )
        rsvp_id = int(cur.lastrowid)
    assign_seats_if_ready(conn, game["id"], game["total_players"])
    cur.execute("SELECT seat_number FROM rsvps WHERE id = ?", (rsvp_id,))
    seat_row = cur.fetchone()
    seat_to_show = seat_row["seat_number"] if seat_row else None
    table_label, seat_in_table = seat_assignment(seat_to_show, game["total_players"], game_uses_multiple_tables(game))
    seat_label = seat_display(seat_to_show, game["total_players"], game_uses_multiple_tables(game))
    issued_invitee_token = None
    if cleaned_phone:
        upsert_invitee_profiles(conn, int(game["organizer_id"]), cleaned_phone, cleaned_name)
        issued_invitee_token = ensure_invitee_token_for_phone(conn, cleaned_phone, cleaned_invitee_token)
    is_full = count_in(conn, int(game["id"])) >= int(game["total_players"])
    if (not existing) or previous_status != status or (status == "LATE" and cleaned_eta):
        notify_rsvp_status_push(conn, game, cleaned_name, status, cleaned_eta)
    if not was_full and is_full:
        notify_game_full_push(conn, game)
    notify_changed_seats_push(conn, game, previous_seats)
    conn.commit()
    conn.close()

    return templates.TemplateResponse(
        "rsvp_thanks.html",
        {
            "request": request,
            "game": game,
            "status": status,
            "late_eta": late_eta,
            "seat_number": seat_to_show,
            "table_label": table_label,
            "seat_in_table": seat_in_table,
            "seat_label": seat_label,
            "invitee_token": issued_invitee_token or cleaned_invitee_token,
        },
    )


@app.post("/g/{code}/contact")
def lookup_contact(
    request: Request,
    code: str,
    name: str = Form(None),
    phone: str = Form(None),
    rsvp_token: str = Form(None),
    invitee_token: str = Form(None),
    csrf_token: str = Form(...),
):
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    cleaned_token = normalize_rsvp_token(rsvp_token)
    cleaned_invitee_token = normalize_invitee_token(invitee_token)
    try:
        cleaned_phone = normalize_phone_10(phone)
    except ValueError:
        cleaned_phone = None
    cleaned_name = None
    if not cleaned_token and name is not None:
        try:
            cleaned_name = clean_text(name, 50)
        except ValueError:
            cleaned_name = None

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE code = ?", (code,))
    game = cur.fetchone()
    if not game or is_game_cancelled(game) or is_game_expired(game):
        conn.close()
        return {"phone": None, "name": None, "invitee_token": cleaned_invitee_token}

    token_phone = lookup_phone_by_invitee_token(conn, cleaned_invitee_token)
    chosen_phone = token_phone or cleaned_phone
    profile_row = lookup_invitee_profile(conn, int(game["organizer_id"]), chosen_phone) if chosen_phone else None
    if not profile_row and cleaned_name:
        profile_row = lookup_unique_invitee_profile_by_name(conn, int(game["organizer_id"]), cleaned_name)
    row = None
    if not profile_row:
        if cleaned_token:
            cur.execute(
                "SELECT phone, name FROM rsvps WHERE game_id = ? AND rsvp_token = ? LIMIT 1",
                (game["id"], cleaned_token),
            )
            row = cur.fetchone()
        elif cleaned_name:
            cur.execute(
                "SELECT phone, name FROM rsvps WHERE game_id = ? AND LOWER(name) = LOWER(?) LIMIT 1",
                (game["id"], cleaned_name),
            )
            row = cur.fetchone()

    effective_phone = (profile_row["phone"] if profile_row else (row["phone"] if row and row["phone"] else chosen_phone))
    effective_name = (profile_row["name"] if profile_row else (row["name"] if row and row["name"] else None))
    effective_invitee_id = int(profile_row["id"]) if profile_row and profile_row["id"] else None
    response_status = None
    response_rsvp_id = None
    response_seat_label = None

    status_row = None
    if effective_invitee_id:
        cur.execute(
            """
            SELECT id, status, seat_number
            FROM rsvps
            WHERE game_id = ? AND invitee_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (int(game["id"]), effective_invitee_id),
        )
        status_row = cur.fetchone()
    if effective_phone:
        if not status_row:
            cur.execute(
                """
                SELECT id, status, seat_number
                FROM rsvps
                WHERE game_id = ? AND phone = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (int(game["id"]), effective_phone),
            )
            status_row = cur.fetchone()
    if not status_row and cleaned_token:
        cur.execute(
            """
            SELECT id, status, seat_number
            FROM rsvps
            WHERE game_id = ? AND rsvp_token = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (int(game["id"]), cleaned_token),
        )
        status_row = cur.fetchone()
    if not status_row and effective_name:
        cur.execute(
            """
            SELECT id, status, seat_number
            FROM rsvps
            WHERE game_id = ? AND LOWER(name) = LOWER(?)
            ORDER BY id DESC
            LIMIT 1
            """,
            (int(game["id"]), effective_name),
        )
        status_row = cur.fetchone()
    if status_row:
        response_status = (status_row["status"] or "").upper() or None
        response_rsvp_id = int(status_row["id"])
        response_seat_label = seat_display(status_row["seat_number"], game["total_players"], game_uses_multiple_tables(game))
    issued_invitee_token = cleaned_invitee_token
    if effective_phone:
        upsert_invitee_profiles(conn, int(game["organizer_id"]), effective_phone, effective_name)
        issued_invitee_token = ensure_invitee_token_for_phone(conn, effective_phone, cleaned_invitee_token)
    conn.commit()
    conn.close()
    return {
        "phone": effective_phone,
        "name": effective_name,
        "invitee_token": issued_invitee_token,
        "verified": False,
        "response_status": response_status,
        "response_rsvp_id": response_rsvp_id,
        "response_seat_label": response_seat_label,
    }


@app.post("/g/{code}/standby", response_class=HTMLResponse)
def standby_game(
    request: Request,
    code: str,
    name: str = Form(...),
    phone: str = Form(None),
    verification_code: str = Form(None),
    invitee_token: str = Form(None),
    csrf_token: str = Form(...),
):
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE code = ?", (code,))
    game = cur.fetchone()
    if not game:
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "Game not found."},
            status_code=404,
        )
    if is_game_cancelled(game):
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "This game has been cancelled."},
            status_code=404,
        )

    try:
        cleaned_name = clean_text(name, 50)
    except ValueError:
        return RedirectResponse(url=f"/g/{code}", status_code=302)
    try:
        cleaned_phone = normalize_phone_10(phone)
    except ValueError:
        return RedirectResponse(url=f"/g/{code}?error=Invalid%20phone%20number", status_code=302)
    cleaned_invitee_token = normalize_invitee_token(invitee_token)
    if not cleaned_phone:
        profile_by_name = lookup_unique_invitee_profile_by_name(conn, int(game["organizer_id"]), cleaned_name)
        if profile_by_name:
            cleaned_phone = profile_by_name["phone"]
    invitee_id = ensure_organizer_invitee(conn, int(game["organizer_id"]), cleaned_phone, cleaned_name)
    existing_active = None
    if invitee_id:
        cur.execute(
            """
            SELECT id, status, seat_number
            FROM rsvps
            WHERE game_id = ? AND invitee_id = ? AND status IN ('HOST', 'IN', 'LATE')
            ORDER BY id DESC
            LIMIT 1
            """,
            (int(game["id"]), int(invitee_id)),
        )
        existing_active = cur.fetchone()
    if not existing_active and cleaned_phone:
        cur.execute(
            """
            SELECT id, status, seat_number
            FROM rsvps
            WHERE game_id = ? AND phone = ? AND status IN ('HOST', 'IN', 'LATE')
            ORDER BY id DESC
            LIMIT 1
            """,
            (int(game["id"]), cleaned_phone),
        )
        existing_active = cur.fetchone()
    if not existing_active:
        cur.execute(
            """
            SELECT id, status, seat_number
            FROM rsvps
            WHERE game_id = ? AND LOWER(name) = LOWER(?) AND status IN ('HOST', 'IN', 'LATE')
            ORDER BY id DESC
            LIMIT 1
            """,
            (int(game["id"]), cleaned_name),
        )
        existing_active = cur.fetchone()
    if existing_active:
        issued_invitee_token = None
        if cleaned_phone:
            upsert_invitee_profiles(conn, int(game["organizer_id"]), cleaned_phone, cleaned_name)
            issued_invitee_token = ensure_invitee_token_for_phone(conn, cleaned_phone, cleaned_invitee_token)
        conn.commit()
        conn.close()
        seat_number = existing_active["seat_number"]
        table_label, seat_in_table = seat_assignment(seat_number, game["total_players"], game_uses_multiple_tables(game))
        seat_label = seat_display(seat_number, game["total_players"], game_uses_multiple_tables(game))
        return templates.TemplateResponse(
            "rsvp_thanks.html",
            {
                "request": request,
                "game": game,
                "status": existing_active["status"],
                "late_eta": None,
                "seat_number": seat_number,
                "table_label": table_label,
                "seat_in_table": seat_in_table,
                "seat_label": seat_label,
                "invitee_token": issued_invitee_token or cleaned_invitee_token,
            },
        )
    cur.execute(
        "INSERT INTO standby (game_id, invitee_id, name, phone, created_at) VALUES (?, ?, ?, ?, ?)",
        (game["id"], invitee_id, cleaned_name, cleaned_phone, datetime.utcnow().isoformat()),
    )
    cur.execute("SELECT COUNT(*) AS c FROM standby WHERE game_id = ?", (game["id"],))
    position = int(cur.fetchone()["c"])
    issued_invitee_token = None
    if cleaned_phone:
        upsert_invitee_profiles(conn, int(game["organizer_id"]), cleaned_phone, cleaned_name)
        issued_invitee_token = ensure_invitee_token_for_phone(conn, cleaned_phone, cleaned_invitee_token)
    conn.commit()
    conn.close()

    return templates.TemplateResponse(
        "standby_thanks.html",
        {"request": request, "game": game, "position": position, "invitee_token": issued_invitee_token or cleaned_invitee_token},
    )
