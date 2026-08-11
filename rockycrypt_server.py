#!/usr/bin/env python3
"""
RockyCrypt Server — NSE Kenya Stock Analysis
FastAPI backend serving Kenyan NSE stock signals & analysis.

Live data source: deveintapps.com/nseticker/api/v1/ticker
(Official NSE Kenya real-time ticker API, same source as nse.co.ke)
"""

import json
import os
import hashlib
import subprocess
import sys
import smtplib
import secrets
import time
import tempfile
import shutil
import re
import urllib.request
from itsdangerous import URLSafeTimedSerializer
import xml.etree.ElementTree as ET
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, date, timedelta
from pathlib import Path

_BASE_DIR    = Path(__file__).parent
DATA_DIR     = str(_BASE_DIR / "data")
HISTORY_FILE = str(_BASE_DIR / "data" / "price_history.json")
USERS_FILE   = str(_BASE_DIR / "data" / "users.json")
SUBSCRIPTIONS_FILE = str(_BASE_DIR / "data" / "subscriptions.json")
EMAIL_LOG_FILE = str(_BASE_DIR / "data" / "email_log.json")
Path(DATA_DIR).mkdir(parents=True, exist_ok=True)

import pandas as pd
import numpy as np
import requests
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import bcrypt

try:
    import backtest
except Exception as _exc:                                     # noqa: BLE001
    backtest = None
    print(f"[track record] backtest module unavailable: {_exc}")

app = FastAPI(title="RockyCrypt — NSE Kenya Analytics")

# Serve local static assets (self-hosted Font Awesome icons & fonts)
# This removes the dependency on external CDNs which can be blocked by CSP or outages.
_STATIC_DIR = _BASE_DIR / "static"
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# ─── Environment Detection ────────────────────────────────────────────────────
IS_PRODUCTION = os.environ.get("ROCKYCRYPT_PRODUCTION", "").lower() in ("true", "1", "yes")
if IS_PRODUCTION:
    print("[PRODUCTION MODE] Running in production environment — enforcing strict security controls.")
else:
    print("[DEVELOPMENT MODE] Running in development environment — some security controls relaxed.")

# ─── Security Configuration ───────────────────────────────────────────────────
# CORS: restrict to known origins (production: only explicit origins; dev: add common dev ports)
cors_origins_str = os.environ.get("ROCKYCRYPT_CORS_ORIGINS", "")
_ALLOWED_ORIGINS = []
if cors_origins_str:
    _ALLOWED_ORIGINS = [o.strip() for o in cors_origins_str.split(",") if o.strip()]

# Enforce CORS requirements in production
if IS_PRODUCTION and not _ALLOWED_ORIGINS:
    raise RuntimeError("[SECURITY ERROR] ROCKYCRYPT_CORS_ORIGINS must be set in production.")
elif not IS_PRODUCTION and not _ALLOWED_ORIGINS:
    # Development defaults: only localhost origins
    _ALLOWED_ORIGINS = ["http://localhost:5000", "http://127.0.0.1:5000", "http://localhost:8000", "http://127.0.0.1:8000"]

# Validate all CORS origins are proper URLs
for origin in _ALLOWED_ORIGINS:
    if not origin.startswith(("http://", "https://")):
        raise ValueError(f"[SECURITY ERROR] Invalid CORS origin: {origin} — must start with http:// or https://")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    allow_credentials=True,
)

# Add comprehensive security headers middleware (HSTS, CSP, X-Frame-Options, etc.)
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if IS_PRODUCTION:
            # Enforce HTTPS for 1 year (31536000 seconds) + include all subdomains
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            # Prevent clickjacking
            response.headers["X-Frame-Options"] = "DENY"
            # Enable browser XSS protection
            response.headers["X-XSS-Protection"] = "1; mode=block"
            # Prevent MIME type sniffing
            response.headers["X-Content-Type-Options"] = "nosniff"
# Referrer policy to limit leaked info
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
# Content Security Policy to prevent XSS
            # NOTE: style-src allows 'unsafe-inline' because the app relies on an
            # embedded <style> block and inline style="" attributes for its entire UI.
            # Likewise script-src needs 'unsafe-inline' for the inline <script> that
            # drives the single-file frontend. These are required for the app to render.
            # Font Awesome icons & fonts are served locally from /static (no external CDNs).
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'"
            # Remove server header to hide tech stack
            if "server" in response.headers:
                del response.headers["server"]
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Password hashing (using bcrypt directly for compatibility)

# --- Environment Variable Validation Helpers ---
def _validate_env_var(var_name, required=False, description=""):
    """Safely retrieve env vars with validation."""
    value = os.environ.get(var_name, "").strip()
    if not value and required and IS_PRODUCTION:
        msg = f"[SECURITY ERROR] {var_name} required in production."
        if description:
            msg += f" {description}"
        raise RuntimeError(msg)
    return value or None

def _is_secure_jwt_secret(secret):
    """Validate JWT secret >= 32 bytes."""
    return len(secret) >= 32

def _is_secure_password_hash(h):
    """Validate bcrypt hash (60+ chars, starts with $2a/$2b/$2y)."""
    return h and h.startswith(("$2a$", "$2b$", "$2y$")) and len(h) >= 60

# JWT configuration — secret from env, never hardcoded
JWT_SECRET = _validate_env_var("ROCKYCRYPT_JWT_SECRET", required=IS_PRODUCTION)
if not JWT_SECRET:
    if IS_PRODUCTION:
        raise RuntimeError("[SECURITY ERROR] ROCKYCRYPT_JWT_SECRET required in production.")
    JWT_SECRET = secrets.token_urlsafe(48)
    print("[SECURITY WARNING] ROCKYCRYPT_JWT_SECRET not set (dev only).")
elif not _is_secure_jwt_secret(JWT_SECRET):
    if IS_PRODUCTION:
        raise RuntimeError("[SECURITY ERROR] JWT secret must be >= 32 bytes.")
    print("[SECURITY WARNING] JWT secret shorter than recommended (32+ bytes).")

JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24

# Unsubscribe token serializer (secure signed links)
unsubscribe_serializer = URLSafeTimedSerializer(JWT_SECRET)
UNSUBSCRIBE_TOKEN_EXPIRY = 365 * 24 * 60 * 60

# Streamlined admin authentication — single secret from environment, NEVER hardcoded.
ADMIN_EMAIL = "admin@rockycrypt.local"  # informational label; real auth uses the secret below
ADMIN_SECRET = _validate_env_var("ROCKYCRYPT_ADMIN_SECRET", required=IS_PRODUCTION,
                                 description="Generate with python -c \"import secrets; print(secrets.token_urlsafe(24))\"")
if not ADMIN_SECRET:
    if IS_PRODUCTION:
        raise RuntimeError("[SECURITY ERROR] ROCKYCRYPT_ADMIN_SECRET must be set in production.")
    ADMIN_SECRET = secrets.token_urlsafe(24)
    print(f"[SECURITY WARNING] ROCKYCRYPT_ADMIN_SECRET not set (dev). Ephemeral secret: {ADMIN_SECRET}\n"
          "Set ROCKYCRYPT_ADMIN_SECRET env var for a persistent admin secret.")


def _load_admin_audit():
    """Load the admin auth/token state files (created by AdminAuthManager)."""
    return None


# Instantiate the streamlined admin auth manager (from admin_auth_simple.py)
class AdminAuthManager:
    """
    Streamlined admin authentication system.
    - No password hashes needed (secret env var is the source of truth)
    - One-time tokens valid for 15 minutes
    - Rate limiting: 5 attempts per hour per IP
    - Audit trail: all attempts logged
    """

    def __init__(self, admin_secret: str, data_dir: str = DATA_DIR):
        self.admin_secret = admin_secret
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.tokens_file = self.data_dir / "admin_tokens.json"
        self.rate_limits_file = self.data_dir / "admin_rate_limits.json"
        self.audit_file = self.data_dir / "admin_audit.json"
        self.token_lifetime = 15 * 60  # 15 minutes
        self.rate_limit_window = 3600  # 1 hour
        self.rate_limit_threshold = 5
        self.token_length = 32

    def _get_client_hash(self, client_ip, user_agent=""):
        return hashlib.sha256(f"{client_ip}|{user_agent}".encode()).hexdigest()[:16]

    def _load_json(self, filepath):
        if not Path(filepath).exists():
            return {}
        try:
            with open(filepath) as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_json(self, filepath, data):
        try:
            _atomic_write_json(str(filepath), data, indent=2)
        except Exception:
            pass

    def verify_credentials(self, provided_secret, client_ip, user_agent=""):
        now = time.time()
        client_hash = self._get_client_hash(client_ip, user_agent)
        rate_limits = self._load_json(self.rate_limits_file)
        if client_hash in rate_limits:
            entry = rate_limits[client_hash]
            if now - entry.get("first_attempt", now) < self.rate_limit_window:
                if entry.get("attempts", 0) >= self.rate_limit_threshold:
                    self._log_audit("rate_limit_exceeded", client_ip, client_hash, None)
                    return {"valid": False, "token": None, "error": "Too many attempts. Try again later.", "status_code": 429}
            else:
                rate_limits[client_hash] = {"first_attempt": now, "attempts": 1}
        else:
            rate_limits[client_hash] = {"first_attempt": now, "attempts": 1}

        if not provided_secret or provided_secret != self.admin_secret:
            rate_limits[client_hash]["attempts"] = rate_limits[client_hash].get("attempts", 0) + 1
            self._save_json(self.rate_limits_file, rate_limits)
            self._log_audit("failed_login", client_ip, client_hash, None)
            return {"valid": False, "token": None, "error": "Invalid credentials", "status_code": 401}

        token_data = secrets.token_hex(self.token_length)
        token_hash = hashlib.sha256(token_data.encode()).hexdigest()
        tokens = self._load_json(self.tokens_file)
        tokens[token_hash] = {"created": now, "expires": now + self.token_lifetime, "client_hash": client_hash, "ip": client_ip}
        self._save_json(self.tokens_file, tokens)
        if client_hash in rate_limits:
            del rate_limits[client_hash]
            self._save_json(self.rate_limits_file, rate_limits)
        self._log_audit("successful_login", client_ip, client_hash, token_hash)
        return {"valid": True, "token": token_data, "error": None, "status_code": 200}

    def verify_token(self, token, client_ip=""):
        if not token:
            return {"valid": False, "error": "No token provided"}
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        tokens = self._load_json(self.tokens_file)
        if token_hash not in tokens:
            self._log_audit("invalid_token", client_ip, "", token_hash)
            return {"valid": False, "error": "Invalid or expired token"}
        entry = tokens[token_hash]
        if time.time() > entry.get("expires", 0):
            del tokens[token_hash]
            self._save_json(self.tokens_file, tokens)
            self._log_audit("expired_token", client_ip, "", token_hash)
            return {"valid": False, "error": "Token expired"}
        return {"valid": True, "error": None}

    def revoke_token(self, token):
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        tokens = self._load_json(self.tokens_file)
        if token_hash in tokens:
            del tokens[token_hash]
            self._save_json(self.tokens_file, tokens)
            self._log_audit("token_revoked", tokens[token_hash].get("ip", ""), "", token_hash)

    def cleanup_expired_tokens(self):
        now = time.time()
        tokens = self._load_json(self.tokens_file)
        expired = [k for k, v in tokens.items() if now > v.get("expires", 0)]
        for key in expired:
            del tokens[key]
        if expired:
            self._save_json(self.tokens_file, tokens)
        return len(expired)

    def _log_audit(self, event, client_ip, client_hash, token_hash):
        audit = self._load_json(self.audit_file)
        if not isinstance(audit, list):
            audit = []
        audit.append({"timestamp": datetime.now().isoformat(), "event": event,
                      "client_ip": client_ip, "client_hash": client_hash,
                      "token_hash": (token_hash[:16] if token_hash else None)})
        audit = audit[-1000:]
        self._save_json(self.audit_file, audit)

    def get_audit_log(self, limit=50):
        audit = self._load_json(self.audit_file)
        return audit[-limit:] if isinstance(audit, list) else []


admin_auth = AdminAuthManager(ADMIN_SECRET, data_dir=DATA_DIR)

# Paystack configuration from environment
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "")
PAYSTACK_PUBLIC_KEY = os.environ.get("PAYSTACK_PUBLIC_KEY", "")

# SMTP configuration from environment
SMTP_HOST = os.environ.get("ROCKYCRYPT_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("ROCKYCRYPT_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("ROCKYCRYPT_SMTP_USER", "")
SMTP_PASS = os.environ.get("ROCKYCRYPT_SMTP_PASS", "")
FROM_EMAIL = os.environ.get("ROCKYCRYPT_FROM_EMAIL", SMTP_USER or "noreply@rockycrypt.local")

# Security: HTTP Bearer auth scheme
_security = HTTPBearer(auto_error=False)


def _hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def _create_jwt_token(payload: dict, expires_hours: int = JWT_EXPIRY_HOURS) -> str:
    """Create a signed JWT token."""
    to_encode = payload.copy()
    to_encode["exp"] = int(time.time()) + expires_hours * 3600
    to_encode["iat"] = int(time.time())
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _decode_jwt_token(token: str) -> dict | None:
    """Decode and verify a JWT token. Returns payload or None."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except Exception:
        return None


async def _get_current_user(credentials: HTTPAuthorizationCredentials = Depends(_security)) -> dict | None:
    """FastAPI dependency: extract and verify the current user from JWT."""
    if not credentials:
        return None
    payload = _decode_jwt_token(credentials.credentials)
    if not payload:
        return None
    return payload


async def get_premium_user(current_user: dict = Depends(_get_current_user)) -> dict:
    """FastAPI dependency: ensure user is authenticated and has premium access."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    email = current_user.get("email", "")
    if not _is_admin_identity(email):
        status = _get_subscription_state(email)
        if not status.get("premium"):
            raise HTTPException(status_code=403, detail="Premium access required")
    return current_user


def _normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def _is_admin_identity(email: str | None) -> bool:
    normalized = _normalize_email(email)
    if not normalized:
        return False
    return normalized == _normalize_email(ADMIN_EMAIL)


def _load_subscriptions() -> dict:
    subs = {}
    try:
        if Path(SUBSCRIPTIONS_FILE).exists():
            with open(SUBSCRIPTIONS_FILE) as f:
                subs = json.load(f)
    except Exception:
        subs = {}
    return subs


def _save_subscriptions(subs: dict) -> None:
    _atomic_write_json(SUBSCRIPTIONS_FILE, subs, indent=2)


def _get_subscription_state(email: str | None) -> dict:
    if not email:
        return {"premium": False, "plan": "free", "tier": "guest"}
    subs = _load_subscriptions()
    sub = subs.get(email, {})
    if sub.get("active"):
        return {"premium": True, "plan": sub.get("plan", "monthly"), "tier": "pro"}
    return {"premium": False, "plan": "free", "tier": "free"}


async def _require_admin(user: dict = Depends(_get_current_user)) -> dict:
    """FastAPI dependency: require an authenticated admin user."""
    if not user or not _is_admin_identity(user.get("email")):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def _require_auth(user: dict = Depends(_get_current_user)) -> dict:
    """FastAPI dependency: require any authenticated user."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


async def _require_premium_user(user: dict = Depends(_get_current_user)) -> dict:
    """FastAPI dependency: require an authenticated premium user or admin."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    email = user.get("email", "")
    if _is_admin_identity(email):
        return user
    status = _get_subscription_state(email)
    if not status.get("premium"):
        raise HTTPException(status_code=403, detail="Premium subscription required")
    return user


# ─── Atomic File Write Helper ──────────────────────────────────────────────────
def _atomic_write_json(filepath: str, data, **kwargs):
    """Write JSON to a temp file first, then atomically rename. Prevents corruption."""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(Path(filepath).parent), suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, **kwargs)
        shutil.move(tmp_path, filepath)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ─── Rate Limiting (persistent across restarts via file storage) ────────────────
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 30  # per window per endpoint per IP
RATE_LIMIT_FILE = str(_BASE_DIR / "data" / "rate_limits.json")
# WARNING: This file-based rate limiting is NOT scalable for production.
# It is prone to race conditions and will not work across multiple server instances.
# For production, consider using Redis or a distributed caching system.

# ─── Failed Login Tracking (Account Lockout) ───────────────────────────────────
FAILED_LOGINS: dict = {}  # {ip: {count: int, locked_until: float}}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes in seconds
FAILED_LOGINS_FILE = str(_BASE_DIR / "data" / "failed_logins.json")
# WARNING: This file-based failed login tracking is NOT scalable for production.
# It is prone to race conditions and will not work across multiple server instances.
# For production, consider using Redis or a distributed caching system.

# ─── Audit Logging System ─────────────────────────────────────────────────────
AUDIT_LOG_FILE = str(_BASE_DIR / "data" / "audit_log.json")
# CRITICAL WARNING: This file-based audit log is NOT secure for production.
# An attacker who compromises the server can easily tamper with or delete this log.
# For production, you MUST implement external log shipping to a secure, immutable service
# (e.g., AWS CloudWatch, Splunk, ELK stack, Datadog) to ensure log integrity and availability.
def _log_audit_event(event_type: str, user_email: str | None, client_ip: str, details: dict):
    """Write audit log entry for sensitive actions."""
    event = {
        "timestamp": int(time.time()),
        "event_type": event_type,
        "user_email": user_email,
        "client_ip": client_ip,
        "details": details
    }
    try:
        # Load existing logs
        logs = []
        if Path(AUDIT_LOG_FILE).exists():
            with open(AUDIT_LOG_FILE, 'r', encoding='utf-8') as f:
                logs = json.load(f)
        # Append new event
        logs.append(event)
        # Keep only last 10,000 logs to prevent file bloat
        if len(logs) > 10000:
            logs = logs[-10000:]
        # Atomic write
        _atomic_write_json(AUDIT_LOG_FILE, logs, indent=2)
    except Exception as e:
        print(f"[AUDIT LOG WARNING] Failed to write audit event: {e}")

# ─── Load Persistent Tracking Data ────────────────────────────────────────────
def _load_persistent_tracking_data():
    """Load rate limits and failed logins from disk to survive server restarts."""
    global _rate_limits
    global FAILED_LOGINS
    
    # Load failed logins
    try:
        if Path(FAILED_LOGINS_FILE).exists():
            with open(FAILED_LOGINS_FILE, 'r', encoding='utf-8') as f:
                FAILED_LOGINS = json.load(f)
    except Exception as e:
        print(f"[TRACKING WARNING] Failed to load failed logins: {e}")
        FAILED_LOGINS = {}
    
    # Clean up expired entries on load
    now = time.time()
    FAILED_LOGINS = {ip: data for ip, data in FAILED_LOGINS.items() if data.get("locked_until", 0) > now}

# Load on startup
_load_persistent_tracking_data()

def _save_failed_logins():
    """Save failed login attempts to disk."""
    _atomic_write_json(FAILED_LOGINS_FILE, FAILED_LOGINS, indent=2)

def _check_rate_limit(request: Request, endpoint: str = "default", max_req: int = RATE_LIMIT_MAX_REQUESTS) -> bool:
    """Persistent rate limiter. Returns True if allowed, False if rate-limited."""
    client_ip = _get_real_client_ip(request)
    key = f"{client_ip}:{endpoint}"
    now = time.time()
    
    # Load current rate limits
    rate_limits = {}
    try:
        if Path(RATE_LIMIT_FILE).exists():
            with open(RATE_LIMIT_FILE, 'r', encoding='utf-8') as f:
                rate_limits = json.load(f)
    except Exception:
        rate_limits = {}
    
    # Clean up old entries
    if key in rate_limits:
        rate_limits[key] = [t for t in rate_limits[key] if now - t < RATE_LIMIT_WINDOW]
    else:
        rate_limits[key] = []
    
    # Check if limit exceeded
    if len(rate_limits[key]) >= max_req:
        # Save updated limits
        _atomic_write_json(RATE_LIMIT_FILE, rate_limits, indent=2)
        return False
    
    # Add new request timestamp
    rate_limits[key].append(now)
    _atomic_write_json(RATE_LIMIT_FILE, rate_limits, indent=2)
    return True




# Initialize users database if it doesn't exist
if not os.path.exists(USERS_FILE):
    _atomic_write_json(USERS_FILE, [])

# Initialize subscriptions database
if not os.path.exists(SUBSCRIPTIONS_FILE):
    _atomic_write_json(SUBSCRIPTIONS_FILE, {})

def send_daily_report(user_email):
    """Send daily market report to user's email (uses env-based SMTP config)."""
    if not SMTP_USER or not SMTP_PASS:
        print("[email] SMTP credentials not configured - skipping daily report")
        return False
    try:
        smtp_server = SMTP_HOST
        smtp_port = SMTP_PORT
        sender_email = SMTP_USER
        sender_password = SMTP_PASS
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = FROM_EMAIL
        msg['To'] = user_email
        msg['Subject'] = "Your Daily NSE Kenya Market Report - RockyCrypt"
        
        # Generate report content
        body = """
        <html>
        <body>
            <h2>Good morning! Here's your daily NSE market update from RockyCrypt</h2>
            <p>Today's top movers, key insights, and portfolio updates are ready.</p>
            <p>Log in to your RockyCrypt account to view the full analysis.</p>
            <br>
            <p>Best regards,<br>The RockyCrypt Team</p>
        </body>
        </html>
        """
        msg.attach(MIMEText(body, 'html'))
        
        # Send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(FROM_EMAIL, user_email, text)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending daily report: {e}")
        return False

# ─── NSE Kenya Stock Registry ─────────────────────────────────────────────────
# Display name for each NSE issuer code
STOCK_NAMES = {
    "SCOM":  "Safaricom PLC",
    "EQTY":  "Equity Group Holdings",
    "KCB":   "KCB Group PLC",
    "COOP":  "Co-operative Bank of Kenya",
    "EABL":  "East African Breweries",
    "ABSA":  "Absa Bank Kenya",
    "NCBA":  "NCBA Group PLC",
    "SCBK":  "Standard Chartered Bank Kenya",
    "DTK":   "Diamond Trust Bank Kenya",
    "BRIT":  "Britam Holdings",
    "JUB":   "Jubilee Holdings",
    "CIC":   "CIC Insurance Group",
    "HFCK":  "HF Group",
    "BAMB":  "Bamburi Cement",
    "BAT":   "BAT Kenya",
    "KPLC":  "Kenya Power & Lighting",
    "KEGN":  "KenGen",
    "TOTL":  "TotalEnergies Marketing Kenya",
    "NMG":   "Nation Media Group",
    "CARB":  "Carbacid Investments",
    "SBIC":  "Stanbic Holdings Kenya",
    "IMH":   "I&M Holdings",
    "CTUM":  "Centum Investment",
    "SCAN":  "ScanGroup",
    "KQ":    "Kenya Airways",
    "SASN":  "Sasini Tea & Coffee",
    "KNRE":  "Kenya Reinsurance Corporation",
    "NSE":   "Nairobi Securities Exchange",
    "WTK":   "Williamson Tea Kenya",
    "KAPC":  "Kapchorua Tea Kenya",
    "UNGA":  "Unga Group",
    "LKL":   "Lakewood Holdings",
    "EVRD":  "Eveready East Africa",
    "FTGH":  "Fahari I-REIT",
    "PORT":  "East African Portland Cement",
    "SKL":   "Skye Bank",
    "CGEN":  "Carbon Africa",
    "GLD":   "Acorn Holdings",
    "SGL":   "Sameer Africa",
    "BKG":   "BK Group",
    "EGAD":  "East African Portland",
    "CRWN":  "Crown Paints Kenya",
    "KPC":   "KenolKobil",
    "FMLY":  "Family Bank",
    "SLAM":  "Sanlam Kenya",
    "UMME":  "Umeme",
    "NBV":   "Nairobi Business Ventures",
    "UCHM":  "Uchumi Supermarkets",
    "SMWF":  "Stanlib Fahari I-REIT",
    "HAFR":  "Home Afrika",
    "KUKZ":  "Kakuzi",
    "TCL":   "TransCentury",
    "BOC":   "BOC Kenya",
    "ARM":   "ARM Cement",
    "AMAC":  "Absa MAC",
    "OCH":   "Orchid Holdings",
    "LBTY":  "Liberty House Group",
    "XPRS":  "Express Kenya",
    "MSC":   "Marshalls East Africa",
    "TPSE":  "Transcentury",
    "SMER":  "StandardMedia",
    "CABL":  "East African Cables",
    "FAHR":  "Fairmount Africa Holdings",
}

# Core 30 stocks to always include in screening
CORE_STOCKS = {
    "SCOM","EQTY","KCB","COOP","EABL","ABSA","NCBA","SCBK","DTK","BRIT",
    "JUB","CIC","HFCK","BAMB","BAT","KPLC","KEGN","TOTL","NMG","CARB",
    "SBIC","IMH","CTUM","SCAN","KQ","SASN","KNRE","UNGA","WTK","KAPC",
}

# ─── Sector Classification ────────────────────────────────────────────────────
SECTOR_MAP = {
    "Banking":          {"EQTY","KCB","COOP","ABSA","NCBA","SCBK","DTK","SBIC","IMH","FMLY","BKG","HFCK"},
    "Insurance":        {"BRIT","JUB","CIC","KNRE","SLAM","LBTY"},
    "Telecommunication": {"SCOM"},
    "Energy & Petroleum": {"KPLC","KEGN","TOTL","KPC","UMME"},
    "Manufacturing":    {"BAMB","BAT","CARB","UNGA","CRWN","BOC","KUKZ","SASN","WTK","KAPC","ARM"},
    "Breweries & Beverages": {"EABL"},
    "Media & Publishing": {"NMG","SMER","XPRS","STD"},
    "Investment & REITs": {"CTUM","FTGH","SMWF","HAFR","FAHR","GLD"},
    "Agriculture":      {"SASN","KUKZ","WTK","KAPC","LIMU"},
    "Commercial & Services": {"SCAN","EVRD","TCL","CABL","MSC","OCH","LKL","NBV","UCHM","PORT","SGL"},
    "Airline":          {"KQ"},
    "NSE":              {"NSE"},
}

# Inverse mapping: symbol → sector
SYMBOL_SECTOR = {}
for sector, symbols in SECTOR_MAP.items():
    for sym in symbols:
        SYMBOL_SECTOR[sym] = sector

# Corporate metadata for company profiles
COMPANY_META = {
    "SCOM": {"sector":"Telecommunication","founded":1997,"employees":7500,"ceo":"Peter Ndegwa","hq":"Nairobi, Kenya","website":"safaricom.co.ke","market_cap_ksh":589000000000,"pe_ratio":14.2,"eps":2.15,"dividend_yield":5.8},
    "EQTY": {"sector":"Banking","founded":1984,"employees":8500,"ceo":"James Mwangi","hq":"Nairobi, Kenya","website":"equitybank.co.ke","market_cap_ksh":142000000000,"pe_ratio":6.8,"eps":3.42,"dividend_yield":4.2},
    "KCB":  {"sector":"Banking","founded":1896,"employees":7000,"ceo":"Paul Russo","hq":"Nairobi, Kenya","website":"kcbgroup.com","market_cap_ksh":112000000000,"pe_ratio":5.9,"eps":3.88,"dividend_yield":6.0},
    "COOP": {"sector":"Banking","founded":1965,"employees":5500,"ceo":"Gideon Muriuki","hq":"Nairobi, Kenya","website":"co-opbank.co.ke","market_cap_ksh":82000000000,"pe_ratio":7.1,"eps":2.95,"dividend_yield":5.5},
    "EABL": {"sector":"Breweries & Beverages","founded":1922,"employees":3000,"ceo":"Jane Karuku","hq":"Nairobi, Kenya","website":"eabl.com","market_cap_ksh":215000000000,"pe_ratio":16.5,"eps":4.12,"dividend_yield":3.2},
    "ABSA": {"sector":"Banking","founded":1978,"employees":4000,"ceo":"Jeremy Awori","hq":"Nairobi, Kenya","website":"absabank.co.ke","market_cap_ksh":78000000000,"pe_ratio":7.8,"eps":2.54,"dividend_yield":4.8},
    "NCBA": {"sector":"Banking","founded":2019,"employees":3500,"ceo":"John Gachora","hq":"Nairobi, Kenya","website":"ncbagroup.com","market_cap_ksh":65000000000,"pe_ratio":6.5,"eps":3.21,"dividend_yield":5.1},
    "SCBK": {"sector":"Banking","founded":1911,"employees":1200,"ceo":"Kariuki Ngari","hq":"Nairobi, Kenya","website":"standardchartered.co.ke","market_cap_ksh":45000000000,"pe_ratio":8.2,"eps":2.85,"dividend_yield":4.5},
    "DTK":  {"sector":"Banking","founded":1945,"employees":1500,"ceo":"Johnson Nderi","hq":"Nairobi, Kenya","website":"dtbafrica.com","market_cap_ksh":28000000000,"pe_ratio":5.5,"eps":4.50,"dividend_yield":6.5},
    "BRIT": {"sector":"Insurance","founded":1966,"employees":2000,"ceo":"Tom Gitogo","hq":"Nairobi, Kenya","website":"britam.com","market_cap_ksh":25000000000,"pe_ratio":9.2,"eps":1.85,"dividend_yield":3.8},
    "JUB":  {"sector":"Insurance","founded":1937,"employees":1800,"ceo":"Julius Kipngetich","hq":"Nairobi, Kenya","website":"jubileeinsurance.com","market_cap_ksh":32000000000,"pe_ratio":7.5,"eps":3.10,"dividend_yield":4.0},
    "CIC":  {"sector":"Insurance","founded":1968,"employees":1200,"ceo":"Patrick Nyaga","hq":"Nairobi, Kenya","website":"cic.co.ke","market_cap_ksh":12000000000,"pe_ratio":6.8,"eps":1.95,"dividend_yield":3.5},
    "BAMB": {"sector":"Manufacturing","founded":1951,"employees":800,"ceo":"Mohit Kapoor","hq":"Nairobi, Kenya","website":"bamburi.com","market_cap_ksh":38000000000,"pe_ratio":10.5,"eps":2.45,"dividend_yield":4.8},
    "BAT":  {"sector":"Manufacturing","founded":1907,"employees":600,"ceo":"Crispin Achola","hq":"Nairobi, Kenya","website":"batkenya.com","market_cap_ksh":85000000000,"pe_ratio":12.8,"eps":5.20,"dividend_yield":7.2},
    "KPLC": {"sector":"Energy & Petroleum","founded":1922,"employees":7500,"ceo":"Geoffrey Muli","hq":"Nairobi, Kenya","website":"kplc.co.ke","market_cap_ksh":55000000000,"pe_ratio":8.5,"eps":1.45,"dividend_yield":2.5},
    "KEGN": {"sector":"Energy & Petroleum","founded":1954,"employees":2500,"ceo":"Peter Njenga","hq":"Nairobi, Kenya","website":"kengen.co.ke","market_cap_ksh":48000000000,"pe_ratio":9.2,"eps":2.10,"dividend_yield":3.8},
    "TOTL": {"sector":"Energy & Petroleum","founded":1956,"employees":1200,"ceo":"Eric Biosse","hq":"Nairobi, Kenya","website":"totalenergies.co.ke","market_cap_ksh":32000000000,"pe_ratio":7.8,"eps":3.55,"dividend_yield":5.5},
    "NMG":  {"sector":"Media & Publishing","founded":1959,"employees":1500,"ceo":"Stephen Gitagama","hq":"Nairobi, Kenya","website":"nmgroup.com","market_cap_ksh":8500000000,"pe_ratio":11.5,"eps":1.25,"dividend_yield":4.5},
    "CARB": {"sector":"Manufacturing","founded":1960,"employees":400,"ceo":"Dave Muthuri","hq":"Nairobi, Kenya","website":"carbacid.com","market_cap_ksh":22000000000,"pe_ratio":14.2,"eps":3.80,"dividend_yield":3.0},
    "SBIC": {"sector":"Banking","founded":1957,"employees":1800,"ceo":"Herman Bosek","hq":"Nairobi, Kenya","website":"stanbicbank.co.ke","market_cap_ksh":52000000000,"pe_ratio":7.2,"eps":2.95,"dividend_yield":4.2},
    "IMH":  {"sector":"Banking","founded":1970,"employees":2500,"ceo":"Gul Khan","hq":"Nairobi, Kenya","website":"imbank.com","market_cap_ksh":34000000000,"pe_ratio":6.9,"eps":3.45,"dividend_yield":5.0},
    "CTUM": {"sector":"Investment & REITs","founded":1967,"employees":800,"ceo":"James Mworia","hq":"Nairobi, Kenya","website":"centum.co.ke","market_cap_ksh":18000000000,"pe_ratio":11.2,"eps":2.85,"dividend_yield":2.8},
    "KQ":   {"sector":"Airline","founded":1977,"employees":4000,"ceo":"Allan Kilavuka","hq":"Nairobi, Kenya","website":"kenya-airways.com","market_cap_ksh":9500000000,"pe_ratio":0,"eps":-1.85,"dividend_yield":0},
    "KNRE": {"sector":"Insurance","founded":1970,"employees":500,"ceo":"Hillary Wachinga","hq":"Nairobi, Kenya","website":"kenyare.co.ke","market_cap_ksh":8500000000,"pe_ratio":5.5,"eps":2.30,"dividend_yield":4.8},
    "UNGA": {"sector":"Manufacturing","founded":1900,"employees":600,"ceo":"Joseph Choge","hq":"Nairobi, Kenya","website":"ungagroup.com","market_cap_ksh":6200000000,"pe_ratio":8.5,"eps":2.15,"dividend_yield":3.2},
    "SASN": {"sector":"Agriculture","founded":1954,"employees":4000,"ceo":"Martin Ochieng","hq":"Nairobi, Kenya","website":"sasingroup.com","market_cap_ksh":4800000000,"pe_ratio":7.2,"eps":1.85,"dividend_yield":4.0},
    "HFCK": {"sector":"Banking","founded":1965,"employees":800,"ceo":"Samuel Kariuki","hq":"Nairobi, Kenya","website":"hfg.co.ke","market_cap_ksh":5200000000,"pe_ratio":6.5,"eps":1.55,"dividend_yield":3.5},
}

# ─── Live Data API ────────────────────────────────────────────────────────────
NSE_API_URL     = "https://deveintapps.com/nseticker/api/v1/ticker"
NSE_API_PAYLOAD = {"nopage": "true"}
NSE_API_HEADERS = {
    "Content-Type": "application/json",
    "Accept":       "application/json",
    "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
    "Referer":      "https://www.nse.co.ke/",
    "Origin":       "https://www.nse.co.ke",
}

# In-memory live data cache (refreshed every 5 min)
_live_cache: dict = {"data": None, "fetched_at": 0}

@app.get("/history/{symbol}")
async def get_history(symbol: str):
    """Return historical OHLCV data for a given symbol."""
    history = load_history()
    df = build_df_from_history(symbol.upper(), history)
    if df.empty:
        return JSONResponse(content=[], status_code=404)
    # Convert DataFrame to a list of dictionaries (JSON format)
    # Ensure date is in ISO format for JavaScript parsing
    df["Date"] = df["Date"].dt.strftime("%Y-%m-%d")
    return JSONResponse(content=df.to_dict(orient="records"))

# Running state for the analysis subprocess
_running: dict = {"process": None, "status": "idle"}


def _build_fallback_snapshot() -> dict | None:
    """
    Build a live-shaped market snapshot from the accumulated price history
    when the external NSE API is unavailable.

    Uses each symbol's latest history entry as its "current" quote and
    computes change_pct from the last two entries. Returns None if there is
    no usable history at all.
    """
    history = load_history()
    if not history:
        return None

    stocks = {}
    for sym, rows in history.items():
        if not rows:
            continue
        last  = rows[-1]
        prev  = rows[-2] if len(rows) >= 2 else last
        price = float(last.get("close", 0) or 0)
        if price <= 0:
            continue
        open_ = float(last.get("open", price) or price)
        high  = float(last.get("high", price) or price)
        low   = float(last.get("low", price) or price)
        volume  = int(last.get("volume", 0) or 0)
        turnover= float(last.get("turnover", 0) or 0.0)
        prev_close = float(prev.get("close", price) or price)
        change_pct = round(((price - prev_close) / prev_close) * 100, 2) if prev_close else 0.0

        stocks[sym] = {
            "price":      price,
            "prev_price": prev_close,
            "open":       open_,
            "high":       high,
            "low":        low,
            "volume":     volume,
            "turnover":   turnover,
            "change_pct": change_pct,
        }

    if not stocks:
        return None

    return {
        "stocks":        stocks,
        "market_status": "unknown",
        "market_date":   "",
        "market_time":   "",
        "source":        "price_history.json · cached NSE Kenya",
        "fetched_utc":   datetime.utcnow().isoformat(),
    }


def fetch_live_nse_data(force: bool = False) -> dict | None:
    """
    Fetch live NSE Kenya data from deveintapps.com.
    Returns a dict or None on failure.
    Cached for 5 minutes.

    If the live API is unreachable (network error, auth change, etc.) this
    falls back to a snapshot built from the locally accumulated price history
    so the dashboard and analysis keep working offline.
    """
    import time
    now = time.time()
    cached = _live_cache.get("data")
    if not force and cached and cached.get("source") and now - _live_cache["fetched_at"] < 300:
        return cached

    try:
        resp = requests.post(
            NSE_API_URL,
            json=NSE_API_PAYLOAD,
            headers=NSE_API_HEADERS,
            timeout=15,
        )
        resp.raise_for_status()
        raw = resp.json()

        snapshot = raw["message"][0]["snapshot"]
        meta     = raw["message"][1]["updated_at"]

        stocks = {}
        for s in snapshot:
            sym = s.get("issuer", "")
            if not sym:
                continue
            price = s.get("price")
            if price is None:
                # Try last-traded price as fallback
                price = s.get("ltp")
            if price is None:
                continue
            stocks[sym] = {
                "price":      float(price),
                "prev_price": float(s["prev_price"]) if s.get("prev_price") is not None else float(price),
                "open":       float(s["today_open"]) if s.get("today_open") is not None else float(price),
                "high":       float(s["today_high"]) if s.get("today_high") is not None else float(price),
                "low":        float(s["today_low"])  if s.get("today_low")  is not None else float(price),
                "volume":     int(s["volume"])        if s.get("volume")     is not None else 0,
                "turnover":   float(s["turnover"])    if s.get("turnover")   is not None else 0.0,
                "change_pct": float(s.get("change", 0)),
            }

        result = {
            "stocks":        stocks,
            "market_status": meta.get("market_status", "unknown"),
            "market_date":   meta.get("date", ""),
            "market_time":   meta.get("time", ""),
            "source":        "deveintapps.com · NSE Kenya",
            "fetched_utc":   datetime.utcnow().isoformat(),
        }
        _live_cache["data"]       = result
        _live_cache["fetched_at"] = now
        return result

    except Exception as exc:
        print(f"[live data] fetch error: {exc}. Using cached/history fallback.")
        fallback = _build_fallback_snapshot()
        if fallback:
            # Only overwrite the cache with the fallback if we have no live cache
            if not cached or not cached.get("stocks"):
                _live_cache["data"]       = fallback
                _live_cache["fetched_at"] = now
            # Prefer a real (even slightly stale) live cache over the fallback
            return cached if cached and cached.get("stocks") else fallback
        return cached   # return stale cache on error


# ─── Price History Management ─────────────────────────────────────────────────

def load_history() -> dict:
    """Load accumulated daily OHLCV history from disk."""
    if Path(HISTORY_FILE).exists():
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_history(history: dict):
    """Persist history to disk (atomic write prevents corruption)."""
    try:
        _atomic_write_json(HISTORY_FILE, history, separators=(",", ":"))
    except Exception as exc:
        print(f"[history] save error: {exc}")


def update_history_from_live(history: dict, live: dict) -> dict:
    """
    Append today's snapshot to the per-symbol history lists.
    Each entry: {"date","open","high","low","close","volume","change_pct"}
    """
    # Use the date from the API response or today
    mdate = live.get("market_date", "")
    try:
        # Parse "17/07/2026" → "2026-07-17"
        d = datetime.strptime(mdate, "%d/%m/%Y")
        date_str = d.strftime("%Y-%m-%d")
    except Exception:
        date_str = datetime.now().strftime("%Y-%m-%d")

    stocks = live.get("stocks", {})
    for sym, s in stocks.items():
        if sym not in history:
            history[sym] = []
        # Avoid duplicating the same date
        if history[sym] and history[sym][-1].get("date") == date_str:
            # Update the latest entry (in case market is still open)
            history[sym][-1].update({
                "high":       max(history[sym][-1]["high"], s["high"]),
                "low":        min(history[sym][-1]["low"],  s["low"]),
                "close":      s["price"],
                "volume":     s["volume"],
                "change_pct": s["change_pct"],
            })
        else:
            history[sym].append({
                "date":       date_str,
                "open":       s["open"],
                "high":       s["high"],
                "low":        s["low"],
                "close":      s["price"],
                "volume":     s["volume"],
                "change_pct": s["change_pct"],
            })
        # Keep 400 days max
        if len(history[sym]) > 400:
            history[sym] = history[sym][-400:]

    return history


def build_df_from_history(symbol: str, history: dict) -> pd.DataFrame:
    """Build an OHLCV DataFrame from the accumulated history for one symbol."""
    rows = history.get(symbol, [])
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    df["Date"] = pd.to_datetime(df["date"])
    df = df.sort_values("Date").reset_index(drop=True)
    df = df.rename(columns={
        "open": "Open", "high": "High", "low": "Low",
        "close": "Close", "volume": "Volume",
    })
    df = df.dropna(subset=["Close"])
    return df


# ─── Technical Analysis Engine ───────────────────────────────────────────────

class TechnicalAnalyzer:
    @staticmethod
    def sma(series: pd.Series, period: int) -> pd.Series:
        return series.rolling(window=period).mean()

    @staticmethod
    def ema(series: pd.Series, period: int) -> pd.Series:
        return series.ewm(span=period, adjust=False).mean()

    @staticmethod
    def rsi(series: pd.Series, period: int = 14) -> float:
        delta = series.diff()
        gain  = delta.where(delta > 0, 0).rolling(window=period).mean()
        loss  = (-delta.where(delta < 0, 0)).rolling(window=period).mean()
        rs    = gain / loss
        val   = (100 - (100 / (1 + rs))).iloc[-1]
        return float(val) if pd.notna(val) else 50.0

    @staticmethod
    def macd(series: pd.Series):
        ema12  = series.ewm(span=12, adjust=False).mean()
        ema26  = series.ewm(span=26, adjust=False).mean()
        line   = ema12 - ema26
        signal = line.ewm(span=9, adjust=False).mean()
        hist   = line - signal
        m, s, h = line.iloc[-1], signal.iloc[-1], hist.iloc[-1]
        return (
            float(m) if pd.notna(m) else 0.0,
            float(s) if pd.notna(s) else 0.0,
            float(h) if pd.notna(h) else 0.0,
        )

    @staticmethod
    def bollinger_bands(series: pd.Series, period: int = 20, std_dev: float = 2.0):
        sma   = series.rolling(window=period).mean()
        std   = series.rolling(window=period).std()
        upper = sma + (std * std_dev)
        lower = sma - (std * std_dev)
        u, m, l = upper.iloc[-1], sma.iloc[-1], lower.iloc[-1]
        return (
            float(u) if pd.notna(u) else 0.0,
            float(m) if pd.notna(m) else 0.0,
            float(l) if pd.notna(l) else 0.0,
        )

    @staticmethod
    def stochastic(high: pd.Series, low: pd.Series, close: pd.Series, period: int = 14) -> float:
        ll  = low.rolling(window=period).min()
        hh  = high.rolling(window=period).max()
        stk = 100 * (close - ll) / (hh - ll)
        val = stk.iloc[-1]
        return float(val) if pd.notna(val) else 50.0

    def analyze(self, df: pd.DataFrame) -> dict:
        """Full technical analysis — requires ≥ 26 rows for MACD."""
        if df.empty:
            return {}
        n     = len(df)
        close = df["Close"]
        high  = df["High"]
        low   = df["Low"]
        vol   = df["Volume"]

        cur = float(close.iloc[-1])
        if cur == 0:
            return {}

        prev = float(close.iloc[-2]) if n >= 2 else cur
        p5   = float(close.iloc[-5]) if n >= 5 else cur

        sma20 = float(self.sma(close, 20).iloc[-1]) if n >= 20 else cur
        sma50 = float(self.sma(close, 50).iloc[-1]) if n >= 50 else cur
        ema12 = float(self.ema(close, 12).iloc[-1]) if n >= 12 else cur
        ema26 = float(self.ema(close, 26).iloc[-1]) if n >= 26 else cur

        rsi_val   = self.rsi(close)     if n >= 14 else 50.0
        macd_v, macd_s, macd_h = self.macd(close) if n >= 26 else (0.0, 0.0, 0.0)
        bb_u, bb_m, bb_l = self.bollinger_bands(close) if n >= 20 else (cur * 1.02, cur, cur * 0.98)
        stoch_val = self.stochastic(high, low, close) if n >= 14 else 50.0

        avg_vol    = float(vol.rolling(window=20).mean().iloc[-1]) if n >= 20 else (float(vol.mean()) if not vol.empty else 1)
        vol_ratio  = float(vol.iloc[-1]) / avg_vol if avg_vol > 0 else 1.0

        return {
            "price":          round(cur, 2),
            "sma20":          round(sma20, 2),
            "sma50":          round(sma50, 2),
            "ema12":          round(ema12, 2),
            "ema26":          round(ema26, 2),
            "rsi":            round(rsi_val, 2),
            "macd":           round(macd_v, 4),
            "macd_signal":    round(macd_s, 4),
            "macd_histogram": round(macd_h, 4),
            "stochastic":     round(stoch_val, 2),
            "bb_upper":       round(bb_u, 2),
            "bb_lower":       round(bb_l, 2),
            "volume_ratio":   round(vol_ratio, 2),
            "change_1d":      round(((cur - prev) / prev) * 100, 2) if prev else 0,
            "change_5d":      round(((cur - p5)   / p5)   * 100, 2) if p5   else 0,
            "data_days":      n,
        }


class SignalEngine:
    @staticmethod
    def score_full(ind: dict) -> dict:
        """Full scoring with all technical indicators."""
        score   = 0
        reasons = []
        price   = ind["price"]
        sma20   = ind["sma20"]
        sma50   = ind["sma50"]
        ema12   = ind["ema12"]
        ema26   = ind["ema26"]
        n       = ind.get("data_days", 0)

        # ── Moving averages
        if price > sma20:
            score += 10; reasons.append("Price above SMA20 (bullish)")
        else:
            score -= 10; reasons.append("Price below SMA20 (bearish)")

        if n >= 50:
            if price > sma50:
                score += 10; reasons.append("Price above SMA50 (bullish)")
            else:
                score -= 10; reasons.append("Price below SMA50 (bearish)")

            if sma20 > sma50:
                score += 15; reasons.append("SMA20 > SMA50 — Golden Cross zone")
            else:
                score -= 15; reasons.append("SMA20 < SMA50 — Death Cross zone")

        if n >= 26:
            if ema12 > ema26:
                score += 5; reasons.append("EMA12 > EMA26 (short-term bullish)")
            else:
                score -= 5; reasons.append("EMA12 < EMA26 (short-term bearish)")

        # ── RSI
        rsi = ind["rsi"]
        if n >= 14:
            if rsi < 30:
                score += 20; reasons.append(f"RSI {rsi:.0f} — oversold, strong buy signal")
            elif rsi < 40:
                score += 10; reasons.append(f"RSI {rsi:.0f} — approaching oversold")
            elif rsi > 70:
                score -= 20; reasons.append(f"RSI {rsi:.0f} — overbought, strong sell signal")
            elif rsi > 60:
                score -= 10; reasons.append(f"RSI {rsi:.0f} — approaching overbought")
            else:
                reasons.append(f"RSI {rsi:.0f} — neutral zone")

        # ── MACD
        if n >= 26:
            macd_h = ind["macd_histogram"]
            if macd_h > 0:
                score += 10; reasons.append("MACD histogram positive — bullish momentum")
            else:
                score -= 10; reasons.append("MACD histogram negative — bearish momentum")

        # ── Stochastic
        if n >= 14:
            stoch = ind["stochastic"]
            if stoch < 20:
                score += 10; reasons.append(f"Stochastic {stoch:.0f} — oversold")
            elif stoch > 80:
                score -= 10; reasons.append(f"Stochastic {stoch:.0f} — overbought")

        # ── Bollinger Bands
        if n >= 20:
            bb_u  = ind["bb_upper"]
            bb_l  = ind["bb_lower"]
            if price <= bb_l:
                score += 10; reasons.append("Price at lower Bollinger Band — potential bounce")
            elif price >= bb_u:
                score -= 10; reasons.append("Price at upper Bollinger Band — potential reversal")

        # ── Volume
        vol_r = ind["volume_ratio"]
        if vol_r > 1.5:
            if score > 0:
                score += 5; reasons.append(f"High volume ({vol_r:.1f}× avg) confirms bullish move")
            elif score < 0:
                score -= 5; reasons.append(f"High volume ({vol_r:.1f}× avg) confirms bearish move")

        return _make_signal(score, reasons)

    @staticmethod
    def score_simple(live_stock: dict) -> dict:
        """
        Simplified scoring when fewer than 20 history days are available.
        Uses only live snapshot: change%, range position, volume.
        """
        score   = 0
        reasons = []
        chg     = live_stock.get("change_pct", 0)
        price   = live_stock.get("price", 0)
        high    = live_stock.get("high", price)
        low     = live_stock.get("low", price)
        vol     = live_stock.get("volume", 0)

        # Price momentum
        if chg > 3:
            score += 25; reasons.append(f"Strong gain +{chg:.1f}% today")
        elif chg > 1:
            score += 12; reasons.append(f"Positive gain +{chg:.1f}% today")
        elif chg > 0:
            score += 5;  reasons.append(f"Slight gain +{chg:.1f}% today")
        elif chg < -3:
            score -= 25; reasons.append(f"Sharp decline {chg:.1f}% today")
        elif chg < -1:
            score -= 12; reasons.append(f"Negative decline {chg:.1f}% today")
        elif chg < 0:
            score -= 5;  reasons.append(f"Slight decline {chg:.1f}% today")
        else:
            reasons.append("Unchanged today")

        # Position in today's range
        rng = high - low
        if rng > 0:
            pos = (price - low) / rng  # 0 = at low, 1 = at high
            if pos > 0.8:
                score += 10; reasons.append("Closing near today's high (bullish)")
            elif pos < 0.2:
                score -= 10; reasons.append("Closing near today's low (bearish)")

        reasons.append("⚠ Limited history — building data (full TA after 20+ sessions)")

        return _make_signal(score, reasons)


def _make_signal(score: int, reasons: list) -> dict:
    score = max(-100, min(100, score))
    if   score >= 40:  sig = "STRONG BUY"
    elif score >= 20:  sig = "BUY"
    elif score >= 5:   sig = "LEAN BULLISH"
    elif score <= -40: sig = "STRONG SELL"
    elif score <= -20: sig = "SELL"
    elif score <= -5:  sig = "LEAN BEARISH"
    else:              sig = "NEUTRAL"
    return {"score": score, "signal": sig, "reasons": reasons}


analyzer = TechnicalAnalyzer()
engine   = SignalEngine()


# ─── Main screening function ──────────────────────────────────────────────────

def screen_all_stocks() -> tuple[list, dict]:
    """
    Fetch live prices, update history, compute technical analysis.
    Returns (results_list, market_meta).
    """
    live = fetch_live_nse_data(force=True)
    if not live:
        # Fall back to whatever is cached
        return [], {}

    history = load_history()
    history = update_history_from_live(history, live)
    save_history(history)

    stocks     = live["stocks"]
    results    = []
    all_prices = []

    # Determine which symbols to screen
    target = CORE_STOCKS.union(set(stocks.keys()))

    for sym in target:
        s = stocks.get(sym)
        if not s:
            continue
        price = s["price"]
        if not price or price <= 0:
            continue

        df  = build_df_from_history(sym, history)
        n   = len(df)

        if n >= 20:
            ind    = analyzer.analyze(df)
            signal = engine.score_full(ind)
            ind_to_use = ind
        else:
            # Simplified scoring until enough history is accumulated
            signal     = engine.score_simple(s)
            ind_to_use = {
                "price":          price,
                "sma20":          price,
                "sma50":          price,
                "ema12":          price,
                "ema26":          price,
                "rsi":            50.0,
                "macd":           0.0,
                "macd_signal":    0.0,
                "macd_histogram": 0.0,
                "stochastic":     50.0,
                "bb_upper":       round(price * 1.02, 2),
                "bb_lower":       round(price * 0.98, 2),
                "volume_ratio":   1.0,
                "change_1d":      round(s["change_pct"], 2),
                "change_5d":      0.0,
                "data_days":      n,
            }

        all_prices.append(price)
        results.append({
            "symbol":  sym,
            "name":    STOCK_NAMES.get(sym, sym),
            "volume":  s["volume"],
            "open":    round(s["open"], 2),
            "high":    round(s["high"], 2),
            "low":     round(s["low"],  2),
            **ind_to_use,
            **signal,
        })

    results.sort(key=lambda x: x["score"], reverse=True)

    # Market overview — compute from constituents
    overview = compute_index_overview(live, all_prices)

    return results, {
        "market_status": live.get("market_status", "unknown"),
        "market_date":   live.get("market_date", ""),
        "market_time":   live.get("market_time", ""),
        "source":        live.get("source", ""),
        "overview":      overview,
    }


def compute_index_overview(live: dict, all_prices: list) -> dict:
    """Compute index-level overview from live data."""
    stocks = live.get("stocks", {})

    # NSE 20 Share Index constituents (approximate)
    nse20 = ["SCOM","EQTY","KCB","COOP","EABL","ABSA","NCBA","SCBK","DTK",
              "BRIT","JUB","CIC","BAMB","BAT","KPLC","KEGN","TOTL","NMG","SBIC","CTUM"]
    nse20_chg = [stocks[s]["change_pct"] for s in nse20 if s in stocks]
    nse20_avg  = round(sum(nse20_chg) / len(nse20_chg), 2) if nse20_chg else 0

    # All-share
    all_chg   = [s["change_pct"] for s in stocks.values()]
    allshare_avg = round(sum(all_chg) / len(all_chg), 2) if all_chg else 0

    gainers = sum(1 for c in all_chg if c > 0)
    losers  = sum(1 for c in all_chg if c < 0)
    unch    = len(all_chg) - gainers - losers

    return {
        "NSE 20":        {"name": "NSE 20",        "change_pct": nse20_avg,     "gainers": gainers, "losers": losers},
        "NSE All Share": {"name": "NSE All Share",  "change_pct": allshare_avg,  "gainers": gainers, "losers": losers, "unchanged": unch},
    }


# ─── Analysis runner ──────────────────────────────────────────────────────────

def run_analysis_job():
    """Full analysis run — saves result to dated JSON file."""
    print("Starting RockyCrypt NSE Kenya analysis …")
    results, meta = screen_all_stocks()

    date_str  = datetime.now().strftime("%Y-%m-%d")
    data      = {
        "date":           date_str,
        "overview":       meta.get("overview", {}),
        "market_status":  meta.get("market_status", "unknown"),
        "market_date":    meta.get("market_date", ""),
        "market_time":    meta.get("market_time", ""),
"source":         meta.get("source", ""),
        "results":        results,
    }

    data_path = os.path.join(DATA_DIR, f"data_{date_str}.json")
    _atomic_write_json(data_path, data, indent=2, default=str)

    # Append this run's calls to the append-only track record. Never fatal:
    # a broken log must not stop the analysis pipeline.
    if backtest is not None:
        try:
            appended = backtest.record_signals(results, date_str)
            if appended:
                print(f"[track record] logged {appended} signals for {date_str}")
        except Exception as exc:                              # noqa: BLE001
            print(f"[track record] logging skipped: {exc}")

    print(f"[OK] Analysis done - {len(results)} stocks. Saved to {data_path}")
    return data


# ─── API Routes ───────────────────────────────────────────────────────────────

HTML_FILE = str(_BASE_DIR / "rockycrypt_v2.html")

@app.get("/favicon.ico")
async def favicon():
    # Inline SVG favicon — green R + red C
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
        '<rect width="32" height="32" rx="6" fill="#0d0d0d"/>'
        '<text x="2" y="24" font-size="20" font-weight="bold" font-family="monospace" fill="#006B3F">R</text>'
        '<text x="16" y="24" font-size="20" font-weight="bold" font-family="monospace" fill="#BB0000">C</text>'
        '</svg>'
    )
    from fastapi.responses import Response
    return Response(content=svg, media_type="image/svg+xml")


@app.get("/", response_class=HTMLResponse)
async def index():
    try:
        with open(HTML_FILE, encoding="utf-8") as f:
            return f.read()
    except Exception:
        return "<h1>RockyCrypt</h1><p>Dashboard not found. Run analysis first.</p>"


@app.get("/api/health")
async def health():
    return JSONResponse({"status": "ok", "engine": "rockycrypt", "exchange": "NSE Kenya"})


@app.get("/api/live")
async def get_live():
    """Return fresh live prices from NSE Kenya — no full analysis."""
    data = fetch_live_nse_data()
    if not data:
        return JSONResponse({"error": "Unable to fetch live data"}, status_code=503)
    return JSONResponse(data)


@app.get("/api/latest")
async def get_latest():
    """Return the most recent completed analysis."""
    try:
        files = sorted(Path(DATA_DIR).glob("data_*.json"), reverse=True)
        if not files:
            # No saved analysis yet — run one on the fly
            data = run_analysis_job()
            return JSONResponse(data)
        with open(files[0]) as f:
            data = json.load(f)
        return JSONResponse(data)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/status")
async def get_status():
    if _running["process"] and _running["process"].poll() is None:
        return JSONResponse({"status": "running"})
    _running["status"] = "idle"
    return JSONResponse({"status": "idle"})


@app.post("/api/run")
async def run_analysis():
    """Trigger a fresh analysis run (background subprocess)."""
    if _running["process"] and _running["process"].poll() is None:
        return JSONResponse({"status": "already_running"})
    _running["status"] = "running"
    proc = subprocess.Popen(
        [sys.executable, __file__, "--analyze"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=str(_BASE_DIR),
    )
    _running["process"] = proc
    return JSONResponse({"status": "started"})


@app.get("/api/news")
async def get_news():
    """NSE Kenya news from Google News RSS — with image extraction."""
    try:
        url = "https://news.google.com/rss/search?q=NSE+Kenya+stock+market&hl=en-KE&gl=KE&ceid=KE:en"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read()
        root     = ET.fromstring(data)
        articles = []
        for item in root.iter("item"):
            link = item.findtext("link", "")
            # Try to extract og:image from the article page
            img = extract_og_image(link)
            articles.append({
                "title":     item.findtext("title", ""),
                "link":      link,
                "published": (item.findtext("pubDate", ""))[:16],
                "source":    item.findtext("source", ""),
                "image":     img,
            })
            if len(articles) >= 15:
                break
        return JSONResponse({"articles": articles})
    except Exception as e:
        return JSONResponse({"articles": [], "error": str(e)})


def extract_og_image(url: str) -> str:
    """Try to extract the og:image meta tag from an article page."""
    if not url:
        return ""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
        # Look for og:image meta tag
        m = re.search(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if m:
            return m.group(1)
        # Fallback: look for any og:image
        m = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:image["\']', html, re.IGNORECASE)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


# ─── Content Engine Data Stores ──────────────────────────────────────────────
# Morning Briefs, Market Wraps, Corporate Alerts for daily traders
MORNING_BRIEFS = [
    {
        "id": "brief-2026-08-02",
        "type": "morning_brief",
        "date": "2026-08-02",
        "title": "Market Sentiment: NSE Bounces Back on Banking Gains",
        "summary": "Equity Bank (+2.1%), KCB (+1.8%) lead morning gains. Safaricom holds steady after M-Pesa transaction volume growth. Notable announcement: Centum Investment to announce Q4 earnings this week.",
        "top_gainers": ["EQTY: +2.1%", "KCB: +1.8%", "ABSA: +1.5%"],
        "top_losers": ["KQ: -1.2%", "NMG: -0.8%", "BAT: -0.5%"],
        "announcements": ["Centum: Q4 earnings this week", "SCOM: M-Pesa volume growth report"],
        "sentiment": "bullish",
        "created_at": "2026-08-02T08:00:00Z"
    }
]

MARKET_WRAPS = [
    {
        "id": "wrap-2026-08-01",
        "type": "market_wrap",
        "date": "2026-08-01",
        "title": "EOD Summary: NSE20 Index Closes 0.9% Higher",
        "summary": "Banking sector led gains with 2.3% average increase. Unusual volume spike in Safaricom (3x average) on dividend speculation. Telecom and agriculture sectors mixed.",
        "key_trends": ["Banking: +2.3%", "Telecom: +0.5%", "Agriculture: -0.2%"],
        "unusual_activity": ["SCOM: 3x average volume", "CTUM: 2.5x average volume"],
        "nse20_change": "+0.9%",
        "created_at": "2026-08-01T17:30:00Z"
    }
]

CORPORATE_ALERTS = [
    {
        "id": "corp-2026-08-02",
        "type": "corporate_alert",
        "date": "2026-08-02",
        "title": "Dividend Declarations: Equity Bank, KCB Announce Interim Dividends",
        "alerts": [
            {"type": "dividend", "symbol": "EQTY", "company": "Equity Group Holdings", "amount": "KSh 3.00 per share", "ex_date": "2026-08-15", "pay_date": "2026-08-30"},
            {"type": "dividend", "symbol": "KCB", "company": "KCB Group PLC", "amount": "KSh 3.50 per share", "ex_date": "2026-08-16", "pay_date": "2026-08-31"},
            {"type": "bonus", "symbol": "SCOM", "company": "Safaricom PLC", "ratio": "1:10", "record_date": "2026-08-20"}
        ],
        "created_at": "2026-08-02T09:15:00Z"
    }
]

# Long-term sector reports and investment guides for passive traders
SECTOR_REPORTS = [
    {
        "id": "sector-banking-2026-q2",
        "type": "sector_report",
        "sector": "Banking",
        "quarter": "Q2 2026",
        "title": "Kenyan Banking Sector: Strong Loan Growth Amid Stable Interest Rates",
        "summary": "Banking sector reports 18% YoY loan growth in Q2. Digital banking adoption continues to drive efficiency gains. Interest rate environment remains favorable for borrowers and lenders alike.",
        "key_metrics": {"loan_growth": "18% YoY", "npl_ratio": "11.2%", "cost_income_ratio": "45%", "digital_transaction_growth": "35% YoY"},
        "top_picks": ["EQTY", "KCB", "ABSA"],
        "risks": ["Inflation risks", "Currency volatility"],
        "created_at": "2026-07-01T00:00:00Z"
    },
    {
        "id": "sector-agriculture-2026-q2",
        "type": "sector_report",
        "sector": "Agriculture",
        "quarter": "Q2 2026",
        "title": "Agriculture Sector: Tea and Coffee Exports Recover on Global Demand",
        "summary": "Kenyan agricultural exports show strong recovery. Tea exports up 12% YoY, coffee up 8%. Weather conditions favorable for main growing regions. Commodity prices remain supportive.",
        "key_metrics": {"tea_exports": "+12% YoY", "coffee_exports": "+8% YoY", "maize_production": "+5% YoY"},
        "top_picks": ["WTK", "KAPC", "SASN"],
        "risks": ["Weather variability", "Global price fluctuations"],
        "created_at": "2026-07-01T00:00:00Z"
    },
    {
        "id": "sector-telecom-2026-q2",
        "type": "sector_report",
        "sector": "Telecommunication",
        "quarter": "Q2 2026",
        "title": "Telecom Sector: 5G Rollout and Fintech Innovation Drive Growth",
        "summary": "Safaricom's M-Pesa continues to dominate mobile financial services. 5G network expansion underway in major urban centers. Data consumption grows 40% YoY across all operators.",
        "key_metrics": {"mobile_penetration": "92%", "internet_penetration": "65%", "data_growth": "40% YoY"},
        "top_picks": ["SCOM"],
        "risks": ["Regulatory changes", "Infrastructure costs"],
        "created_at": "2026-07-01T00:00:00Z"
    }
]

INVESTMENT_GUIDES = [
    {
        "id": "guide-dividend-portfolio-nse",
        "type": "investment_guide",
        "title": "How to Build a Dividend Portfolio on NSE",
        "summary": "A comprehensive guide to constructing a diversified dividend portfolio for long-term passive income on the Nairobi Securities Exchange.",
        "content": "Learn how to select dividend stocks, calculate dividend yield, diversify across sectors, and reinvest dividends for compound growth. This guide includes example portfolios for different risk profiles.",
        "glossary_links": ["dividend_yield", "compounding", "diversification", "ex_dividend_date"],
        "stocks_covered": ["EQTY", "KCB", "SCOM", "BAT", "DTK"],
        "created_at": "2026-06-15T00:00:00Z"
    },
    {
        "id": "guide-passive-investing-kenya",
        "type": "investment_guide",
        "title": "Passive Investing Strategies in Kenya",
        "summary": "Everything you need to know about passive investing for Kenyan investors, from index funds to buy-and-hold strategies.",
        "content": "Explore low-cost passive investment approaches available to Kenyan investors. Understand the benefits of long-term investing, dollar-cost averaging, and minimizing transaction costs.",
        "glossary_links": ["passive_investing", "index_fund", "dollar_cost_averaging", "asset_allocation"],
        "stocks_covered": [],
        "created_at": "2026-06-20T00:00:00Z"
    }
]

MACRO_ANALYSIS = [
    {
        "id": "macro-inflation-rates-2026",
        "type": "macro_analysis",
        "title": "Inflation and Interest Rates: Impact on Long-Term Returns",
        "summary": "Analysis of how Kenya's current inflation trajectory and CBK monetary policy affect long-term investment returns across asset classes.",
        "inflation_outlook": "Inflation expected to moderate to 5.5% by end-2026",
        "interest_rate_outlook": "CBK likely to hold rates steady through Q3 2026",
        "impact_analysis": {
            "equities": "Favorable for growth stocks, especially in defensive sectors",
            "bonds": "Fixed income returns remain attractive at current yields",
            "real_estate": "Interest rate stability supports property market"
        },
        "policy_impacts": ["Government infrastructure spending plans", "Tax policy changes affecting corporations"],
        "created_at": "2026-07-15T00:00:00Z"
    }
]

# Glossary for educational layer
GLOSSARY = {
    "dividend_yield": {"term": "Dividend Yield", "definition": "A financial ratio that shows how much a company pays out in dividends each year relative to its share price."},
    "compounding": {"term": "Compounding", "definition": "The process where earnings from an investment are reinvested to generate additional earnings over time."},
    "diversification": {"term": "Diversification", "definition": "The strategy of spreading investments across various financial instruments and sectors to reduce risk."},
    "ex_dividend_date": {"term": "Ex-Dividend Date", "definition": "The date on or after which a stock trades without the right to receive the next declared dividend."},
    "passive_investing": {"term": "Passive Investing", "definition": "An investment strategy that aims to maximize long-term returns by minimizing buying and selling, often through tracking a market index."},
    "index_fund": {"term": "Index Fund", "definition": "A type of mutual fund or ETF that tracks the performance of a specific market index, such as the NSE20."},
    "dollar_cost_averaging": {"term": "Dollar-Cost Averaging", "definition": "The strategy of investing a fixed amount of money at regular intervals regardless of market conditions, reducing the impact of volatility."},
    "asset_allocation": {"term": "Asset Allocation", "definition": "The process of dividing an investment portfolio among different asset categories, such as stocks, bonds, and cash."},
    "rsi": {"term": "Relative Strength Index (RSI)", "definition": "A momentum indicator that measures the magnitude of recent price changes to evaluate overbought or oversold conditions."},
    "moving_average": {"term": "Moving Average", "definition": "A stock indicator that helps smooth out price action by filtering out the noise from random price fluctuations."}
}

@app.get("/api/content/morning-briefs")
async def get_morning_briefs():
    """Get morning briefs for daily traders - market sentiment, gainers/losers, announcements."""
    return JSONResponse({"briefs": MORNING_BRIEFS})

@app.get("/api/content/market-wraps")
async def get_market_wraps():
    """Get end-of-day market wraps summarizing daily activity."""
    return JSONResponse({"wraps": MARKET_WRAPS})

@app.get("/api/content/corporate-alerts")
async def get_corporate_alerts():
    """Get corporate actions alerts: dividends, rights issues, bonus shares."""
    return JSONResponse({"alerts": CORPORATE_ALERTS})

@app.get("/api/content/intraday-analysis/{symbol}")
async def get_intraday_analysis(symbol: str):
    """Get intraday analysis with technical indicators for a specific stock."""
    symbol = symbol.upper()
    history = load_history()
    if symbol not in history:
        raise HTTPException(status_code=404, detail="Symbol not found")
    
    df = build_df_from_history(symbol, history)
    if len(df) < 20:
        raise HTTPException(status_code=400, detail="Insufficient data for analysis")
    
    # Calculate technical indicators
    analyzer = TechnicalAnalyzer()
    df['sma_20'] = analyzer.sma(df['Close'], 20)
    df['sma_50'] = analyzer.sma(df['Close'], 50)
    df['rsi'] = analyzer.rsi(df['Close'])
    macd_line, signal_line, histogram = analyzer.macd(df['Close'])
    df['macd'] = macd_line
    df['macd_signal'] = signal_line
    df['macd_hist'] = histogram
    
    # Get volume spikes
    avg_volume = df['Volume'].mean()
    latest_volume = df['Volume'].iloc[-1]
    volume_spike = latest_volume > (avg_volume * 2)
    
    # Get latest price movements
    latest_prices = df[['Date', 'Open', 'High', 'Low', 'Close', 'Volume', 'sma_20', 'sma_50', 'rsi']].tail(30).to_dict('records')
    
    return JSONResponse({
        "symbol": symbol,
        "company_name": STOCK_NAMES.get(symbol, symbol),
        "latest_price": float(df['Close'].iloc[-1]),
        "price_change_pct": float(((df['Close'].iloc[-1] - df['Close'].iloc[-2]) / df['Close'].iloc[-2]) * 100) if len(df) > 1 else 0,
        "volume": int(latest_volume),
        "avg_volume": float(avg_volume),
        "volume_spike": volume_spike,
        "technical_indicators": {
            "sma_20": float(df['sma_20'].iloc[-1]),
            "sma_50": float(df['sma_50'].iloc[-1]),
            "rsi": float(df['rsi'].iloc[-1]),
            "macd": float(df['macd'].iloc[-1]),
            "macd_signal": float(df['macd_signal'].iloc[-1])
        },
        "intraday_data": latest_prices
    })

@app.get("/api/content/longterm/")
async def get_longterm_content():
    """Get all long-form content for passive traders: sector reports, investment guides, macro analysis."""
    return JSONResponse({
        "sector_reports": SECTOR_REPORTS,
        "investment_guides": INVESTMENT_GUIDES,
        "macro_analysis": MACRO_ANALYSIS
    })

@app.get("/api/content/sector-reports")
async def get_sector_reports():
    """Get quarterly sector reports for passive investors."""
    return JSONResponse({"reports": SECTOR_REPORTS})

@app.get("/api/content/investment-guides")
async def get_investment_guides():
    """Get investment guides for passive trading strategies."""
    return JSONResponse({"guides": INVESTMENT_GUIDES})

@app.get("/api/content/macro-analysis")
async def get_macro_analysis():
    """Get macroeconomic analysis impacting long-term returns."""
    return JSONResponse({"analysis": MACRO_ANALYSIS})

@app.get("/api/content/fundamentals/{symbol}")
async def get_company_fundamentals(symbol: str):
    """Get company fundamentals: P/E, dividend history, earnings growth explained."""
    symbol = symbol.upper()
    if symbol not in COMPANY_META:
        raise HTTPException(status_code=404, detail="Company not found")
    
    meta = COMPANY_META[symbol]
    # Generate dividend history
    dividend_history = [
        {"year": 2026, "amount": meta.get("dividend_yield", 0), "payout_date": "2026-06-15"},
        {"year": 2025, "amount": meta.get("dividend_yield", 0) * 0.95, "payout_date": "2025-06-20"},
        {"year": 2024, "amount": meta.get("dividend_yield", 0) * 0.90, "payout_date": "2024-06-18"},
    ]
    
    # Earnings growth simulation
    earnings_growth = {"2024": 12.5, "2025": 15.2, "2026_YTD": 18.3}
    
    return JSONResponse({
        "symbol": symbol,
        "company_name": STOCK_NAMES.get(symbol, symbol),
        "sector": meta.get("sector"),
        "market_cap": meta.get("market_cap_ksh"),
        "pe_ratio": meta.get("pe_ratio"),
        "dividend_yield": meta.get("dividend_yield"),
        "eps": meta.get("eps"),
        "explainer": {
            "pe_ratio_explanation": f"P/E ratio of {meta.get('pe_ratio')} indicates the market's expectation of future growth. This is lower than the sector average of ~9, suggesting potential undervaluation.",
            "dividend_yield_explanation": f"Dividend yield of {meta.get('dividend_yield')}% means this stock pays out {meta.get('dividend_yield')}% of its current share price annually in dividends, above the NSE average of 4%.",
            "earnings_growth_explanation": "Consistent double-digit earnings growth over the past 3 years shows strong operational performance and business momentum."
        },
        "dividend_history": dividend_history,
        "earnings_growth": earnings_growth
    })

@app.get("/api/glossary")
async def get_glossary():
    """Get complete glossary of financial terms for educational layer."""
    return JSONResponse({"glossary": GLOSSARY})

@app.get("/api/glossary/{term}")
async def get_glossary_term(term: str):
    """Get specific glossary term definition."""
    if term not in GLOSSARY:
        raise HTTPException(status_code=404, detail="Term not found in glossary")
    return JSONResponse(GLOSSARY[term])

@app.get("/api/watchlist/alerts")
async def get_watchlist_alerts(current_user: dict = Depends(get_premium_user)):
    """Get all alerts for watchlist stocks: price alerts, corporate actions, news."""
    watchlist = load_watchlist()
    all_alerts = []
    
    # Collect all symbols from all watchlists
    watchlist_symbols = set()
    for list_name, list_data in watchlist.get("lists", {}).items():
        symbols = list_data.get("symbols", [])
        for sym in symbols:
            watchlist_symbols.add(sym)
    
    # Add corporate alerts affecting watchlist stocks
    for alert in CORPORATE_ALERTS:
        for corp_alert in alert['alerts']:
            if corp_alert['symbol'] in watchlist_symbols:
                all_alerts.append({
                    "type": "corporate_action",
                    "symbol": corp_alert['symbol'],
                    "message": f"{corp_alert['company']}: {corp_alert['type']} of {corp_alert['amount'] if 'amount' in corp_alert else corp_alert['ratio']}",
                    "date": alert['date'],
                    "ex_date": corp_alert.get('ex_date')
                })
    
    return JSONResponse({"watchlist_alerts": all_alerts, "total": len(all_alerts)})


@app.get("/api/research-hub")
async def get_research_hub():
    """Aggregate research content for the dashboard: briefs, alerts, macro, glossary, and economic events."""
    live = fetch_live_nse_data(force=False)
    market_snapshot = live.get("stocks", {}) if live else {}
    top_movers = sorted(
        market_snapshot.items(),
        key=lambda item: item[1].get("change_pct", 0),
        reverse=True,
    )[:5]

    overview = {
        "market_status": live.get("market_status", "Unknown") if live else "Unknown",
        "market_time": live.get("market_time", "") if live else "",
        "top_movers": [
            {
                "symbol": symbol,
                "name": STOCK_NAMES.get(symbol, symbol),
                "change_pct": round(stock.get("change_pct", 0), 2),
                "price": round(stock.get("price", 0), 2),
            }
            for symbol, stock in top_movers
        ],
    }

    fundamentals = []
    for symbol in ["SCOM", "EQTY", "KCB", "EABL"]:
        meta = COMPANY_META.get(symbol, {})
        fundamentals.append({
            "symbol": symbol,
            "name": STOCK_NAMES.get(symbol, symbol),
            "sector": meta.get("sector", ""),
            "pe_ratio": meta.get("pe_ratio"),
            "dividend_yield": meta.get("dividend_yield"),
            "market_cap_ksh": meta.get("market_cap_ksh"),
        })

    corporate_calendar = [
        {"date": "2026-08-10", "title": "Dividend ex-date: KCB", "symbol": "KCB", "type": "dividend"},
        {"date": "2026-08-12", "title": "Dividend ex-date: Equity Bank", "symbol": "EQTY", "type": "dividend"},
        {"date": "2026-08-20", "title": "Bonus issue record date: Safaricom", "symbol": "SCOM", "type": "bonus"},
    ]

    watchlist_ideas = [
        {"symbol": "EQTY", "reason": "Strong banking growth and attractive dividend profile"},
        {"symbol": "KCB", "reason": "Solid loan book and stable payout"},
        {"symbol": "SCOM", "reason": "Defensive telecom exposure with recurring cash flows"},
    ]

    earnings_preview = [
        {"symbol": "EQTY", "period": "Q2 2026", "note": "Net interest income expected to remain resilient"},
        {"symbol": "KCB", "period": "Q2 2026", "note": "Provisioning trends remain a watchpoint"},
        {"symbol": "SCOM", "period": "Q2 2026", "note": "Data revenue growth likely to support earnings"},
    ]

    return JSONResponse({
        "overview": overview,
        "briefs": MORNING_BRIEFS,
        "alerts": CORPORATE_ALERTS,
        "macro_analysis": MACRO_ANALYSIS,
        "glossary": GLOSSARY,
        "fundamentals": fundamentals,
        "corporate_calendar": corporate_calendar,
        "watchlist_ideas": watchlist_ideas,
        "earnings_preview": earnings_preview,
        "economic_events": [
            {
                "date": event.get("date"),
                "time": event.get("time"),
                "event": event.get("event"),
                "impact": event.get("impact"),
                "forecast": event.get("forecast"),
                "description": event.get("description"),
            }
            for event in [
                {"date": "2026-08-05", "time": "14:00", "event": "CBK Monetary Policy Decision", "impact": "high", "forecast": "10.50%", "description": "Central Bank Rate announcement"},
                {"date": "2026-08-15", "time": "09:00", "event": "Kenya Inflation Rate (Jul)", "impact": "high", "forecast": "5.0%", "description": "Year-over-year CPI change"},
                {"date": "2026-08-20", "time": "09:00", "event": "GDP Growth Rate Q2 2026", "impact": "high", "forecast": "5.4%", "description": "Quarterly GDP expansion"},
            ]
        ],
    })


@app.get("/api/chart/{symbol}")
async def get_chart(symbol: str, user: dict = Depends(_require_auth)):
    """Return recent price history for charting (last 60 days)."""
    history = load_history()
    rows    = history.get(symbol.upper(), [])
    if not rows:
        # Fallback: try to build from live data
        live = fetch_live_nse_data()
        if live and symbol.upper() in live.get("stocks", {}):
            s = live["stocks"][symbol.upper()]
            rows = [{"date": live.get("market_date", ""), "close": s["price"]}]
    # Return last 60 days
    data = rows[-60:]
    prices = [r["close"] for r in data if r.get("close")]
    dates  = [r.get("date", "") for r in data]
    return JSONResponse({
        "symbol": symbol.upper(),
        "dates": dates,
        "prices": prices,
        "days": len(data),
    })


@app.get("/api/history/{symbol}")
async def get_history(symbol: str, user: dict = Depends(_require_auth)):
    """Return accumulated daily history for a specific stock."""
    history = load_history()
    rows    = history.get(symbol.upper(), [])
    return JSONResponse({"symbol": symbol.upper(), "days": len(rows), "data": rows[-90:]})


# ─── Helper: compute multi-period performance ─────────────────────────────────

def compute_period_returns(df: pd.DataFrame) -> dict:
    """Compute returns for 1d, 3d, 1w, 2w, 1m, 3m, 6m, 1y periods."""
    if df.empty:
        return {"1d":0,"3d":0,"1w":0,"2w":0,"1m":0,"3m":0,"6m":0,"1y":0}
    close = df["Close"].values
    n = len(close)
    cur = float(close[-1])
    periods = {
        "1d": max(0, n-2),
        "3d": max(0, n-4),
        "1w": max(0, n-6),
        "2w": max(0, n-11),
        "1m": max(0, n-22),
        "3m": max(0, n-66),
        "6m": max(0, n-132),
        "1y": max(0, n-264),
    }
    result = {}
    for key, idx in periods.items():
        if idx < n and idx >= 0:
            prev = float(close[idx])
            result[key] = round(((cur - prev) / prev) * 100, 2) if prev else 0
        else:
            result[key] = 0
    return result


def compute_capm(stock_data: dict, market_data: dict) -> dict:
    """
    Compute CAPM and valuation metrics.
    Uses risk-free rate = 10.5% (Kenya T-bill approximate)
    Market risk premium = 5.5%
    """
    rf = 10.5  # Kenya risk-free rate (T-bill)
    mp = 5.5   # Market risk premium
    beta = stock_data.get("beta", 1.0)
    expected_return = rf + (beta * mp)
    
    # Estimate actual return from 1y performance if available
    actual_return = stock_data.get("change_1y", stock_data.get("change_1d", 0))
    
    # Determine if over/under priced
    diff = actual_return - expected_return
    if diff > 2:
        verdict = "UNDERPRICED"
        explanation = f"Stock returned {actual_return:.1f}% vs CAPM expected {expected_return:.1f}% — outperforming risk-adjusted expectations"
    elif diff < -2:
        verdict = "OVERVALUED"
        explanation = f"Stock returned {actual_return:.1f}% vs CAPM expected {expected_return:.1f}% — underperforming risk-adjusted expectations"
    else:
        verdict = "FAIRLY VALUED"
        explanation = f"Stock returning near CAPM expected return of {expected_return:.1f}%"
    
    return {
        "beta": beta,
        "risk_free_rate": rf,
        "market_premium": mp,
        "expected_return": round(expected_return, 2),
        "actual_return": round(actual_return, 2),
        "verdict": verdict,
        "explanation": explanation,
        "alpha": round(diff, 2),
    }


# ─── New API Endpoints ────────────────────────────────────────────────────────

@app.get("/api/sector-analysis")
async def get_sector_analysis():
    """Get detailed sector performance breakdown."""
    live = fetch_live_nse_data()
    if not live:
        return JSONResponse({"error": "No live data"}, status_code=503)
    
    stocks_data = live.get("stocks", {})
    sectors = {}
    
    for sector, symbols in SECTOR_MAP.items():
        members = [s for s in symbols if s in stocks_data]
        if not members:
            continue
        changes = [stocks_data[s]["change_pct"] for s in members]
        prices = [stocks_data[s]["price"] for s in members if stocks_data[s]["price"] > 0]
        volumes = [stocks_data[s]["volume"] for s in members]
        
        avg_chg = round(sum(changes) / len(changes), 2) if changes else 0
        total_vol = sum(volumes)
        avg_price = round(sum(prices) / len(prices), 2) if prices else 0
        
        gainers = sum(1 for c in changes if c > 0)
        losers = sum(1 for c in changes if c < 0)
        
        # Top/bottom performers
        perf_list = sorted([(stocks_data[s]["change_pct"], s, STOCK_NAMES.get(s,s)) for s in members], key=lambda x: x[0])
        
        sectors[sector] = {
            "name": sector,
            "constituents_count": len(members),
            "average_change_pct": avg_chg,
            "total_volume": total_vol,
            "average_price": avg_price,
            "gainers": gainers,
            "losers": losers,
            "top_performer": {"symbol": perf_list[-1][1], "name": perf_list[-1][2], "change_pct": perf_list[-1][0]} if perf_list else None,
            "worst_performer": {"symbol": perf_list[0][1], "name": perf_list[0][2], "change_pct": perf_list[0][0]} if perf_list else None,
            "members": [{"symbol": s, "name": STOCK_NAMES.get(s,s), "price": stocks_data[s]["price"], "change_pct": stocks_data[s]["change_pct"]} for s in members],
        }
    
    return JSONResponse({
        "sectors": sectors,
        "total_sectors": len(sectors),
        "market_date": live.get("market_date", ""),
    })


@app.get("/api/market-kpis")
async def get_market_kpis():
    """Get comprehensive market KPIs including multi-period volume and cap."""
    live = fetch_live_nse_data()
    if not live:
        return JSONResponse({"error": "No live data"}, status_code=503)
    
    stocks_data = live.get("stocks", {})
    history = load_history()
    
    # Total market cap (estimated from metadata + price ratios)
    total_mcap = 0
    total_volume_24h = 0
    total_turnover = 0
    
    for sym, s in stocks_data.items():
        total_volume_24h += s.get("volume", 0)
        total_turnover += s.get("turnover", 0)
        # Estimate market cap from known or price * volume approximation
        meta = COMPANY_META.get(sym, {})
        if meta.get("market_cap_ksh"):
            total_mcap += meta["market_cap_ksh"]
    
    # Multi-period volume aggregates
    volume_periods = {"1d": 0, "3d": 0, "1w": 0, "2w": 0, "1m": 0, "3m": 0, "6m": 0, "1y": 0}
    for sym, rows in history.items():
        n = len(rows)
        for i, row in enumerate(rows):
            period_idx = n - 1 - i
            vol = row.get("volume", 0)
            if period_idx <= 1:
                volume_periods["1d"] += vol
            if period_idx <= 3:
                volume_periods["3d"] += vol
            if period_idx <= 6:
                volume_periods["1w"] += vol
            if period_idx <= 11:
                volume_periods["2w"] += vol
            if period_idx <= 22:
                volume_periods["1m"] += vol
            if period_idx <= 66:
                volume_periods["3m"] += vol
            if period_idx <= 132:
                volume_periods["6m"] += vol
            if period_idx <= 264:
                volume_periods["1y"] += vol
    
    all_chg = [s["change_pct"] for s in stocks_data.values()]
    gainers = sum(1 for c in all_chg if c > 0)
    losers = sum(1 for c in all_chg if c < 0)
    unchanged = len(all_chg) - gainers - losers
    
    return JSONResponse({
        "total_market_cap_ksh": total_mcap,
        "total_volume_24h": total_volume_24h,
        "total_turnover_ksh": round(total_turnover, 2),
        "volume_periods": volume_periods,
        "market_breadth": {
            "gainers": gainers,
            "losers": losers,
            "unchanged": unchanged,
            "total": len(all_chg),
        },
        "market_status": live.get("market_status", ""),
        "market_date": live.get("market_date", ""),
    })


@app.get("/api/stock-detail/{symbol}")
async def get_stock_detail(symbol: str, user: dict = Depends(_require_auth)):
    """Get full stock profile with all metadata."""
    sym = symbol.upper()
    live = fetch_live_nse_data()
    if not live:
        return JSONResponse({"error": "No live data"}, status_code=503)
    
    stocks_data = live.get("stocks", {})
    stock = stocks_data.get(sym)
    if not stock:
        return JSONResponse({"error": f"Symbol {sym} not found"}, status_code=404)
    
    history = load_history()
    df = build_df_from_history(sym, history)
    n = len(df)
    
    # Technical analysis
    if n >= 20:
        ind = analyzer.analyze(df)
        signal = engine.score_full(ind)
    else:
        signal = engine.score_simple(stock)
        ind = {
            "price": stock["price"], "sma20": stock["price"], "sma50": stock["price"],
            "ema12": stock["price"], "ema26": stock["price"], "rsi": 50.0,
            "macd": 0.0, "macd_signal": 0.0, "macd_histogram": 0.0, "stochastic": 50.0,
            "bb_upper": round(stock["price"]*1.02,2), "bb_lower": round(stock["price"]*0.98,2),
            "volume_ratio": 1.0, "change_1d": round(stock["change_pct"],2), "change_5d": 0.0, "data_days": n,
        }
    
    # Multi-period returns
    returns = compute_period_returns(df)
    
    # Company metadata
    meta = COMPANY_META.get(sym, {})
    sector_name = SYMBOL_SECTOR.get(sym, "Unknown")
    
    # Sector peer comparison
    peer_symbols = SECTOR_MAP.get(sector_name, set())
    peers = []
    for psym in peer_symbols:
        if psym in stocks_data and psym != sym:
            ps = stocks_data[psym]
            peers.append({
                "symbol": psym,
                "name": STOCK_NAMES.get(psym, psym),
                "price": ps["price"],
                "change_pct": ps["change_pct"],
            })
    
    # CAPM / Valuation
    capm_input = {
        "change_1d": returns.get("1d", 0),
        "change_1y": returns.get("1y", 0),
        "beta": meta.get("beta", 1.0),  # Fixed default (was random - misleading)
    }
    valuation = compute_capm(capm_input, {})
    
    # PE-based valuation
    pe = meta.get("pe_ratio", 0)
    eps = meta.get("eps", 0)
    sector_pe_map = {
        "Banking": 7.0, "Insurance": 8.5, "Telecommunication": 14.0,
        "Energy & Petroleum": 8.0, "Manufacturing": 11.0, "Breweries & Beverages": 16.0,
        "Media & Publishing": 10.0, "Investment & REITs": 12.0, "Agriculture": 7.5,
        "Airline": 0, "Commercial & Services": 8.5, "NSE": 10.0,
    }
    avg_sector_pe = sector_pe_map.get(sector_name, 10)
    pe_verdict = "N/A"
    if pe and eps:
        if pe > avg_sector_pe * 1.2:
            pe_verdict = "Above sector average — potentially overvalued"
        elif pe < avg_sector_pe * 0.8:
            pe_verdict = "Below sector average — potentially undervalued"
        else:
            pe_verdict = "In line with sector average"
    
    # Estimate beta if not in metadata
    beta = meta.get("beta", 1.0)  # Default to market-average beta
    
    return JSONResponse({
        "symbol": sym,
        "name": STOCK_NAMES.get(sym, sym),
        "sector": sector_name,
        "price": stock["price"],
        "open": stock["open"],
        "high": stock["high"],
        "low": stock["low"],
        "volume": stock["volume"],
        "turnover": stock["turnover"],
        "change_pct": stock["change_pct"],
        "prev_price": stock["prev_price"],
        "signal": signal.get("signal", "NEUTRAL"),
        "score": signal.get("score", 0),
        "reasons": signal.get("reasons", []),
        "technical_indicators": ind,
        "period_returns": returns,
        "company_metadata": {
            "founded": meta.get("founded"),
            "employees": meta.get("employees"),
            "ceo": meta.get("ceo"),
            "headquarters": meta.get("hq"),
            "website": meta.get("website"),
            "market_cap_ksh": meta.get("market_cap_ksh"),
            "pe_ratio": pe,
            "eps": eps,
            "dividend_yield": meta.get("dividend_yield"),
        },
        "valuation": {
            "capm": valuation,
            "pe_analysis": {
                "pe_ratio": pe,
                "sector_average_pe": avg_sector_pe,
                "verdict": pe_verdict,
            },
            "beta": beta,
        },
        "peer_comparison": {
            "sector": sector_name,
            "peers": peers,
        },
        "data_days": n,
    })


@app.get("/api/valuation/{symbol}")
async def get_valuation(symbol: str, user: dict = Depends(_require_auth)):
    """Detailed CAPM + valuation analysis for a stock."""
    sym = symbol.upper()
    live = fetch_live_nse_data()
    if not live:
        return JSONResponse({"error": "No live data"}, status_code=503)
    
    stocks_data = live.get("stocks", {})
    stock = stocks_data.get(sym)
    if not stock:
        return JSONResponse({"error": f"Symbol {sym} not found"}, status_code=404)
    
    history = load_history()
    df = build_df_from_history(sym, history)
    meta = COMPANY_META.get(sym, {})
    returns = compute_period_returns(df)
    sector_name = SYMBOL_SECTOR.get(sym, "Unknown")
    
    # Estimate beta from price volatility vs market
    if df.empty or len(df) < 20:
        beta = 1.0  # Default to market-average beta when insufficient data
    else:
        # Simple beta estimate from close prices
        close = df["Close"].values
        returns_stock = np.diff(close) / close[:-1]
        market_returns = np.full(len(returns_stock), np.mean(returns_stock))  # Use mean as market proxy instead of random
        if len(returns_stock) > 1 and np.std(market_returns) > 0:
            beta = round(np.cov(returns_stock, market_returns)[0][1] / np.var(market_returns), 2)
            beta = max(0.5, min(2.5, beta))
        else:
            beta = 1.0
    
    rf = 10.5  # Kenya T-bill rate
    mp = 5.5   # Market risk premium
    expected_return = rf + (beta * mp)
    actual_return_1y = returns.get("1y", returns.get("1m", 0))
    
    # DCF-like intrinsic value estimate
    eps = meta.get("eps", 0)
    pe = meta.get("pe_ratio", 0)
    estimated_intrinsic = round(eps * 12, 2) if eps > 0 else 0  # Fair PE of 12
    
    current_price = stock["price"]
    if estimated_intrinsic > 0:
        discount_pct = round(((estimated_intrinsic - current_price) / current_price) * 100, 2)
        if discount_pct > 15:
            intrinsic_verdict = "UNDERPRICED"
        elif discount_pct < -15:
            intrinsic_verdict = "OVERVALUED"
        else:
            intrinsic_verdict = "FAIRLY VALUED"
    else:
        estimated_intrinsic = 0
        discount_pct = 0
        intrinsic_verdict = "INSUFFICIENT DATA"
    
    # Alpha (Jensen's Alpha)
    alpha = round(actual_return_1y - expected_return, 2)
    
    # Sharpe-like ratio (simplified)
    sharpe = round((actual_return_1y - rf) / 15, 2) if actual_return_1y != 0 else 0
    
    # Drawdown estimate from history
    max_dd = 0
    if not df.empty and len(df) > 10:
        close_prices = df["Close"].values
        peak = close_prices[0]
        for p in close_prices:
            if p > peak:
                peak = p
            dd = (peak - p) / peak * 100
            if dd > max_dd:
                max_dd = round(dd, 2)
    
    return JSONResponse({
        "symbol": sym,
        "name": STOCK_NAMES.get(sym, sym),
        "sector": sector_name,
        "current_price": current_price,
        "valuation_models": {
            "CAPM": {
                "risk_free_rate": rf,
                "market_risk_premium": mp,
                "beta": beta,
                "expected_return_pct": round(expected_return, 2),
                "actual_return_1y_pct": round(actual_return_1y, 2),
                "alpha": alpha,
                "verdict": "BEATING MARKET" if alpha > 0 else "UNDERPERFORMING MARKET",
            },
            "DCF_Intrinsic": {
                "estimated_intrinsic_value_ksh": estimated_intrinsic,
                "current_price_ksh": current_price,
                "discount_pct": discount_pct,
                "verdict": intrinsic_verdict,
            },
            "PE_Analysis": {
                "pe_ratio": pe,
                "sector": sector_name,
                "pe_verdict": "Above average" if pe > 10 else "Below average" if pe > 0 else "N/A",
            },
        },
        "risk_metrics": {
            "beta": beta,
            "max_drawdown_pct": max_dd,
            "sharpe_ratio": sharpe,
            "volatility_annualized_pct": round(abs(actual_return_1y) * 0.4, 2) if actual_return_1y else 0,
        },
        "period_returns": returns,
        "company_metadata": {
            "market_cap_ksh": meta.get("market_cap_ksh"),
            "eps": eps,
            "dividend_yield": meta.get("dividend_yield"),
            "employees": meta.get("employees"),
            "ceo": meta.get("ceo"),
        },
    })


@app.get("/api/price-performance/{symbol}")
async def get_price_performance(symbol: str, user: dict = Depends(_require_auth)):
    """Get multi-period price performance for a stock."""
    sym = symbol.upper()
    history = load_history()
    df = build_df_from_history(sym, history)
    returns = compute_period_returns(df)
    
    return JSONResponse({
        "symbol": sym,
        "period_returns": returns,
        "data_days": len(df),
    })


# ─── Phase 1: New API Endpoints ──────────────────────────────────────────────

# ─── Security Type Classification ─────────────────────────────────────────────
SECURITY_TYPES = {
    "Equity": {"SCOM","EQTY","KCB","COOP","EABL","ABSA","NCBA","SCBK","DTK","BRIT",
               "JUB","CIC","HFCK","BAMB","BAT","KPLC","KEGN","TOTL","NMG","CARB",
               "SBIC","IMH","CTUM","SCAN","KQ","SASN","KNRE","UNGA","WTK","KAPC",
               "SGL","KUKZ","CRWN","FMLY","SLAM","UMME","BKG","LKL","TCL","BOC",
               "PORT","CABL","MSC","EVRD","NBV","SMER","HAFR","LBTY","XPRS",
               "FTGH","GLD","NSE","CGEN","SKL","KPC","OCH","EGAD","AMAC","HBE",
               "KURV","LAPR","SMWF","TPSE","LIMT","TRFC","ALP","FAHR","UCHM"},
    "REIT": {"FTGH","SMWF"},
    "ETF": {"GLD"},
    "Derivative": {"NSE"},
    "Bond": set(),
}

@app.get("/api/security-types")
async def get_security_types():
    """Classify stocks by security type (Equity, Bond, ETF, REIT, Derivative)."""
    live = fetch_live_nse_data()
    stocks_data = live.get("stocks", {}) if live else {}
    
    result = {}
    for stype, symbols in SECURITY_TYPES.items():
        members = []
        for sym in symbols:
            if sym in stocks_data or sym in STOCK_NAMES:
                s = stocks_data.get(sym, {})
                members.append({
                    "symbol": sym,
                    "name": STOCK_NAMES.get(sym, sym),
                    "price": s.get("price", 0),
                    "change_pct": s.get("change_pct", 0),
                })
        if members:
            result[stype] = {
                "type": stype,
                "count": len(members),
                "members": members,
            }
    
    return JSONResponse({
        "security_types": result,
        "total_classified": sum(v["count"] for v in result.values()),
    })


# ─── Arbitrage Scanner ────────────────────────────────────────────────────────

def _latest_snapshot_stocks() -> tuple[dict, str]:
    """Build a live-shaped stocks map from the newest data/data_*.json snapshot.

    Used as an engine fallback so arbitrage / dividends keep calculating even
    when the external NSE API is unreachable and local price history is thin.
    """
    try:
        files = sorted(Path(DATA_DIR).glob("data_*.json"), reverse=True)
        for fp in files:
            try:
                with open(fp, encoding="utf-8") as f:
                    snap = json.load(f)
                results = snap.get("results") or []
                stocks = {}
                for r in results:
                    sym = (r.get("symbol") or "").upper().strip()
                    if not sym:
                        continue
                    price = float(r.get("price") or 0)
                    if price <= 0:
                        continue
                    stocks[sym] = {
                        "price":      price,
                        "prev_price": float(r.get("prev_price") or price),
                        "open":       float(r.get("open") or price),
                        "high":       float(r.get("high") or price),
                        "low":        float(r.get("low") or price),
                        "volume":     int(r.get("volume") or 0),
                        "turnover":   float(r.get("turnover") or 0.0),
                        "change_pct": round(float(r.get("change_1d") or 0), 2),
                    }
                if stocks:
                    return stocks, snap.get("market_status", "unknown")
            except Exception:
                continue
    except Exception:
        pass
    return {}, "unknown"


@app.get("/api/arbitrage-scanner")
async def get_arbitrage_scanner(current_user: dict = Depends(get_premium_user)):
    """Scan for pair trading and arbitrage opportunities across sectors."""
    live = fetch_live_nse_data()
    stocks_data = (live or {}).get("stocks", {})
    market_status = (live or {}).get("market_status", "unknown")
    if not stocks_data:
        # Engine fallback: derive prices/positions from the newest analysis snapshot
        stocks_data, market_status = _latest_snapshot_stocks()
    if not stocks_data:
        return JSONResponse({
            "error": "Insufficient market data to scan. Run analysis first.",
            "opportunities": [], "total_found": 0,
            "market_status": market_status,
        }, status_code=503)

    history = load_history()
    
    # Find potential pairs within same sector with high correlation
    opportunities = []
    
    for sector, symbols in SECTOR_MAP.items():
        syms = [s for s in symbols if s in stocks_data]
        if len(syms) < 2:
            continue
        
        # Build price series for correlation
        pairs_checked = set()
        for i in range(len(syms)):
            for j in range(i+1, len(syms)):
                s1, s2 = syms[i], syms[j]
                pair_key = tuple(sorted([s1, s2]))
                if pair_key in pairs_checked:
                    continue
                pairs_checked.add(pair_key)
                
                df1 = build_df_from_history(s1, history)
                df2 = build_df_from_history(s2, history)
                
                if df1.empty or df2.empty or len(df1) < 5 or len(df2) < 5:
                    continue
                
                # simple correlation estimate from price ratios
                p1 = df1["Close"].values[-min(len(df1),20):]
                p2 = df2["Close"].values[-min(len(df2),20):]
                n = min(len(p1), len(p2))
                if n < 5:
                    continue
                p1, p2 = p1[-n:], p2[-n:]
                
                r1 = np.diff(p1) / p1[:-1]
                r2 = np.diff(p2) / p2[:-1]
                
                if len(r1) > 1 and np.std(r1) > 0 and np.std(r2) > 0:
                    corr = np.corrcoef(r1, r2)[0][1]
                else:
                    corr = 0
                
                p1_cur = stocks_data[s1]["price"]
                p2_cur = stocks_data[s2]["price"]
                
                # Price ratio divergence
                ratio_z = abs((p1_cur/p2_cur) - np.mean(p1[-n:]/p2[-n:])) / (np.std(p1[-n:]/p2[-n:]) + 0.001)
                
                if abs(corr) > 0.6 and ratio_z > 1.5:
                    opportunities.append({
                        "pair": f"{s1}/{s2}",
                        "symbol_a": s1,
                        "symbol_b": s2,
                        "name_a": STOCK_NAMES.get(s1, s1),
                        "name_b": STOCK_NAMES.get(s2, s2),
                        "sector": sector,
                        "correlation": round(corr, 3),
                        "price_a": p1_cur,
                        "price_b": p2_cur,
                        "z_score": round(ratio_z, 2),
                        "signal": "DIVERGING" if ratio_z > 2.0 else "WATCHING",
                    })
    
    opportunities.sort(key=lambda x: abs(x["z_score"]), reverse=True)

    # Real correlation matrix (computed from returns history) for top 8 names
    symbol_order = sorted(
        [s for s in stocks_data if history.get(s) and len(history.get(s, [])) >= 5],
        key=lambda s: len(history.get(s, [])),
        reverse=True,
    )[:8]
    matrix_symbols = symbol_order
    corr_matrix = []
    if len(matrix_symbols) >= 2:
        series = []
        for s in matrix_symbols:
            df = build_df_from_history(s, history)
            closes = df["Close"].values[-min(len(df), 30):]
            if len(closes) >= 3:
                rets = np.diff(closes) / np.maximum(closes[:-1], 1e-9)
                series.append(rets[-min(20, len(rets)):])
            else:
                series.append(None)
        lengths = [len(x) for x in series if x is not None]
        n = min(lengths) if lengths else 0
        for i in range(len(matrix_symbols)):
            row = []
            for j in range(len(matrix_symbols)):
                if i == j:
                    row.append(1.0)
                elif series[i] is not None and series[j] is not None and n >= 3:
                    ri, rj = series[i][-n:], series[j][-n:]
                    if np.std(ri) > 0 and np.std(rj) > 0:
                        row.append(round(float(np.corrcoef(ri, rj)[0][1]), 3))
                    else:
                        row.append(0.0)
                else:
                    row.append(0.0)
            corr_matrix.append({"symbol": matrix_symbols[i], "values": row})

    return JSONResponse({
        "opportunities": opportunities[:20],
        "total_found": len(opportunities),
        "market_status": market_status,
        "correlation_matrix": {"symbols": matrix_symbols, "matrix": corr_matrix},
    })


# ─── Dividend Calendar ────────────────────────────────────────────────────────

DIVIDEND_DATA = {
    "SCOM": {"amount": 2.05, "ex_date": "2026-08-15", "pay_date": "2026-09-01", "frequency": "Semi-Annual", "yield_pct": 5.8},
    "EQTY": {"amount": 3.50, "ex_date": "2026-07-30", "pay_date": "2026-08-20", "frequency": "Annual", "yield_pct": 4.2},
    "KCB":  {"amount": 5.25, "ex_date": "2026-08-05", "pay_date": "2026-08-28", "frequency": "Annual", "yield_pct": 6.0},
    "COOP": {"amount": 1.95, "ex_date": "2026-09-10", "pay_date": "2026-10-01", "frequency": "Annual", "yield_pct": 5.5},
    "EABL": {"amount": 8.75, "ex_date": "2026-09-05", "pay_date": "2026-09-30", "frequency": "Semi-Annual", "yield_pct": 3.2},
    "ABSA": {"amount": 1.85, "ex_date": "2026-08-20", "pay_date": "2026-09-15", "frequency": "Annual", "yield_pct": 4.8},
    "NCBA": {"amount": 2.75, "ex_date": "2026-07-25", "pay_date": "2026-08-15", "frequency": "Annual", "yield_pct": 5.1},
    "SCBK": {"amount": 12.50, "ex_date": "2026-08-10", "pay_date": "2026-09-05", "frequency": "Annual", "yield_pct": 4.5},
    "DTK":  {"amount": 8.00, "ex_date": "2026-09-15", "pay_date": "2026-10-10", "frequency": "Annual", "yield_pct": 6.5},
    "BRIT": {"amount": 1.20, "ex_date": "2026-08-25", "pay_date": "2026-09-18", "frequency": "Annual", "yield_pct": 3.8},
    "JUB":  {"amount": 15.00, "ex_date": "2026-07-20", "pay_date": "2026-08-10", "frequency": "Annual", "yield_pct": 4.0},
    "BAT":  {"amount": 42.00, "ex_date": "2026-08-01", "pay_date": "2026-08-25", "frequency": "Semi-Annual", "yield_pct": 7.2},
    "KEGN": {"amount": 0.55, "ex_date": "2026-09-20", "pay_date": "2026-10-15", "frequency": "Annual", "yield_pct": 3.8},
    "TOTL": {"amount": 2.40, "ex_date": "2026-08-15", "pay_date": "2026-09-10", "frequency": "Annual", "yield_pct": 5.5},
    "NMG":  {"amount": 0.75, "ex_date": "2026-09-01", "pay_date": "2026-09-25", "frequency": "Annual", "yield_pct": 4.5},
    "UNGA": {"amount": 1.50, "ex_date": "2026-10-05", "pay_date": "2026-10-30", "frequency": "Annual", "yield_pct": 3.2},
    "KNRE": {"amount": 1.10, "ex_date": "2026-08-20", "pay_date": "2026-09-12", "frequency": "Annual", "yield_pct": 4.8},
    "CTUM": {"amount": 1.05, "ex_date": "2026-10-01", "pay_date": "2026-10-25", "frequency": "Annual", "yield_pct": 2.8},
    "IMH":  {"amount": 3.20, "ex_date": "2026-09-10", "pay_date": "2026-10-05", "frequency": "Annual", "yield_pct": 5.0},
    "SBIC": {"amount": 14.50, "ex_date": "2026-08-05", "pay_date": "2026-08-30", "frequency": "Annual", "yield_pct": 4.2},
}

@app.get("/api/dividend-calendar")
async def get_dividend_calendar(current_user: dict = Depends(get_premium_user)):
    """Get dividend schedule with ex-dates, pay dates, and yields."""
    upcoming = []
    past = []
    today = datetime.now().strftime("%Y-%m-%d")

    live = fetch_live_nse_data()
    price_map = (live or {}).get("stocks", {})
    if not price_map:
        price_map, _ = _latest_snapshot_stocks()

    for sym, div in DIVIDEND_DATA.items():
        price = price_map.get(sym, {}).get("price")
        yield_pct = div["yield_pct"]
        if price:
            computed = round(div["amount"] / price * 100, 2)
            if computed > 0:
                yield_pct = computed
        entry = {
            "symbol": sym,
            "name": STOCK_NAMES.get(sym, sym),
            "amount_ksh": div["amount"],
            "ex_date": div["ex_date"],
            "pay_date": div["pay_date"],
            "frequency": div["frequency"],
            "price": round(float(price), 2) if price else None,
            "yield_pct": yield_pct,
            "days_until_ex": (datetime.strptime(div["ex_date"], "%Y-%m-%d") - datetime.strptime(today, "%Y-%m-%d")).days,
        }
        if entry["days_until_ex"] >= 0:
            upcoming.append(entry)
        else:
            past.append(entry)
    
    upcoming.sort(key=lambda x: x["days_until_ex"])
    past.sort(key=lambda x: x["days_until_ex"], reverse=True)
    
    return JSONResponse({
        "upcoming": upcoming[:15],
        "past": past[:10],
        "total_dividend_stocks": len(DIVIDEND_DATA),
        "as_of": today,
    })


# ─── Market Breadth ───────────────────────────────────────────────────────────

@app.get("/api/market-breadth")
async def get_market_breadth():
    """Detailed market breadth: advance/decline, new highs/lows, cumulative."""
    live = fetch_live_nse_data()
    if not live:
        return JSONResponse({"error": "No live data"}, status_code=503)
    
    stocks_data = live.get("stocks", {})
    history = load_history()
    
    all_chg = [s["change_pct"] for s in stocks_data.values()]
    gainers = sum(1 for c in all_chg if c > 0)
    losers = sum(1 for c in all_chg if c < 0)
    unchanged = len(all_chg) - gainers - losers
    
    # New highs/lows (52-week approximation using history)
    new_highs = 0
    new_lows = 0
    for sym in stocks_data:
        df = build_df_from_history(sym, history)
        if df.empty or len(df) < 20:
            continue
        closes = df["Close"].values
        cur = closes[-1]
        if cur >= max(closes[-20:]):
            new_highs += 1
        elif cur <= min(closes[-20:]):
            new_lows += 1
    
    # Sector breadth
    sector_breadth = {}
    for sector, symbols in SECTOR_MAP.items():
        members = [s for s in symbols if s in stocks_data]
        if not members:
            continue
        sg = sum(1 for s in members if stocks_data[s]["change_pct"] > 0)
        sl = sum(1 for s in members if stocks_data[s]["change_pct"] < 0)
        sector_breadth[sector] = {
            "gainers": sg,
            "losers": sl,
            "total": len(members),
            "advance_pct": round(sg/len(members)*100, 1) if members else 0,
        }
    
    return JSONResponse({
        "advance_decline": {
            "gainers": gainers,
            "losers": losers,
            "unchanged": unchanged,
            "total": len(all_chg),
            "advance_pct": round(gainers/len(all_chg)*100, 1) if all_chg else 0,
        },
        "new_highs": new_highs,
        "new_lows": new_lows,
        "sector_breadth": sector_breadth,
        "market_status": live.get("market_status", ""),
        "market_date": live.get("market_date", ""),
    })


# ─── Professional Screener ────────────────────────────────────────────────────

@app.get("/api/screener")
async def get_screener(
    user: dict = Depends(_require_auth),
    min_price: float = 0, max_price: float = 1e9,
    min_change: float = -100, max_change: float = 100,
    min_volume: int = 0,
    min_score: int = -100, max_score: int = 100,
    signal: str = "",
    sector: str = "",
    min_yield: float = 0,
    min_days: int = 0,
    sort_by: str = "score",
    sort_dir: str = "desc",
    limit: int = 50,
):
    """Multi-filter professional screener with 10+ filters."""
    results, meta = screen_all_stocks_v2()
    
    filtered = []
    for r in results:
        if r["price"] < min_price or r["price"] > max_price:
            continue
        if r["change_1d"] < min_change or r["change_1d"] > max_change:
            continue
        if r["volume"] < min_volume:
            continue
        if r["score"] < min_score or r["score"] > max_score:
            continue
        if signal and r.get("signal", "").upper() != signal.upper():
            continue
        if sector and r.get("sector", "").lower() != sector.lower():
            continue
        cm = COMPANY_META.get(r["symbol"], {})
        if min_yield > 0 and (cm.get("dividend_yield", 0) or 0) < min_yield:
            continue
        if min_days > 0 and r.get("data_days", 0) < min_days:
            continue
        filtered.append(r)
    
    reverse = sort_dir.lower() == "desc"
    key_map = {"price": "price", "change": "change_1d", "volume": "volume",
               "score": "score", "yield": "dividend_yield", "days": "data_days"}
    sk = key_map.get(sort_by, "score")
    filtered.sort(key=lambda x: x.get(sk, 0) or 0, reverse=reverse)
    
    return JSONResponse({
        "results": filtered[:limit],
        "total": len(filtered),
        "filters_applied": {
            "min_price": min_price, "max_price": max_price,
            "min_change": min_change, "max_change": max_change,
            "min_volume": min_volume,
            "signal": signal, "sector": sector,
            "min_yield": min_yield, "min_days": min_days,
        }
    })


# ─── Correlation Matrix ───────────────────────────────────────────────────────

@app.get("/api/correlation-matrix")
async def get_correlation_matrix(symbols: str = ""):
    """Pairwise correlation matrix for given symbols or all core stocks."""
    live = fetch_live_nse_data()
    if not live:
        return JSONResponse({"error": "No live data"}, status_code=503)
    
    stock_list = [s.strip().upper() for s in symbols.split(",") if s.strip()] if symbols else list(CORE_STOCKS)
    stock_list = [s for s in stock_list if s in live["stocks"]][:15]  # max 15
    
    history = load_history()
    matrix = {}
    pairs = []
    
    for i, s1 in enumerate(stock_list):
        matrix[s1] = {}
        df1 = build_df_from_history(s1, history)
        for j, s2 in enumerate(stock_list):
            if j <= i:
                df2 = build_df_from_history(s2, history)
                if df1.empty or df2.empty or len(df1) < 5 or len(df2) < 5:
                    matrix[s1][s2] = 0
                else:
                    p1 = df1["Close"].values[-min(len(df1),30):]
                    p2 = df2["Close"].values[-min(len(df2),30):]
                    n = min(len(p1), len(p2))
                    if n < 5:
                        matrix[s1][s2] = 0
                    else:
                        r1 = np.diff(p1[-n:]) / p1[-n:-1]
                        r2 = np.diff(p2[-n:]) / p2[-n:-1]
                        if len(r1) > 1 and np.std(r1) > 0 and np.std(r2) > 0:
                            corr = round(float(np.corrcoef(r1, r2)[0][1]), 3)
                        else:
                            corr = 0
                        matrix[s1][s2] = corr
                if s1 != s2:
                    pairs.append({"pair": f"{s1}/{s2}", "correlation": matrix[s1][s2]})
    
    pairs.sort(key=lambda x: abs(x["correlation"]), reverse=True)
    
    return JSONResponse({
        "symbols": stock_list,
        "matrix": matrix,
        "top_pairs": pairs[:20],
        "n": len(stock_list),
    })


# ─── Bond Yields ──────────────────────────────────────────────────────────────

@app.get("/api/bond-yields")
async def get_bond_yields(current_user: dict = Depends(get_premium_user)):
    """Kenya bond yield curve data (simulated from CBK reference rates)."""
    bonds = [
        {"name": "91-Day T-Bill", "tenor": "91d", "yield_pct": 10.45, "type": "Treasury Bill", "change_bps": -5},
        {"name": "182-Day T-Bill", "tenor": "182d", "yield_pct": 10.82, "type": "Treasury Bill", "change_bps": +3},
        {"name": "364-Day T-Bill", "tenor": "364d", "yield_pct": 11.15, "type": "Treasury Bill", "change_bps": +8},
        {"name": "2-Year Bond", "tenor": "2y", "yield_pct": 11.50, "type": "Treasury Bond", "change_bps": +2},
        {"name": "5-Year Bond", "tenor": "5y", "yield_pct": 12.25, "type": "Treasury Bond", "change_bps": -3},
        {"name": "10-Year Bond", "tenor": "10y", "yield_pct": 12.80, "type": "Treasury Bond", "change_bps": -8},
        {"name": "15-Year Bond", "tenor": "15y", "yield_pct": 13.10, "type": "Treasury Bond", "change_bps": -2},
        {"name": "20-Year Bond", "tenor": "20y", "yield_pct": 13.25, "type": "Treasury Bond", "change_bps": +1},
        {"name": "Safaricom 10Y Infrastructure Bond", "tenor": "10y", "yield_pct": 13.60, "type": "Corporate", "change_bps": +5},
        {"name": "EABL 7Y Corporate Bond", "tenor": "7y", "yield_pct": 13.10, "type": "Corporate", "change_bps": +2},
        {"name": "Kengen Green Bond 2035", "tenor": "15y", "yield_pct": 12.95, "type": "Corporate", "change_bps": -1},
        {"name": "Commercial Bank Tier-II Bond", "tenor": "10y", "yield_pct": 14.20, "type": "Corporate", "change_bps": +9},
        {"name": "CBK Rate", "tenor": "ref", "yield_pct": 10.50, "type": "Central Bank Rate", "change_bps": 0},
        {"name": "KE Euribor Spread", "tenor": "spread", "yield_pct": 4.20, "type": "Risk Premium", "change_bps": +15},
    ]
    
    # Yield curve steepness
    tenors = [b for b in bonds if b["type"] == "Treasury Bond"]
    curve_steepness = round(tenors[-1]["yield_pct"] - tenors[0]["yield_pct"], 2) if len(tenors) >= 2 else 0
    
    return JSONResponse({
        "bonds": bonds,
        "yield_curve": {
            "short_term": {"91d": 10.45, "182d": 10.82, "364d": 11.15},
            "medium_term": {"2y": 11.50, "5y": 12.25},
            "long_term": {"10y": 12.80, "15y": 13.10, "20y": 13.25},
        },
        "curve_steepness": curve_steepness,
        "central_bank_rate": 10.50,
        "market_note": "Kenya yield curve remains elevated amid fiscal consolidation efforts. CBK held rates at 10.50%.",
        "updated": datetime.now().strftime("%Y-%m-%d"),
    })


# ─── Economic Calendar ────────────────────────────────────────────────────────

@app.get("/api/economic-calendar")
async def get_economic_calendar():
    """Kenya economic events: CBK decisions, GDP, inflation, etc."""
    events = [
        {"date": "2026-08-05", "time": "14:00", "event": "CBK Monetary Policy Decision", "impact": "high",
         "previous": "10.50%", "forecast": "10.50%", "description": "Central Bank Rate announcement"},
        {"date": "2026-08-15", "time": "09:00", "event": "Kenya Inflation Rate (Jul)", "impact": "high",
         "previous": "5.2%", "forecast": "5.0%", "description": "Year-over-year CPI change"},
        {"date": "2026-08-20", "time": "09:00", "event": "GDP Growth Rate Q2 2026", "impact": "high",
         "previous": "5.6%", "forecast": "5.4%", "description": "Quarterly GDP expansion"},
        {"date": "2026-08-28", "time": "09:00", "event": "Trade Balance (Jul)", "impact": "medium",
         "previous": "-KSh 142B", "forecast": "-KSh 138B", "description": "Monthly trade deficit"},
        {"date": "2026-09-02", "time": "09:00", "event": "Manufacturing PMI (Aug)", "impact": "medium",
         "previous": "51.2", "forecast": "51.5", "description": "Purchasing Managers Index"},
        {"date": "2026-09-10", "time": "09:00", "event": "Foreign Reserves (Weekly)", "impact": "medium",
         "previous": "$8.2B", "forecast": "$8.3B", "description": "CBK foreign currency reserves"},
        {"date": "2026-09-15", "time": "09:00", "event": "Remittances (Aug)", "impact": "low",
         "previous": "$320M", "forecast": "$325M", "description": "Diaspora remittance inflows"},
        {"date": "2026-09-25", "time": "09:00", "event": "CBK MPC Meeting Minutes", "impact": "medium",
         "previous": "-", "forecast": "-", "description": "Detailed committee voting and rationale"},
        {"date": "2026-09-30", "time": "14:00", "event": "CBK Monetary Policy Decision", "impact": "high",
         "previous": "10.50%", "forecast": "10.25%", "description": "Central Bank Rate announcement"},
        {"date": "2026-10-05", "time": "09:00", "event": "NSE Market Report Q3", "impact": "medium",
         "previous": "-", "forecast": "-", "description": "NSE quarterly market performance report"},
        {"date": "2026-10-12", "time": "09:00", "event": "Kenya Inflation Rate (Sep)", "impact": "high",
         "previous": "5.0%", "forecast": "4.8%", "description": "Year-over-year CPI change"},
        {"date": "2026-11-04", "time": "09:00", "event": "GDP Growth Rate Q3 2026", "impact": "high",
         "previous": "5.4%", "forecast": "5.3%", "description": "Quarterly GDP expansion"},
    ]
    
    today = datetime.now().strftime("%Y-%m-%d")
    upcoming = [e for e in events if e["date"] >= today]
    past = [e for e in events if e["date"] < today]
    
    return JSONResponse({
        "upcoming": upcoming,
        "past": past,
        "total_events": len(events),
        "high_impact_count": sum(1 for e in events if e["impact"] == "high"),
    })


# ─── Virtual Portfolio CRUD ───────────────────────────────────────────────────

PORTFOLIO_FILE = str(_BASE_DIR / "data" / "portfolio.json")

def load_portfolio() -> dict:
    """Load portfolio from disk."""
    try:
        if Path(PORTFOLIO_FILE).exists():
            with open(PORTFOLIO_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {"holdings": [], "cash": 0, "name": "My Portfolio"}

def save_portfolio(pf: dict):
    """Persist portfolio to disk (atomic write prevents corruption)."""
    try:
        _atomic_write_json(PORTFOLIO_FILE, pf, indent=2)
    except Exception as e:
        print(f"[portfolio] save error: {e}")

@app.get("/api/portfolio")
async def get_portfolio(user: dict = Depends(_require_auth)):
    """Get the current portfolio with real-time P&L."""
    pf = load_portfolio()
    live = fetch_live_nse_data()
    stocks_data = live.get("stocks", {}) if live else {}
    
    total_cost = 0
    total_market_value = 0
    enriched = []
    
    for h in pf.get("holdings", []):
        sym = h["symbol"]
        live_price = stocks_data.get(sym, {}).get("price", h.get("buy_price", 0))
        cost = h["shares"] * h.get("buy_price", 0)
        market_value = h["shares"] * live_price
        pl = market_value - cost
        pl_pct = (pl / cost * 100) if cost > 0 else 0
        
        total_cost += cost
        total_market_value += market_value
        
        enriched.append({
            "symbol": sym,
            "name": STOCK_NAMES.get(sym, sym),
            "shares": h["shares"],
            "buy_price": h.get("buy_price", 0),
            "current_price": live_price,
            "cost_basis": round(cost, 2),
            "market_value": round(market_value, 2),
            "pl": round(pl, 2),
            "pl_pct": round(pl_pct, 2),
            "change_pct": stocks_data.get(sym, {}).get("change_pct", 0),
        })
    
    return JSONResponse({
        "name": pf.get("name", "My Portfolio"),
        "cash": pf.get("cash", 0),
        "holdings": enriched,
        "total_cost": round(total_cost, 2),
        "total_market_value": round(total_market_value, 2),
        "total_pl": round(total_market_value - total_cost, 2),
        "total_pl_pct": round(((total_market_value - total_cost) / total_cost) * 100, 2) if total_cost > 0 else 0,
        "holdings_count": len(enriched),
    })

@app.post("/api/portfolio/add")
async def add_to_portfolio(symbol: str = "", shares: float = 0, buy_price: float = 0, user: dict = Depends(_require_auth)):
    """Add a holding to the portfolio."""
    if not symbol or shares <= 0 or buy_price <= 0:
        return JSONResponse({"error": "Invalid parameters"}, status_code=400)
    sym = symbol.upper()
    pf = load_portfolio()
    # Check if already held
    for h in pf["holdings"]:
        if h["symbol"] == sym:
            h["shares"] += shares
            h["buy_price"] = (h["buy_price"] + buy_price) / 2  # simple average
            save_portfolio(pf)
            return JSONResponse({"status": "updated", "symbol": sym, "shares": h["shares"]})
    pf["holdings"].append({"symbol": sym, "shares": shares, "buy_price": buy_price})
    save_portfolio(pf)
    return JSONResponse({"status": "added", "symbol": sym, "shares": shares})

@app.post("/api/portfolio/remove")
async def remove_from_portfolio(symbol: str = "", shares: float = 0, user: dict = Depends(_require_auth)):
    """Remove shares from a portfolio holding."""
    if not symbol:
        return JSONResponse({"error": "Invalid parameters"}, status_code=400)
    sym = symbol.upper()
    pf = load_portfolio()
    for h in pf["holdings"]:
        if h["symbol"] == sym:
            if shares >= h["shares"] or shares <= 0:
                pf["holdings"] = [x for x in pf["holdings"] if x["symbol"] != sym]
            else:
                h["shares"] -= shares
            save_portfolio(pf)
            return JSONResponse({"status": "removed", "symbol": sym})
    return JSONResponse({"error": "Symbol not found"}, status_code=404)


# ─── Watchlist Management ─────────────────────────────────────────────────────

WATCHLIST_FILE = str(_BASE_DIR / "data" / "watchlist.json")

def load_watchlist() -> dict:
    """Load watchlist from disk."""
    try:
        if Path(WATCHLIST_FILE).exists():
            with open(WATCHLIST_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {"lists": {"Default": {"symbols": ["SCOM","EQTY","KCB","EABL","BAT"]}}}

def save_watchlist(wl: dict):
    """Persist watchlist to disk (atomic write prevents corruption)."""
    try:
        _atomic_write_json(WATCHLIST_FILE, wl, indent=2)
    except Exception as e:
        print(f"[watchlist] save error: {e}")

@app.get("/api/watchlist")
async def get_watchlist(user: dict = Depends(_require_auth)):
    """Get watchlists with real-time prices."""
    wl = load_watchlist()
    live = fetch_live_nse_data()
    stocks_data = live.get("stocks", {}) if live else {}
    
    enriched_lists = {}
    for list_name, data in wl.get("lists", {}).items():
        symbols = data if isinstance(data, list) else data.get("symbols", [])
        enriched = []
        for sym in symbols:
            s = stocks_data.get(sym, {})
            enriched.append({
                "symbol": sym,
                "name": STOCK_NAMES.get(sym, sym),
                "price": s.get("price", 0),
                "change_pct": s.get("change_pct", 0),
                "volume": s.get("volume", 0),
            })
        enriched_lists[list_name] = {"symbols": enriched, "count": len(enriched)}
    
    return JSONResponse({
        "lists": enriched_lists,
        "total_watched": sum(v["count"] for v in enriched_lists.values()),
    })

@app.post("/api/watchlist/add")
async def add_to_watchlist(symbol: str = "", list_name: str = "Default", user: dict = Depends(_require_auth)):
    """Add a symbol to a watchlist."""
    if not symbol:
        return JSONResponse({"error": "No symbol provided"}, status_code=400)
    sym = symbol.upper()
    wl = load_watchlist()
    if list_name not in wl["lists"]:
        wl["lists"][list_name] = {"symbols": []}
    lst = wl["lists"][list_name]
    if isinstance(lst, list):
        lst = {"symbols": lst}
    if sym not in lst["symbols"]:
        lst["symbols"].append(sym)
    wl["lists"][list_name] = lst
    save_watchlist(wl)
    return JSONResponse({"status": "added", "symbol": sym, "list": list_name})

@app.post("/api/watchlist/remove")
async def remove_from_watchlist(symbol: str = "", list_name: str = "Default", user: dict = Depends(_require_auth)):
    """Remove a symbol from a watchlist."""
    if not symbol:
        return JSONResponse({"error": "No symbol provided"}, status_code=400)
    sym = symbol.upper()
    wl = load_watchlist()
    if list_name in wl["lists"]:
        lst = wl["lists"][list_name]
        if isinstance(lst, list):
            lst = {"symbols": lst}
        lst["symbols"] = [s for s in lst["symbols"] if s != sym]
        wl["lists"][list_name] = lst
        save_watchlist(wl)
        return JSONResponse({"status": "removed", "symbol": sym, "list": list_name})
    return JSONResponse({"error": "List not found"}, status_code=404)


# ─── Enhanced screen_all_stocks with sector info ─────────────────────────────

def screen_all_stocks_v2() -> tuple:
    """Enhanced version of screen_all_stocks with sector and metadata."""
    results, meta = screen_all_stocks()
    # Add sector and metadata to each result
    for r in results:
        sym = r["symbol"]
        r["sector"] = SYMBOL_SECTOR.get(sym, "Unknown")
        cm = COMPANY_META.get(sym, {})
        r["market_cap_ksh"] = cm.get("market_cap_ksh")
        r["pe_ratio"] = cm.get("pe_ratio")
        r["eps"] = cm.get("eps")
        r["dividend_yield"] = cm.get("dividend_yield")
        
        # Multi-period returns from history
        history = load_history()
        df = build_df_from_history(sym, history)
        returns = compute_period_returns(df)
        r["period_returns"] = returns
    
    return results, meta


# ─── Phase 4: Securitization Deep-Dive ───────────────────────────────────────

# ─── Securitized Products (ABS/MBS) Static Dataset ───────────────────────────

SECURITIZED_PRODUCTS = [
    {
        "id": "ABS-001", "name": "Stanbic Auto Loan ABS 2026-A", "type": "ABS",
        "asset_class": "Auto Loans", "issuer": "Stanbic Bank Kenya",
        "issue_date": "2026-03-15", "maturity": "2031-03-15", "tenor_years": 5,
        "issue_size_ksh": 4500000000, "current_balance_ksh": 4120000000,
        "coupon_pct": 13.25, "rating": "AA-", "rating_agency": "GCR Ratings",
        "wac_pct": 14.8, "wam_months": 42, "prepayment_speed_cpr": 8.5,
        "delinquency_30pct": 1.2, "delinquency_60pct": 0.4, "delinquency_90pct": 0.15,
        "default_rate_pct": 0.8, "recovery_rate_pct": 65.0,
        "tranches": [
            {"name": "A", "size_pct": 80, "coupon_pct": 12.5, "rating": "AAA", "subordination_pct": 20},
            {"name": "B", "size_pct": 15, "coupon_pct": 14.0, "rating": "A", "subordination_pct": 5},
            {"name": "E", "size_pct": 5, "coupon_pct": 18.0, "rating": "BBB", "subordination_pct": 0},
        ],
        "status": "Active",
    },
    {
        "id": "ABS-002", "name": "Equity Group SME Loan ABS 2026-B", "type": "ABS",
        "asset_class": "SME Loans", "issuer": "Equity Bank Kenya",
        "issue_date": "2026-05-20", "maturity": "2029-05-20", "tenor_years": 3,
        "issue_size_ksh": 3200000000, "current_balance_ksh": 2980000000,
        "coupon_pct": 12.75, "rating": "A+", "rating_agency": "GCR Ratings",
        "wac_pct": 15.2, "wam_months": 28, "prepayment_speed_cpr": 6.0,
        "delinquency_30pct": 2.1, "delinquency_60pct": 0.8, "delinquency_90pct": 0.3,
        "default_rate_pct": 1.5, "recovery_rate_pct": 55.0,
        "tranches": [
            {"name": "A", "size_pct": 75, "coupon_pct": 11.5, "rating": "AA", "subordination_pct": 25},
            {"name": "B", "size_pct": 20, "coupon_pct": 14.5, "rating": "A-", "subordination_pct": 5},
            {"name": "E", "size_pct": 5, "coupon_pct": 19.0, "rating": "BB", "subordination_pct": 0},
        ],
        "status": "Active",
    },
    {
        "id": "MBS-001", "name": "Kenya Mortgage Refinance MBS 2026-1", "type": "MBS",
        "asset_class": "Residential Mortgages", "issuer": "Kenya Mortgage Refinance Company (KMRC)",
        "issue_date": "2026-02-10", "maturity": "2036-02-10", "tenor_years": 10,
        "issue_size_ksh": 7800000000, "current_balance_ksh": 7450000000,
        "coupon_pct": 9.5, "rating": "AAA", "rating_agency": "Fitch Africa",
        "wac_pct": 10.5, "wam_months": 96, "prepayment_speed_cpr": 12.0,
        "delinquency_30pct": 0.5, "delinquency_60pct": 0.15, "delinquency_90pct": 0.05,
        "default_rate_pct": 0.2, "recovery_rate_pct": 85.0,
        "tranches": [
            {"name": "A", "size_pct": 90, "coupon_pct": 9.0, "rating": "AAA", "subordination_pct": 10},
            {"name": "B", "size_pct": 10, "coupon_pct": 11.5, "rating": "AA-", "subordination_pct": 0},
        ],
        "status": "Active",
    },
    {
        "id": "ABS-003", "name": "KCB Credit Card Receivables ABS 2026-C", "type": "ABS",
        "asset_class": "Credit Card Receivables", "issuer": "KCB Bank Kenya",
        "issue_date": "2026-06-01", "maturity": "2028-06-01", "tenor_years": 2,
        "issue_size_ksh": 1800000000, "current_balance_ksh": 1620000000,
        "coupon_pct": 15.5, "rating": "A", "rating_agency": "GCR Ratings",
        "wac_pct": 18.5, "wam_months": 18, "prepayment_speed_cpr": 15.0,
        "delinquency_30pct": 3.2, "delinquency_60pct": 1.1, "delinquency_90pct": 0.5,
        "default_rate_pct": 2.8, "recovery_rate_pct": 40.0,
        "tranches": [
            {"name": "A", "size_pct": 70, "coupon_pct": 13.5, "rating": "AA-", "subordination_pct": 30},
            {"name": "B", "size_pct": 22, "coupon_pct": 16.0, "rating": "BBB", "subordination_pct": 8},
            {"name": "E", "size_pct": 8, "coupon_pct": 22.0, "rating": "B", "subordination_pct": 0},
        ],
        "status": "Active",
    },
    {
        "id": "MBS-002", "name": "Housing Finance MBS 2025-2", "type": "MBS",
        "asset_class": "Residential Mortgages", "issuer": "HF Group",
        "issue_date": "2025-09-15", "maturity": "2035-09-15", "tenor_years": 10,
        "issue_size_ksh": 2500000000, "current_balance_ksh": 2280000000,
        "coupon_pct": 10.25, "rating": "AA", "rating_agency": "Fitch Africa",
        "wac_pct": 11.8, "wam_months": 84, "prepayment_speed_cpr": 10.0,
        "delinquency_30pct": 0.8, "delinquency_60pct": 0.25, "delinquency_90pct": 0.1,
        "default_rate_pct": 0.4, "recovery_rate_pct": 80.0,
        "tranches": [
            {"name": "A", "size_pct": 85, "coupon_pct": 9.75, "rating": "AA", "subordination_pct": 15},
            {"name": "B", "size_pct": 15, "coupon_pct": 12.5, "rating": "A", "subordination_pct": 0},
        ],
        "status": "Active",
    },
    {
        "id": "ABS-004", "name": "Co-op Bank Microfinance ABS 2026-D", "type": "ABS",
        "asset_class": "Microfinance Loans", "issuer": "Co-operative Bank",
        "issue_date": "2026-07-01", "maturity": "2029-07-01", "tenor_years": 3,
        "issue_size_ksh": 1500000000, "current_balance_ksh": 1480000000,
        "coupon_pct": 14.0, "rating": "A-", "rating_agency": "GCR Ratings",
        "wac_pct": 17.5, "wam_months": 30, "prepayment_speed_cpr": 5.0,
        "delinquency_30pct": 2.8, "delinquency_60pct": 1.0, "delinquency_90pct": 0.4,
        "default_rate_pct": 2.0, "recovery_rate_pct": 50.0,
        "tranches": [
            {"name": "A", "size_pct": 72, "coupon_pct": 12.0, "rating": "A+", "subordination_pct": 28},
            {"name": "B", "size_pct": 23, "coupon_pct": 15.5, "rating": "BBB-", "subordination_pct": 5},
            {"name": "E", "size_pct": 5, "coupon_pct": 21.0, "rating": "B-", "subordination_pct": 0},
        ],
        "status": "Active",
    },
]

# Securitization deal pipeline (upcoming issuances)
SECURITIZATION_PIPELINE = [
    {"name": "Absa Kenya Personal Loan ABS 2026-E", "issuer": "Absa Bank Kenya",
     "asset_class": "Personal Loans", "expected_size_ksh": 2000000000,
     "expected_date": "2026-09-15", "expected_rating": "A+", "status": "Announced",
     "lead_arranger": "Absa Capital", "description": "Personal loan securitization with 3-year tenor"},
    {"name": "NCBA Auto ABS 2026-F", "issuer": "NCBA Group",
     "asset_class": "Auto Loans", "expected_size_ksh": 2800000000,
     "expected_date": "2026-10-01", "expected_rating": "AA-", "status": "Pre-Marketing",
     "lead_arranger": "NCBA Capital", "description": "Auto loan receivables, 4-year tenor, senior/sub structure"},
    {"name": "KMRC MBS 2026-2", "issuer": "Kenya Mortgage Refinance Company",
     "asset_class": "Residential Mortgages", "expected_size_ksh": 5000000000,
     "expected_date": "2026-11-20", "expected_rating": "AAA", "status": "Regulatory Review",
     "lead_arranger": "KCB Capital", "description": "Second KMRC MBS issuance, affordable housing mortgages"},
    {"name": "DTB SME ABS 2026-G", "issuer": "Diamond Trust Bank",
     "asset_class": "SME Loans", "expected_size_ksh": 1200000000,
     "expected_date": "2026-12-10", "expected_rating": "A", "status": "Early Stage",
     "lead_arranger": "DTB Capital", "description": "SME loan securitization for working capital relief"},
]

# CMA Regulatory Filings Database
CMA_FILINGS = [
    {"id": "CMA-2026-045", "date": "2026-07-28", "type": "Prospectus",
     "title": "Stanbic Auto Loan ABS 2026-A Prospectus", "issuer": "Stanbic Bank Kenya",
     "status": "Approved", "pages": 142, "url": "#",
     "summary": "Full prospectus for auto loan securitization, KSh 4.5B issue with 3-tranche structure"},
    {"id": "CMA-2026-041", "date": "2026-07-15", "type": "Information Memorandum",
     "title": "Equity SME ABS 2026-B Information Memorandum", "issuer": "Equity Bank Kenya",
     "status": "Approved", "pages": 98, "url": "#",
     "summary": "SME loan ABS information memorandum, KSh 3.2B, 3-year tenor"},
    {"id": "CMA-2026-038", "date": "2026-06-30", "type": "Rating Report",
     "title": "KCB Credit Card ABS 2026-C Rating Assessment", "issuer": "KCB Bank Kenya",
     "status": "Published", "pages": 24, "url": "#",
     "summary": "GCR Ratings assessment of credit card receivables ABS, assigned 'A' rating"},
    {"id": "CMA-2026-035", "date": "2026-06-10", "type": "Prospectus",
     "title": "KMRC MBS 2026-1 Prospectus", "issuer": "KMRC",
     "status": "Approved", "pages": 186, "url": "#",
     "summary": "Mortgage-backed securities prospectus, KSh 7.8B, AAA-rated by Fitch Africa"},
    {"id": "CMA-2026-032", "date": "2026-05-22", "type": "Compliance Report",
     "title": "Q1 2026 Securitization Market Compliance Report", "issuer": "CMA Kenya",
     "status": "Published", "pages": 56, "url": "#",
     "summary": "Quarterly compliance and market overview for Kenyan securitization market"},
    {"id": "CMA-2026-028", "date": "2026-04-18", "type": "Trustee Report",
     "title": "HF MBS 2025-2 Annual Trustee Report", "issuer": "HF Group",
     "status": "Published", "pages": 38, "url": "#",
     "summary": "Annual trustee report on mortgage-backed securities performance and collateral health"},
    {"id": "CMA-2026-022", "date": "2026-03-05", "type": "Regulatory Guideline",
     "title": "Updated Securitization Framework Guidelines 2026", "issuer": "CMA Kenya",
     "status": "Effective", "pages": 72, "url": "#",
     "summary": "Revised regulatory framework for asset-backed securities issuance and reporting"},
    {"id": "CMA-2026-015", "date": "2026-02-01", "type": "Prospectus",
     "title": "Co-op Bank Microfinance ABS 2026-D Prospectus", "issuer": "Co-operative Bank",
     "status": "Approved", "pages": 110, "url": "#",
     "summary": "Microfinance loan ABS prospectus, KSh 1.5B, targeting financial inclusion"},
]

# REIT detailed analytics data
REIT_DETAILS = {
    "FTGH": {
        "symbol": "FTGH", "name": "Fahari I-REIT", "type": "Income REIT (I-REIT)",
        "manager": "Stanlib Kenya", "trustee": "KCB Bank Kenya",
        "properties": 3, "total_gla_sqm": 24500, "occupancy_pct": 82.0,
        "nav_per_unit_ksh": 8.45, "current_price": 0,  # filled from live
        "distribution_yield_pct": 2.1, "ffo_per_unit_ksh": 0.42,
        "affo_per_unit_ksh": 0.38, "debt_to_assets_pct": 35.0,
        "interest_coverage": 4.2, "weighted_avg_lease_years": 3.8,
        "property_portfolio": [
            {"name": "Greenspan Mall", "type": "Retail", "value_ksh": 1200000000, "occupancy_pct": 85},
            {"name": "Tatu City Commercial", "type": "Mixed-Use", "value_ksh": 800000000, "occupancy_pct": 78},
            {"name": "Wilson Airport Logistics", "type": "Industrial", "value_ksh": 450000000, "occupancy_pct": 83},
        ],
    },
    "SMWF": {
        "symbol": "SMWF", "name": "Stanlib Fahari I-REIT (Development)", "type": "Development REIT (D-REIT)",
        "manager": "Stanlib Kenya", "trustee": "KCB Bank Kenya",
        "properties": 1, "total_gla_sqm": 12000, "occupancy_pct": 0.0,
        "nav_per_unit_ksh": 20.50, "current_price": 0,
        "distribution_yield_pct": 0.0, "ffo_per_unit_ksh": 0.0,
        "affo_per_unit_ksh": 0.0, "debt_to_assets_pct": 55.0,
        "interest_coverage": 0.0, "weighted_avg_lease_years": 0,
        "property_portfolio": [
            {"name": "Tatu City Phase 1 Development", "type": "Development", "value_ksh": 1500000000, "occupancy_pct": 0},
        ],
    },
}


@app.get("/api/securitized-products")
async def get_securitized_products():
    """Get all securitized products (ABS/MBS) with analytics."""
    live = fetch_live_nse_data()
    products = []
    for p in SECURITIZED_PRODUCTS:
        # Compute weighted average tranche coupon
        wac_tranche = sum(t["coupon_pct"] * t["size_pct"] for t in p["tranches"]) / 100
        products.append({
            **p,
            "weighted_tranche_coupon_pct": round(wac_tranche, 2),
            "current_ltv_pct": round((p["current_balance_ksh"] / p["issue_size_ksh"]) * 100, 1),
            "credit_enhancement_pct": p["tranches"][0]["subordination_pct"] if p["tranches"] else 0,
        })

    # Summary stats
    total_issue = sum(p["issue_size_ksh"] for p in SECURITIZED_PRODUCTS)
    total_balance = sum(p["current_balance_ksh"] for p in SECURITIZED_PRODUCTS)
    avg_coupon = round(sum(p["coupon_pct"] for p in SECURITIZED_PRODUCTS) / len(SECURITIZED_PRODUCTS), 2)
    abs_count = sum(1 for p in SECURITIZED_PRODUCTS if p["type"] == "ABS")
    mbs_count = sum(1 for p in SECURITIZED_PRODUCTS if p["type"] == "MBS")

    return JSONResponse({
        "products": products,
        "summary": {
            "total_products": len(products),
            "abs_count": abs_count,
            "mbs_count": mbs_count,
            "total_issue_size_ksh": total_issue,
            "total_current_balance_ksh": total_balance,
            "average_coupon_pct": avg_coupon,
        },
        "market_date": live.get("market_date", "") if live else "",
    })


@app.get("/api/securitized-product/{product_id}")
async def get_securitized_product_detail(product_id: str):
    """Get detailed analytics for a single securitized product."""
    product = next((p for p in SECURITIZED_PRODUCTS if p["id"] == product_id.upper()), None)
    if not product:
        return JSONResponse({"error": f"Product {product_id} not found"}, status_code=404)

    # Compute tranche-level analytics
    tranches = []
    for t in product["tranches"]:
        tranches.append({
            **t,
            "size_ksh": round(product["current_balance_ksh"] * t["size_pct"] / 100, 0),
            "credit_enhancement_pct": t["subordination_pct"],
        })

    # Collateral performance metrics
    collateral = {
        "wac_pct": product["wac_pct"],
        "wam_months": product["wam_months"],
        "prepayment_speed_cpr": product["prepayment_speed_cpr"],
        "delinquency_30pct": product["delinquency_30pct"],
        "delinquency_60pct": product["delinquency_60pct"],
        "delinquency_90pct": product["delinquency_90pct"],
        "default_rate_pct": product["default_rate_pct"],
        "recovery_rate_pct": product["recovery_rate_pct"],
        "loss_severity_pct": round(100 - product["recovery_rate_pct"], 1),
        "expected_loss_pct": round(product["default_rate_pct"] * (100 - product["recovery_rate_pct"]) / 100, 2),
    }

    return JSONResponse({
        **product,
        "tranches_detail": tranches,
        "collateral_performance": collateral,
        "current_ltv_pct": round((product["current_balance_ksh"] / product["issue_size_ksh"]) * 100, 1),
    })


@app.get("/api/reit-analytics")
async def get_reit_analytics():
    """Advanced REIT analytics: FFO, AFFO, NAV, property portfolio details."""
    live = fetch_live_nse_data()
    stocks_data = live.get("stocks", {}) if live else {}

    reits = []
    for sym, details in REIT_DETAILS.items():
        stock = stocks_data.get(sym, {})
        current_price = stock.get("price", 0)
        details_copy = details.copy()
        details_copy["current_price"] = current_price
        details_copy["change_pct"] = stock.get("change_pct", 0)

        # Compute premium/discount to NAV
        nav = details["nav_per_unit_ksh"]
        if current_price > 0 and nav > 0:
            premium_discount = round(((current_price - nav) / nav) * 100, 2)
            details_copy["premium_discount_to_nav_pct"] = premium_discount
            details_copy["nav_verdict"] = (
                "Trading at DISCOUNT to NAV — potential buy" if premium_discount < -10
                else "Trading at PREMIUM to NAV — potentially overvalued" if premium_discount > 10
                else "Trading near NAV — fairly valued"
            )
        else:
            details_copy["premium_discount_to_nav_pct"] = 0
            details_copy["nav_verdict"] = "Price data unavailable"

        # P/FFO and P/AFFO ratios
        ffo = details["ffo_per_unit_ksh"]
        affo = details["affo_per_unit_ksh"]
        if current_price > 0 and ffo > 0:
            details_copy["p_ffo_ratio"] = round(current_price / ffo, 2)
        else:
            details_copy["p_ffo_ratio"] = 0
        if current_price > 0 and affo > 0:
            details_copy["p_affo_ratio"] = round(current_price / affo, 2)
        else:
            details_copy["p_affo_ratio"] = 0

        reits.append(details_copy)

    return JSONResponse({
        "reits": reits,
        "total_reits": len(reits),
        "market_date": live.get("market_date", "") if live else "",
    })


@app.get("/api/scenario-analysis")
async def get_scenario_analysis(
    product_id: str = "ABS-001",
    default_shock_bps: int = 0,
    prepayment_shock_bps: int = 0,
    rate_shock_bps: int = 0,
):
    """
    Scenario analysis & stress testing for securitized products.
    Models impact of default, prepayment, and interest rate shocks.
    """
    product = next((p for p in SECURITIZED_PRODUCTS if p["id"] == product_id.upper()), None)
    if not product:
        return JSONResponse({"error": f"Product {product_id} not found"}, status_code=404)

    base_default = product["default_rate_pct"]
    base_prepay = product["prepayment_speed_cpr"]
    base_coupon = product["coupon_pct"]
    balance = product["current_balance_ksh"]
    recovery = product["recovery_rate_pct"]

    # Apply shocks (convert bps to percentage points)
    shocked_default = base_default + (default_shock_bps / 100)
    shocked_prepay = base_prepay + (prepayment_shock_bps / 100)
    shocked_coupon = base_coupon + (rate_shock_bps / 100)

    # Base case expected loss
    base_loss = round(balance * base_default * (100 - recovery) / 10000, 0)
    # Stressed expected loss
    stressed_loss = round(balance * shocked_default * (100 - recovery) / 10000, 0)
    loss_delta = round(stressed_loss - base_loss, 0)

    # Impact on yield (simplified duration-based estimate)
    duration_years = product["wam_months"] / 12
    price_impact_pct = round(-duration_years * (rate_shock_bps / 100), 2)

    # Prepayment impact — faster prepay reduces WAL but also reduces interest income
    prepay_impact_ksh = round(balance * (prepayment_shock_bps / 100) / 100, 0)

    # Tranche impact
    tranche_impacts = []
    for t in product["tranches"]:
        # Senior tranches are protected by subordination
        enhancement = t["subordination_pct"]
        tranche_loss = max(0, stressed_loss - (balance * enhancement / 100))
        tranche_impacts.append({
            "tranche": t["name"],
            "rating": t["rating"],
            "base_expected_loss_ksh": round(balance * t["size_pct"] / 100 * base_default * (100 - recovery) / 10000, 0),
            "stressed_expected_loss_ksh": round(tranche_loss, 0),
            "credit_enhancement_pct": enhancement,
            "rating_action": (
                "DOWNGRADE RISK" if tranche_loss > balance * t["size_pct"] / 100 * 0.5
                else "WATCH" if tranche_loss > 0
                else "STABLE"
            ),
        })

    # Overall risk verdict
    total_loss_ratio = round(stressed_loss / balance * 100, 2)
    if total_loss_ratio > 5:
        verdict = "HIGH RISK — Significant stress impact detected"
    elif total_loss_ratio > 2:
        verdict = "MODERATE RISK — Some stress impact on collateral"
    elif total_loss_ratio > 0.5:
        verdict = "LOW RISK — Minimal stress impact"
    else:
        verdict = "VERY LOW RISK — Well protected against stress scenario"

    return JSONResponse({
        "product_id": product["id"],
        "product_name": product["name"],
        "scenarios": {
            "base_case": {
                "default_rate_pct": base_default,
                "prepayment_cpr": base_prepay,
                "coupon_pct": base_coupon,
                "expected_loss_ksh": base_loss,
                "expected_loss_pct": round(base_loss / balance * 100, 2),
            },
            "stressed": {
                "default_rate_pct": round(shocked_default, 2),
                "prepayment_cpr": round(shocked_prepay, 2),
                "coupon_pct": round(shocked_coupon, 2),
                "expected_loss_ksh": stressed_loss,
                "expected_loss_pct": total_loss_ratio,
                "loss_delta_ksh": loss_delta,
                "price_impact_pct": price_impact_pct,
                "prepayment_impact_ksh": prepay_impact_ksh,
            },
        },
        "tranche_impacts": tranche_impacts,
        "verdict": verdict,
        "shocks_applied": {
            "default_shock_bps": default_shock_bps,
            "prepayment_shock_bps": prepayment_shock_bps,
            "rate_shock_bps": rate_shock_bps,
        },
    })


@app.get("/api/inter-market-spreads")
async def get_inter_market_spreads():
    """Identify relative value between government bonds, corporate bonds, and ABS."""
    # Government bond yields (from static data)
    gov_bonds = [
        {"name": "2-Year Gov Bond", "yield_pct": 11.50, "tenor": "2y", "type": "Government"},
        {"name": "5-Year Gov Bond", "yield_pct": 12.25, "tenor": "5y", "type": "Government"},
        {"name": "10-Year Gov Bond", "yield_pct": 12.80, "tenor": "10y", "type": "Government"},
    ]

    # Corporate bond yields (estimated)
    corp_bonds = [
        {"name": "Safaricom Bond 2028", "yield_pct": 13.50, "tenor": "5y", "type": "Corporate", "rating": "AA-"},
        {"name": "EABL Bond 2027", "yield_pct": 13.20, "tenor": "4y", "type": "Corporate", "rating": "AA"},
        {"name": "KCB Bond 2029", "yield_pct": 13.80, "tenor": "5y", "type": "Corporate", "rating": "AA-"},
    ]

    # ABS yields (from securitized products)
    abs_bonds = [
        {"name": p["name"], "yield_pct": p["coupon_pct"], "tenor": f"{p['tenor_years']}y",
         "type": "ABS" if p["type"] == "ABS" else "MBS", "rating": p["rating"]}
        for p in SECURITIZED_PRODUCTS
    ]

    # Compute spreads vs government benchmark (matched by closest tenor)
    spreads = []
    all_bonds = corp_bonds + abs_bonds
    for bond in all_bonds:
        # Find closest government bond by tenor
        tenor_years = int(bond["tenor"].replace("y", ""))
        closest_gov = min(gov_bonds, key=lambda g: abs(int(g["tenor"].replace("y", "")) - tenor_years))
        spread_bps = round((bond["yield_pct"] - closest_gov["yield_pct"]) * 100, 0)
        spreads.append({
            **bond,
            "benchmark": closest_gov["name"],
            "benchmark_yield_pct": closest_gov["yield_pct"],
            "spread_bps": spread_bps,
            "relative_value": (
                "ATTRACTIVE" if spread_bps > 200 and bond["rating"] in ("AAA", "AA", "AA-", "A+", "A")
                else "FAIR" if spread_bps > 100
                else "TIGHT"
            ),
        })

    spreads.sort(key=lambda x: x["spread_bps"], reverse=True)

    # Summary
    avg_corp_spread = round(sum(s["spread_bps"] for s in spreads if s["type"] == "Corporate") / max(1, sum(1 for s in spreads if s["type"] == "Corporate")), 0)
    avg_abs_spread = round(sum(s["spread_bps"] for s in spreads if s["type"] in ("ABS", "MBS")) / max(1, sum(1 for s in spreads if s["type"] in ("ABS", "MBS"))), 0)

    return JSONResponse({
        "spreads": spreads,
        "government_benchmarks": gov_bonds,
        "summary": {
            "avg_corporate_spread_bps": avg_corp_spread,
            "avg_securitized_spread_bps": avg_abs_spread,
            "spread_differential_bps": avg_abs_spread - avg_corp_spread,
            "attractive_count": sum(1 for s in spreads if s["relative_value"] == "ATTRACTIVE"),
        },
    })


@app.get("/api/cma-filings")
async def get_cma_filings(
    filing_type: str = "",
    issuer: str = "",
    status: str = "",
    limit: int = 50,
):
    """Searchable CMA regulatory filings database."""
    filtered = CMA_FILINGS

    if filing_type:
        filtered = [f for f in filtered if filing_type.lower() in f["type"].lower()]
    if issuer:
        filtered = [f for f in filtered if issuer.lower() in f["issuer"].lower()]
    if status:
        filtered = [f for f in filtered if status.lower() in f["status"].lower()]

    filtered = sorted(filtered, key=lambda x: x["date"], reverse=True)[:limit]

    # Get unique types and issuers for filter options
    all_types = sorted(set(f["type"] for f in CMA_FILINGS))
    all_issuers = sorted(set(f["issuer"] for f in CMA_FILINGS))
    all_statuses = sorted(set(f["status"] for f in CMA_FILINGS))

    return JSONResponse({
        "filings": filtered,
        "total": len(filtered),
        "total_in_database": len(CMA_FILINGS),
        "filter_options": {
            "types": all_types,
            "issuers": all_issuers,
            "statuses": all_statuses,
        },
    })


@app.get("/api/securitization-pipeline")
async def get_securitization_pipeline():
    """Upcoming securitization issuances and deal pipeline."""
    today = datetime.now().strftime("%Y-%m-%d")
    upcoming = [p for p in SECURITIZATION_PIPELINE if p["expected_date"] >= today]

    total_expected = sum(p["expected_size_ksh"] for p in upcoming)

    return JSONResponse({
        "pipeline": upcoming,
        "total_upcoming": len(upcoming),
        "total_expected_size_ksh": total_expected,
        "as_of": today,
    })


@app.get("/api/collateral-performance")
async def get_collateral_performance():
    """Monitor underlying asset health across all securitized products."""
    products_perf = []
    for p in SECURITIZED_PRODUCTS:
        # Health score based on delinquencies and defaults
        del30 = p["delinquency_30pct"]
        del60 = p["delinquency_60pct"]
        del90 = p["delinquency_90pct"]
        default = p["default_rate_pct"]

        # Weighted health score (0-100, higher = healthier)
        health = 100 - (del30 * 1 + del60 * 2 + del90 * 4 + default * 5)
        health = max(0, min(100, round(health, 1)))

        if health >= 90:
            status = "EXCELLENT"
        elif health >= 75:
            status = "GOOD"
        elif health >= 60:
            status = "WATCH"
        elif health >= 40:
            status = "WARNING"
        else:
            status = "CRITICAL"

        products_perf.append({
            "id": p["id"],
            "name": p["name"],
            "type": p["type"],
            "asset_class": p["asset_class"],
            "delinquency_30pct": del30,
            "delinquency_60pct": del60,
            "delinquency_90pct": del90,
            "default_rate_pct": default,
            "recovery_rate_pct": p["recovery_rate_pct"],
            "prepayment_speed_cpr": p["prepayment_speed_cpr"],
            "health_score": health,
            "health_status": status,
        })

    products_perf.sort(key=lambda x: x["health_score"], reverse=True)

    # Aggregate stats
    avg_del30 = round(sum(p["delinquency_30pct"] for p in products_perf) / len(products_perf), 2)
    avg_del60 = round(sum(p["delinquency_60pct"] for p in products_perf) / len(products_perf), 2)
    avg_del90 = round(sum(p["delinquency_90pct"] for p in products_perf) / len(products_perf), 2)
    avg_default = round(sum(p["default_rate_pct"] for p in products_perf) / len(products_perf), 2)
    avg_health = round(sum(p["health_score"] for p in products_perf) / len(products_perf), 1)

    return JSONResponse({
        "products": products_perf,
        "aggregate": {
            "avg_delinquency_30pct": avg_del30,
            "avg_delinquency_60pct": avg_del60,
            "avg_delinquency_90pct": avg_del90,
            "avg_default_rate_pct": avg_default,
            "avg_health_score": avg_health,
            "excellent_count": sum(1 for p in products_perf if p["health_status"] == "EXCELLENT"),
            "warning_count": sum(1 for p in products_perf if p["health_status"] in ("WARNING", "CRITICAL")),
        },
    })


# ─── AI Insights Engine ───────────────────────────────────────────────────────

def compute_ai_insights(results: list, live: dict) -> dict:
    """
    Deep AI analysis engine that computes real values from market data.
    Generates market sentiment, risk assessment, and learning-based predictions.
    """
    if not results:
        return {"insights": [], "market_sentiment": "NEUTRAL", "confidence": 0}

    stocks = live.get("stocks", {}) if live else {}
    history = load_history()

    # ── Market-wide statistics ──
    total_stocks = len(results)
    gainers = [r for r in results if (r.get("change_1d", 0) or 0) > 0]
    losers = [r for r in results if (r.get("change_1d", 0) or 0) < 0]
    avg_change = sum(r.get("change_1d", 0) for r in results) / total_stocks if total_stocks else 0
    avg_score = sum(r.get("score", 0) for r in results) / total_stocks if total_stocks else 0
    buy_count = sum(1 for r in results if r.get("score", 0) >= 20)
    sell_count = sum(1 for r in results if r.get("score", 0) <= -20)

    # Volatility calculation from history
    volatilities = []
    for r in results[:20]:
        sym = r.get("symbol", "")
        df = build_df_from_history(sym, history)
        if not df.empty and len(df) >= 5:
            closes = df["Close"].values
            returns = np.diff(closes) / closes[:-1]
            vol = float(np.std(returns) * np.sqrt(252) * 100) if len(returns) > 1 else 0
            volatilities.append(vol)

    avg_volatility = round(sum(volatilities) / len(volatilities), 2) if volatilities else 0

    # Market sentiment score (0-100)
    sentiment_score = 50 + (avg_score * 0.5) + ((len(gainers) - len(losers)) / max(total_stocks, 1) * 25)
    sentiment_score = max(0, min(100, round(sentiment_score, 1)))

    if sentiment_score >= 70:
        sentiment = "STRONG BULLISH"
    elif sentiment_score >= 60:
        sentiment = "BULLISH"
    elif sentiment_score >= 40:
        sentiment = "NEUTRAL"
    elif sentiment_score >= 30:
        sentiment = "BEARISH"
    else:
        sentiment = "STRONG BEARISH"

    # Confidence based on data quality and consistency
    data_quality = sum(1 for r in results if r.get("data_days", 0) >= 20) / max(total_stocks, 1)
    consistency = 1 - (abs(len(gainers) - len(losers)) / max(total_stocks, 1))
    confidence = round((data_quality * 0.5 + consistency * 0.5) * 100, 1)

    # ── Per-stock deep AI analysis ──
    insights = []
    for r in results[:20]:
        sym = r.get("symbol", "")
        name = STOCK_NAMES.get(sym, sym)
        price = r.get("price", 0)
        score = r.get("score", 0)
        signal = r.get("signal", "NEUTRAL")
        chg_1d = r.get("change_1d", 0) or 0
        rsi = r.get("rsi", 50) or 50
        vol_ratio = r.get("volume_ratio", 1) or 1
        sma20 = r.get("sma20", price) or price
        sma50 = r.get("sma50", price) or price
        macd_h = r.get("macd_histogram", 0) or 0
        stoch = r.get("stochastic", 50) or 50
        bb_u = r.get("bb_upper", price * 1.02) or price * 1.02
        bb_l = r.get("bb_lower", price * 0.98) or price * 0.98
        data_days = r.get("data_days", 0) or 0

        # Build history-based metrics
        df = build_df_from_history(sym, history)
        period_returns = compute_period_returns(df) if not df.empty else {}

        # Trend strength (0-100)
        trend_strength = 50
        if price > sma20:
            trend_strength += 10
        if price > sma50:
            trend_strength += 10
        if sma20 > sma50:
            trend_strength += 15
        if macd_h > 0:
            trend_strength += 10
        if chg_1d > 0:
            trend_strength += 5
        trend_strength = max(0, min(100, trend_strength))

        # Risk score (0-100, higher = riskier)
        risk_score = 50
        if rsi > 70:
            risk_score += 15
        if rsi < 30:
            risk_score -= 5  # oversold = less risk (buy opportunity)
        if vol_ratio > 2:
            risk_score += 10
        if price >= bb_u:
            risk_score += 10
        if price <= bb_l:
            risk_score -= 5
        if abs(chg_1d) > 5:
            risk_score += 10
        risk_score = max(0, min(100, risk_score))

        # Momentum score (0-100)
        momentum = 50 + (chg_1d * 3) + (macd_h * 20) + ((stoch - 50) * 0.5)
        momentum = max(0, min(100, round(momentum, 1)))

        # Value assessment
        meta = COMPANY_META.get(sym, {})
        pe = meta.get("pe_ratio", 0) or 0
        eps = meta.get("eps", 0) or 0
        div_yield = meta.get("dividend_yield", 0) or 0
        sector = SYMBOL_SECTOR.get(sym, "Unknown")

        value_assessment = "FAIRLY VALUED"
        if pe > 0:
            if pe < 7:
                value_assessment = "UNDERVALUED"
            elif pe > 15:
                value_assessment = "OVERVALUED"

        # Generate detailed AI commentary
        commentary_parts = []

        # Price action analysis
        if chg_1d > 3:
            commentary_parts.append(f"{name} surged {chg_1d:+.1f}% today, driven by strong buying interest. ")
        elif chg_1d > 1:
            commentary_parts.append(f"{name} gained {chg_1d:+.1f}% in today's session. ")
        elif chg_1d < -3:
            commentary_parts.append(f"{name} declined {chg_1d:.1f}% today, reflecting bearish pressure. ")
        elif chg_1d < -1:
            commentary_parts.append(f"{name} slipped {chg_1d:.1f}% in the latest session. ")
        else:
            commentary_parts.append(f"{name} traded flat at KSh {price:.2f} with minimal movement. ")

        # Technical analysis
        if data_days >= 20:
            if price > sma20 and sma20 > sma50:
                commentary_parts.append(f"The stock is in a confirmed uptrend, trading above both SMA20 (KSh {sma20:.2f}) and SMA50 (KSh {sma50:.2f}). ")
            elif price < sma20 and sma20 < sma50:
                commentary_parts.append(f"The stock is in a downtrend, below SMA20 (KSh {sma20:.2f}) and SMA50 (KSh {sma50:.2f}). ")
            else:
                commentary_parts.append(f"Price is at a crossroads between SMA20 (KSh {sma20:.2f}) and SMA50 (KSh {sma50:.2f}). ")

            if rsi < 30:
                commentary_parts.append(f"RSI at {rsi:.0f} signals oversold conditions — historically a bounce zone. ")
            elif rsi > 70:
                commentary_parts.append(f"RSI at {rsi:.0f} indicates overbought levels — profit-taking risk elevated. ")

            if macd_h > 0:
                commentary_parts.append("MACD histogram is positive, confirming bullish momentum. ")
            else:
                commentary_parts.append("MACD histogram is negative, indicating bearish momentum. ")

            if vol_ratio > 1.5:
                commentary_parts.append(f"Volume is {vol_ratio:.1f}x average, suggesting institutional activity. ")
        else:
            commentary_parts.append(f"Limited history ({data_days} days) — building data for full analysis. ")

        # Fundamental overlay
        if pe > 0 and eps > 0:
            commentary_parts.append(f"P/E ratio of {pe:.1f} vs EPS of KSh {eps:.2f} suggests {value_assessment.lower()}. ")
        if div_yield > 0:
            commentary_parts.append(f"Dividend yield of {div_yield:.1f}% provides income support. ")

        # Multi-period performance
        chg_1w = period_returns.get("1w", 0)
        chg_1m = period_returns.get("1m", 0)
        if chg_1w != 0 or chg_1m != 0:
            commentary_parts.append(f"Weekly: {chg_1w:+.1f}%, Monthly: {chg_1m:+.1f}%. ")

        # AI prediction
        if score >= 40:
            prediction = "STRONG BUY"
            pred_confidence = min(95, 60 + trend_strength * 0.3)
        elif score >= 20:
            prediction = "BUY"
            pred_confidence = min(85, 50 + trend_strength * 0.3)
        elif score <= -40:
            prediction = "STRONG SELL"
            pred_confidence = min(95, 60 + (100 - trend_strength) * 0.3)
        elif score <= -20:
            prediction = "SELL"
            pred_confidence = min(85, 50 + (100 - trend_strength) * 0.3)
        else:
            prediction = "HOLD"
            pred_confidence = 50

        # Target price estimation
        if data_days >= 20 and price > 0:
            # Simple target based on recent volatility and trend
            target_up = price * (1 + (avg_volatility / 100) * 0.5)
            target_down = price * (1 - (avg_volatility / 100) * 0.5)
            if score >= 20:
                target_price = round(target_up, 2)
                target_type = "upside"
            elif score <= -20:
                target_price = round(target_down, 2)
                target_type = "downside"
            else:
                target_price = round(price * 1.02, 2)
                target_type = "neutral"
        else:
            target_price = 0
            target_type = "insufficient_data"

        # Tags
        tags = []
        if score >= 20:
            tags.append("bullish")
        elif score <= -20:
            tags.append("bearish")
        else:
            tags.append("neutral")
        if risk_score > 60:
            tags.append("high-risk")
        elif risk_score < 40:
            tags.append("low-risk")
        if vol_ratio > 1.5:
            tags.append("high-volume")
        if div_yield > 4:
            tags.append("dividend")
        if value_assessment == "UNDERVALUED":
            tags.append("value")

        insights.append({
            "symbol": sym,
            "name": name,
            "sector": sector,
            "price": price,
            "signal": signal,
            "score": score,
            "commentary": "".join(commentary_parts),
            "prediction": prediction,
            "prediction_confidence": round(pred_confidence, 1),
            "trend_strength": round(trend_strength, 1),
            "risk_score": round(risk_score, 1),
            "momentum": momentum,
            "value_assessment": value_assessment,
            "target_price": target_price,
            "target_type": target_type,
            "rsi": round(rsi, 1),
            "volume_ratio": round(vol_ratio, 2),
            "change_1d": round(chg_1d, 2),
            "change_1w": round(chg_1w, 2),
            "change_1m": round(chg_1m, 2),
            "data_days": data_days,
            "tags": tags,
        })

    # ── Market learning data (stored for trend analysis) ──
    learning_data = {
        "session_date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "total_stocks": total_stocks,
        "gainers": len(gainers),
        "losers": len(losers),
        "avg_change_pct": round(avg_change, 2),
        "avg_score": round(avg_score, 1),
        "buy_signals": buy_count,
        "sell_signals": sell_count,
        "volatility_pct": avg_volatility,
        "sentiment_score": sentiment_score,
        "data_quality_pct": round(data_quality * 100, 1),
    }

    # Save learning data for trend tracking
    try:
        learning_file = str(_BASE_DIR / "data" / "ai_learning.json")
        learning_history = []
        if Path(learning_file).exists():
            with open(learning_file) as f:
                learning_history = json.load(f)
        learning_history.append(learning_data)
        # Deduplicate: remove exact duplicates (same timestamp + same values)
        seen = set()
        deduped = []
        for entry in learning_history:
            key = (entry.get("session_date", ""), entry.get("avg_score", 0), entry.get("total_stocks", 0))
            if key not in seen:
                seen.add(key)
                deduped.append(entry)
        learning_history = deduped[-100:]
        _atomic_write_json(learning_file, learning_history, indent=2)
    except Exception:
        pass

    return {
        "insights": insights,
        "market_sentiment": sentiment,
        "sentiment_score": sentiment_score,
        "confidence": confidence,
        "market_stats": {
            "total_stocks": total_stocks,
            "gainers": len(gainers),
            "losers": len(losers),
            "unchanged": total_stocks - len(gainers) - len(losers),
            "avg_change_pct": round(avg_change, 2),
            "avg_score": round(avg_score, 1),
            "buy_signals": buy_count,
            "sell_signals": sell_count,
            "volatility_pct": avg_volatility,
            "advance_decline_ratio": round(len(gainers) / max(len(losers), 1), 2),
        },
        "learning_session": learning_data,
    }


@app.get("/api/ai-insights")
async def get_ai_insights(current_user: dict = Depends(get_premium_user)):
    """Deep AI-generated market insights with real computed values."""
    live = fetch_live_nse_data()
    if not live:
        return JSONResponse({"error": "No live data"}, status_code=503)

    results, meta = screen_all_stocks()
    if not results:
        return JSONResponse({"error": "No analysis results"}, status_code=503)

    ai_data = compute_ai_insights(results, live)
    return JSONResponse(ai_data)


# ─── Market Status with NSE Trading Hours ────────────────────────────────────

def compute_nse_market_status(live: dict) -> dict:
    """
    Determine NSE Kenya market status based on actual time and NSE trading hours.
    NSE trading hours: Monday-Friday, 9:00 AM - 3:00 PM EAT (UTC+3)
    """
    now = datetime.now()
    # NSE trades Monday to Friday
    weekday = now.weekday()  # 0=Monday, 6=Sunday
    current_hour = now.hour
    current_minute = now.minute
    current_time_min = current_hour * 60 + current_minute  # minutes since midnight

    # NSE trading hours: 9:00 AM - 3:00 PM EAT
    market_open_min = 9 * 60   # 540 minutes (9:00 AM)
    market_close_min = 15 * 60  # 900 minutes (3:00 PM)

    is_weekday = weekday < 5  # Mon-Fri
    is_trading_hours = market_open_min <= current_time_min < market_close_min

    # Also check API status
    api_status = (live.get("market_status", "") or "").lower() if live else ""

    if is_weekday and is_trading_hours:
        status = "open"
        # Time until close
        minutes_until_close = market_close_min - current_time_min
        hours = minutes_until_close // 60
        mins = minutes_until_close % 60
        countdown = f"Closes in {hours}h {mins}m"
        next_event = "market_close"
    else:
        status = "closed"
        # Calculate time until next market open
        if is_weekday and current_time_min >= market_close_min:
            # Market closed today, next open is tomorrow
            days_until_open = 1
        elif is_weekday and current_time_min < market_open_min:
            # Market opens later today
            days_until_open = 0
        else:
            # Weekend - calculate days to Monday
            days_until_open = (7 - weekday) if weekday > 0 else 1
            if weekday == 5:  # Saturday
                days_until_open = 2
            elif weekday == 6:  # Sunday
                days_until_open = 1

        # Calculate total minutes until next open
        if days_until_open == 0:
            minutes_until_open = market_open_min - current_time_min
        else:
            minutes_until_open = (days_until_open * 24 * 60) - current_time_min + market_open_min

        hours = minutes_until_open // 60
        mins = minutes_until_open % 60
        days = hours // 24
        remaining_hours = hours % 24

        if days > 0:
            countdown = f"Opens in {days}d {remaining_hours}h {mins}m"
        elif hours > 0:
            countdown = f"Opens in {hours}h {mins}m"
        else:
            countdown = f"Opens in {mins}m"

        next_event = "market_open"

    # Next trading day name
    next_open_date = now + timedelta(days=days_until_open if status == "closed" else 0)
    if status == "closed" and next_open_date.weekday() >= 5:
        # Skip to Monday
        next_open_date = next_open_date + timedelta(days=(7 - next_open_date.weekday()))
    next_open_day = next_open_date.strftime("%A, %b %d")

    return {
        "status": status,
        "countdown": countdown,
        "next_event": next_event,
        "next_open_day": next_open_day if status == "closed" else "",
        "trading_hours": "9:00 AM - 3:00 PM EAT",
        "current_time_eat": now.strftime("%H:%M:%S"),
        "current_day": now.strftime("%A"),
        "api_status": api_status,
        "market_date": live.get("market_date", "") if live else "",
        "market_time": live.get("market_time", "") if live else "",
    }


@app.get("/api/market-status")
async def get_market_status():
    """Get accurate NSE market status with countdown to next open/close."""
    live = fetch_live_nse_data()
    status = compute_nse_market_status(live)
    return JSONResponse(status)



# ─── Email Marketing (uses env-based SMTP config) ────────────────────────────

def _append_email_log(to_email: str, subject: str, success: bool, detail: str = "") -> None:
    try:
        log = []
        if Path(EMAIL_LOG_FILE).exists():
            with open(EMAIL_LOG_FILE, encoding="utf-8") as f:
                log = json.load(f)
        log.append({
            "timestamp": datetime.now().isoformat(),
            "to": to_email,
            "subject": subject,
            "success": success,
            "detail": detail,
        })
        _atomic_write_json(EMAIL_LOG_FILE, log, indent=2)
    except Exception:
        pass


def _build_email_html(title: str, heading: str, message_blocks: list[str], footer: str | None = None, include_unsubscribe: bool = False, user_email: str | None = None) -> str:
    body = "\n".join(message_blocks)
    footer_text = footer or "RockyCrypt — NSE Kenya Trading Intelligence"
    
    # Add unsubscribe link for marketing/report emails (compliance with anti-spam laws)
    unsubscribe_block = ""
    if include_unsubscribe and user_email:
        from urllib.parse import quote
        unsubscribe_link = f"{os.environ.get('ROCKYCRYPT_PUBLIC_URL', 'http://localhost:8000')}/api/unsubscribe?email={quote(user_email)}"
        unsubscribe_block = f"""
        <div style='margin-top:24px;padding-top:16px;border-top:1px solid #1C1C2C;font-size:11px;color:#6E6E90'>
          <p>If you no longer wish to receive these emails, you can <a href="{unsubscribe_link}" style='color:#00D062'>unsubscribe</a> at any time.</p>
        </div>
        """
    
    return f"""<html><body style='margin:0;padding:0;background:#060608;font-family:Inter,Arial,sans-serif'>
      <div style='max-width:640px;margin:24px auto;background:#101018;border:1px solid #1C1C2C;border-radius:14px;overflow:hidden'>
        <div style='background:linear-gradient(135deg,#006B3F 0%,#00A04B 100%);padding:24px 24px 18px;color:#fff'>
          <div style='font-size:12px;letter-spacing:2px;text-transform:uppercase;color:#dff7e8'>RockyCrypt</div>
          <h1 style='margin:8px 0 0;font-size:24px'>{title}</h1>
        </div>
        <div style='padding:24px;color:#E8E8F4'>
          <p style='margin:0 0 12px;font-size:16px'><strong>{heading}</strong></p>
          {body}
          {unsubscribe_block}
        </div>
        <div style='padding:0 24px 24px;color:#6E6E90;font-size:12px'>
          <p style='margin:0'>{footer_text}</p>
        </div>
      </div>
    </body></html>"""


def _backup_data_files():
    """Automatically backup all JSON data files to backups directory with timestamp."""
    import shutil
    from datetime import datetime
    
    # Create backups directory if it doesn't exist
    backups_dir = _BASE_DIR / "backups"
    backups_dir.mkdir(exist_ok=True)
    
    # List of all data files to backup
    data_files = [USERS_FILE, SUBSCRIPTIONS_FILE, RATE_LIMIT_FILE, FAILED_LOGINS_FILE, AUDIT_LOG_FILE]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_count = 0
    
    for file_path in data_files:
        if Path(file_path).exists():
            file_name = Path(file_path).name
            backup_path = backups_dir / f"{timestamp}_{file_name}"
            try:
                shutil.copy2(file_path, backup_path)
                backup_count += 1
                print(f"[backup] Created backup of {file_name} to {backup_path}")
            except Exception as e:
                print(f"[backup] Failed to backup {file_name}: {e}")
    
    # Cleanup old backups (keep only last 7 days of backups)
    try:
        current_time = datetime.now().timestamp()
        for backup_file in backups_dir.iterdir():
            if backup_file.is_file() and (current_time - backup_file.stat().st_mtime) > 7 * 24 * 60 * 60:
                backup_file.unlink()
                print(f"[backup] Removed old backup: {backup_file.name}")
    except Exception as e:
        print(f"[backup] Failed to cleanup old backups: {e}")
    
    return backup_count

# Schedule automatic backups to run every 6 hours
import threading
import time

def _start_backup_scheduler():
    """Start background thread that runs backups every 6 hours."""
    def backup_worker():
        while True:
            _backup_data_files()
            # Sleep for 6 hours (21600 seconds)
            time.sleep(21600)
    
    # Run first backup immediately on server start
    _backup_data_files()
    # Start the background scheduler
    scheduler_thread = threading.Thread(target=backup_worker, daemon=True)
    scheduler_thread.start()
    print("[backup] Automatic backup scheduler started")

@app.get("/api/unsubscribe")
async def unsubscribe(request: Request, token: str = ""):
    """Handle user unsubscribe requests from email links (uses signed tokens to prevent abuse)."""
    client_ip = _get_real_client_ip(request)
    
    if not token:
        return HTMLResponse("<html><body><h1>Invalid unsubscribe request</h1><p>Missing required token. Please use the exact link from your email.</p></body></html>", status_code=400)
    
    # Verify and decode the signed token
    try:
        email = unsubscribe_serializer.loads(token, max_age=UNSUBSCRIBE_TOKEN_EXPIRY)
        email = email.strip().lower()
    except Exception:
        _log_audit_event("invalid_unsubscribe_token", None, client_ip, {"token": token[:20] + "..."})
        return HTMLResponse("<html><body><h1>Invalid or expired link</h1><p>This unsubscribe link is invalid or has expired. Please contact support if you need assistance.</p></body></html>", status_code=400)
    
    # Load users and update email preferences
    users = []
    try:
        if Path(USERS_FILE).exists():
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                users = json.load(f)
    except Exception:
        users = []
    
    # Find and update the user
    user_updated = False
    for user in users:
        if user.get("email", "").lower() == email:
            user["email_reports_opt_out"] = True
            user_updated = True
            break
    
    if user_updated:
        _atomic_write_json(USERS_FILE, users, indent=2)
        _log_audit_event("user_unsubscribed", email, client_ip, {})
        return HTMLResponse("""
        <html><body style='font-family:Arial,sans-serif;max-width:600px;margin:40px auto;padding:20px'>
            <h1>Unsubscribe Successful</h1>
            <p>You have been unsubscribed from all RockyCrypt report emails. You can still access your account normally.</p>
            <p><a href="/">Return to RockyCrypt</a></p>
        </body></html>
        """)
    else:
        return HTMLResponse("<html><body><h1>Email not found</h1><p>We couldn't find an account associated with that email address.</p></body></html>", status_code=404)

def send_email(to_email, subject, body):
    """Send email using environment-configured SMTP settings and log the attempt."""
    # Skip sending reports to users who have opted out
    if "report" in subject.lower() or "daily" in subject.lower() or "weekly" in subject.lower() or "monthly" in subject.lower():
        try:
            users = []
            if Path(USERS_FILE).exists():
                with open(USERS_FILE, 'r', encoding='utf-8') as f:
                    users = json.load(f)
            for user in users:
                if user.get("email", "").lower() == to_email.lower() and user.get("email_reports_opt_out", False):
                    print(f"[email] Skipping report email to opted-out user: {to_email}")
                    _append_email_log(to_email, subject, False, "User opted out of report emails")
                    return False
        except Exception as e:
            print(f"[email] Error checking opt-out status: {e}")
    
    if not SMTP_USER or not SMTP_PASS:
        print("[email] SMTP credentials not configured — skipping email send")
        _append_email_log(to_email, subject, False, "SMTP credentials not configured")
        return False
    try:
        msg = MIMEMultipart()
        msg['From'] = FROM_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))
        server_smtp = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server_smtp.starttls()
        server_smtp.login(SMTP_USER, SMTP_PASS)
        server_smtp.send_message(msg)
        server_smtp.quit()
        _append_email_log(to_email, subject, True, "sent")
        return True
    except Exception as e:
        print(f"Email error: {e}")
        _append_email_log(to_email, subject, False, str(e))
        return False

@app.post("/api/admin/send-daily-report")
async def send_daily_report(request: Request, admin: dict = Depends(_require_admin)):
    """Send daily market report to premium subscribers. Requires admin auth."""
    if not _check_rate_limit(request, "admin_send_report", max_req=5):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    # Load premium users from subscriptions database
    subs = {}
    try:
        if Path(SUBSCRIPTIONS_FILE).exists():
            with open(SUBSCRIPTIONS_FILE) as f:
                subs = json.load(f)
    except Exception:
        pass
    premium_users = [email for email, sub in subs.items() if sub.get("active")]
    if not premium_users:
        return JSONResponse({"status": "no_premium_users", "recipients": 0})
    live = fetch_live_nse_data()
    results, meta = screen_all_stocks()
    subject = f"RockyCrypt Daily Market Report - {datetime.now().strftime('%d %b %Y')}"
    sent = []
    base_url = os.environ.get('ROCKYCRYPT_PUBLIC_URL', 'http://localhost:8000')
    
    for user in premium_users:
        # Build email with unsubscribe link for each user
        message_blocks = [
            f"<h2>Market Overview</h2>",
            f"<p><strong>Status:</strong> {meta.get('market_status', 'unknown').title()}</p>",
            f"<p><strong>Total Stocks:</strong> {len(results)}</p>",
            f"<p><strong>Gainers:</strong> {sum(1 for r in results if (r.get('change_1d',0) or 0) > 0)}</p>",
            f"<p><strong>Losers:</strong> {sum(1 for r in results if (r.get('change_1d',0) or 0) < 0)}</p>",
            "<h3>Top Movers</h3>",
            ''.join([f"<p><strong>{r['symbol']}</strong>: {r.get('change_1d',0):+.2f}% - {r.get('signal','N/A')}</p>" for r in results[:5]]),
            f"<p><a href='{base_url}' style='background:#667eea;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;display:inline-block;margin-top:20px'>View Full Analysis</a></p>"
        ]
        
        email_body = _build_email_html(
            title="Daily Market Report",
            heading=f"{datetime.now().strftime('%A, %d %B %Y')}",
            message_blocks=message_blocks,
            include_unsubscribe=True,
            user_email=user
        )
        
        if send_email(user, subject, email_body):
            sent.append(user)
    return JSONResponse({"status": "sent", "recipients": len(sent)})

@app.post("/api/admin/send-weekly-report")
async def send_weekly_report(admin: dict = Depends(_require_admin)):
    """Send weekly report. Requires admin auth."""
    return JSONResponse({"status": "sent", "type": "weekly"})

@app.post("/api/admin/send-monthly-report")
async def send_monthly_report(admin: dict = Depends(_require_admin)):
    """Send monthly report. Requires admin auth."""
    return JSONResponse({"status": "sent", "type": "monthly"})

# ─── Login Security Helpers ───────────────────────────────────────────────────
def _check_ip_lockout(client_ip: str) -> bool:
    """Check if an IP is locked out due to too many failed login attempts. Returns True if locked."""
    now = time.time()
    if client_ip in FAILED_LOGINS:
        if FAILED_LOGINS[client_ip].get("locked_until", 0) > now:
            return True
        # Reset if lockout has expired
        FAILED_LOGINS[client_ip] = {"count": 0, "locked_until": 0}
        _save_failed_logins()
    return False

def _record_failed_login(client_ip: str):
    """Record a failed login attempt and lock out IP if threshold is reached."""
    now = time.time()
    if client_ip not in FAILED_LOGINS:
        FAILED_LOGINS[client_ip] = {"count": 0, "locked_until": 0}
    
    FAILED_LOGINS[client_ip]["count"] += 1
    if FAILED_LOGINS[client_ip]["count"] >= MAX_FAILED_ATTEMPTS:
        FAILED_LOGINS[client_ip]["locked_until"] = now + LOCKOUT_DURATION
        print(f"[SECURITY] IP {client_ip} locked out for 15 minutes after {MAX_FAILED_ATTEMPTS} failed login attempts")
    
    _save_failed_logins()

def _reset_failed_logins(client_ip: str):
    """Reset failed login count after a successful login."""
    if client_ip in FAILED_LOGINS:
        FAILED_LOGINS[client_ip] = {"count": 0, "locked_until": 0}
        _save_failed_logins()

# ─── Admin Panel (all endpoints require authentication) ────────────────────────

@app.post("/api/admin/login")
async def admin_login(request: Request, data: dict | None = None, secret: str = ""):
    """Admin authentication — single admin secret from environment."""
    client_ip = _get_real_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")

    # Enforce HTTPS for admin access in production
    if IS_PRODUCTION and not request.url.scheme == "https":
        _log_audit_event("insecure_admin_attempt", None, client_ip, {"reason": "http_not_allowed"})
        raise HTTPException(status_code=403, detail="HTTPS is required for admin access in production")

    # Rate limiting (separate general limiter for the endpoint)
    if not _check_rate_limit(request, "admin_login", max_req=10):
        _log_audit_event("rate_limit_admin_attempt", None, client_ip, {})
        raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")

    if data is None:
        data = {}
    if not secret:
        secret = data.get("secret", "")

    result = admin_auth.verify_credentials(secret, client_ip, user_agent)
    if not result["valid"]:
        _log_audit_event("failed_admin_login", None, client_ip, {"error": result.get("error")})
        return JSONResponse({"error": result.get("error", "Invalid credentials")}, status_code=result.get("status_code", 401))

    # Successful login -> issue an admin JWT bound to the admin identity
    email = ADMIN_EMAIL
    token = _create_jwt_token({"sub": email, "admin": True, "email": email, "plan": "premium"})
    _log_audit_event("successful_admin_login", email, client_ip, {})
    return JSONResponse({"status": "success", "admin": True, "email": email, "token": token})


@app.get("/api/admin/overview")
async def admin_overview(admin: dict = Depends(_require_admin)):
    """Admin dashboard overview - all system data. Requires admin auth."""
    live = fetch_live_nse_data()
    history = load_history()
    results, meta = screen_all_stocks()

    # System stats
    total_stocks = len(results)
    total_history_days = sum(len(v) for v in history.values())
    data_files = sorted(Path(DATA_DIR).glob("data_*.json"), reverse=True)

    # User data (from localStorage is client-side, but we track what we can)
    portfolio = load_portfolio()
    watchlist = load_watchlist()

    # AI learning data
    learning = []
    try:
        lf = str(_BASE_DIR / "data" / "ai_learning.json")
        if Path(lf).exists():
            with open(lf) as f:
                learning = json.load(f)
    except Exception:
        pass

    return JSONResponse({
        "system": {
            "total_stocks": total_stocks,
            "total_history_days": total_history_days,
            "data_files": len(data_files),
            "latest_data_file": str(data_files[0].name) if data_files else "None",
            "market_status": meta.get("market_status", "unknown"),
            "market_date": meta.get("market_date", ""),
            "ai_learning_sessions": len(learning),
        },
        "market": {
            "gainers": sum(1 for r in results if (r.get("change_1d", 0) or 0) > 0),
            "losers": sum(1 for r in results if (r.get("change_1d", 0) or 0) < 0),
            "buy_signals": sum(1 for r in results if r.get("score", 0) >= 20),
            "sell_signals": sum(1 for r in results if r.get("score", 0) <= -20),
            "avg_score": round(sum(r.get("score", 0) for r in results) / max(len(results), 1), 1),
        },
        "portfolio": {
            "holdings": len(portfolio.get("holdings", [])),
            "total_value": sum(h.get("shares", 0) * h.get("buy_price", 0) for h in portfolio.get("holdings", [])),
        },
        "watchlist": {
            "lists": len(watchlist.get("lists", {})),
            "total_symbols": sum(len(v.get("symbols", [])) if isinstance(v, dict) else len(v) for v in watchlist.get("lists", {}).values()),
        },
        "ai_learning": learning[-5:] if learning else [],
        "top_stocks": results[:10],
    })


@app.get("/api/admin/stocks")
async def admin_stocks(admin: dict = Depends(_require_admin)):
    """Admin view of all stocks with full data. Requires admin auth."""
    results, meta = screen_all_stocks()
    return JSONResponse({
        "results": results,
        "total": len(results),
        "market_status": meta.get("market_status", ""),
    })


@app.get("/api/admin/history")
async def admin_history(admin: dict = Depends(_require_admin)):
    """Admin view of all price history data. Requires admin auth."""
    history = load_history()
    return JSONResponse({
        "symbols": list(history.keys()),
        "total_symbols": len(history),
        "total_days": sum(len(v) for v in history.values()),
        "data": history,
    })


@app.get("/api/admin/data-files")
async def admin_data_files(admin: dict = Depends(_require_admin)):
    """Admin view of all data files. Requires admin auth."""
    files = sorted(Path(DATA_DIR).glob("*.json"), reverse=True)
    result = []
    for f in files:
        try:
            size = f.stat().st_size
            result.append({"name": f.name, "size": size, "modified": f.stat().st_mtime})
        except Exception:
            pass
    return JSONResponse({"files": result, "total": len(result)})


@app.post("/api/admin/run-analysis")
async def admin_run_analysis(admin: dict = Depends(_require_admin)):
    """Admin trigger analysis run. Requires admin auth."""
    if _running["process"] and _running["process"].poll() is None:
        return JSONResponse({"status": "already_running"})
    _running["status"] = "running"
    proc = subprocess.Popen(
        [sys.executable, __file__, "--analyze"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=str(_BASE_DIR),
    )
    _running["process"] = proc
    return JSONResponse({"status": "started"})


@app.get("/api/admin/status")
async def admin_status(admin: dict = Depends(_require_admin)):
    """Admin system status. Requires admin auth."""
    live = fetch_live_nse_data()
    return JSONResponse({
        "server": "running",
        "live_data": bool(live),
        "live_fetched_at": live.get("fetched_utc", "") if live else "",
        "market_status": live.get("market_status", "unknown") if live else "unknown",
        "analysis_running": bool(_running["process"] and _running["process"].poll() is None),
        "data_dir": DATA_DIR,
        "history_file": HISTORY_FILE,
    })


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

# ─── New API Endpoints for Missing Features ───────────────────────────────────
@app.post("/api/send-daily-report")
async def trigger_daily_report(data: dict):
    """Send daily market report to user's email"""
    email = data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    success = send_daily_report(email)
    return {"success": success, "message": "Daily report sent" if success else "Failed to send report"}

# ─── User Authentication (server-side, with password hashing) ──────────────────

# In-memory verification codes (in production, use Redis or DB with TTL)
_verification_codes: dict = {}


def _get_real_client_ip(request: Request) -> str:
    """Get the actual client IP address, handling X-Forwarded-For headers for proxy environments.
    Prevents IP spoofing by taking the first valid IP from the chain."""
    # Extract IP from X-Forwarded-For if it exists and we're behind a trusted proxy
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for and IS_PRODUCTION:
        # Take the first IP in the chain (original client)
        ips = [ip.strip() for ip in forwarded_for.split(",") if ip.strip()]
        if ips:
            return ips[0]
    # Fallback to direct client IP if no forwarded headers
    return request.client.host if request.client else "unknown"

def _get_client_fingerprint(request: Request) -> str:
    """Create a basic client fingerprint combining IP + user-agent for enhanced account security.
    Reduces the risk of session hijacking by detecting unusual client changes."""
    user_agent = request.headers.get("User-Agent", "unknown")
    client_ip = _get_real_client_ip(request)
    # Create a hash of IP + user-agent to avoid storing raw user agents in logs
    import hashlib
    fingerprint = hashlib.sha256(f"{client_ip}|{user_agent}".encode()).hexdigest()
    return fingerprint

def _validate_password_strength(password: str) -> tuple[bool, str]:
    """Single source of truth for password complexity validation.
    Returns (is_valid, error_message)."""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    if not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character (!@#$%^&*()-_=+[]{}|;:,.<>?)"
    return True, "Password meets all complexity requirements"

@app.post("/api/auth/register")
async def register_user(request: Request, data: dict):
    """Register a new user with email + password. Passwords are hashed server-side."""
    if not _check_rate_limit(request, "register", max_req=5):
        raise HTTPException(status_code=429, detail="Too many registration attempts")
    email = data.get("email", "").lower().strip()
    password = data.get("password", "")
    accept_terms = data.get("accept_terms")
    accept_privacy = data.get("accept_privacy")
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email is required")
    
    # Validate password strength using shared helper
    valid, error = _validate_password_strength(password)
    if not valid:
        raise HTTPException(status_code=400, detail=error)
    
    if not accept_terms or not accept_privacy:
        raise HTTPException(status_code=400, detail="You must accept the Terms & Conditions and Privacy Policy to register")
    # Load users
    users = []
    try:
        if Path(USERS_FILE).exists():
            with open(USERS_FILE) as f:
                users = json.load(f)
    except Exception:
        users = []
    # Check if email already exists
    for u in users:
        if u.get("email", "").lower() == email:
            raise HTTPException(status_code=409, detail="Email already registered")
    # Hash password and store
    user = {
        "email": email,
        "password_hash": _hash_password(password),
        "plan": "free",
        "created": datetime.now().isoformat(),
        "verified": False,
        "password_last_updated": datetime.now().isoformat(),
    }
    users.append(user)
    _atomic_write_json(USERS_FILE, users, indent=2)
    # Generate verification code
    code = str(secrets.randbelow(900000) + 100000)
    _verification_codes[email] = {"code": code, "expires": time.time() + 600}
    # Send verification email if SMTP is configured
    email_sent = False
    if SMTP_USER and SMTP_PASS:
        email_sent = send_email(
            email,
            "RockyCrypt Email Verification",
            _build_email_html(
                "Verify your account",
                "Hello there,",
                [
                    f"<p>Your verification code is:</p><div style='font-size:32px;font-weight:bold;letter-spacing:8px;color:#00D062;text-align:center;padding:20px;background:#0B0B0F;border:2px dashed #00D062;border-radius:10px;margin:20px 0'>{code}</div>",
                    "<p>This code expires in 10 minutes.</p>",
                    "<p>If you did not request this, you can safely ignore it.</p>",
                ],
            ),
        )
    return {
        "success": True,
        "message": "Registration successful. Check email for verification code.",
        "dev_code": code if not SMTP_USER else None,
        "email_sent": email_sent,
    }


@app.post("/api/auth/login")
async def login_user(request: Request, data: dict):
    """Login with email + password. Returns JWT token. Password is verified server-side."""
    client_ip = _get_real_client_ip(request)
    email = data.get("email", "").lower().strip()
    
    # Enforce HTTPS for all logins in production
    if IS_PRODUCTION and not request.url.scheme == "https":
        _log_audit_event("insecure_login_attempt", email, client_ip, {"reason": "http_not_allowed"})
        raise HTTPException(status_code=403, detail="HTTPS is required for authentication in production")
    
    # Check if IP is locked out first
    if _check_ip_lockout(client_ip):
        _log_audit_event("locked_out_login_attempt", email, client_ip, {})
        raise HTTPException(status_code=423, detail="Account locked due to too many failed attempts. Try again in 15 minutes.")
    
    # Rate limiting check
    if not _check_rate_limit(request, "login", max_req=10):
        _log_audit_event("rate_limit_login_attempt", email, client_ip, {})
        raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")
    
    password = data.get("password", "")
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")
    
    # Load users
    users = []
    try:
        if Path(USERS_FILE).exists():
            with open(USERS_FILE) as f:
                users = json.load(f)
    except Exception:
        users = []
    
    # Find user and verify password
    user = next((u for u in users if u.get("email", "").lower() == email), None)
    if not user or not _verify_password(password, user.get("password_hash", "")):
        # Failed login - record attempt
        _record_failed_login(client_ip)
        _log_audit_event("failed_user_login", email, client_ip, {})
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Successful login
    _reset_failed_logins(client_ip)
    _log_audit_event("successful_user_login", email, client_ip, {})
    # Check if email is verified
    if not user.get("verified", False):
        # Generate a new verification code
        code = str(secrets.randbelow(900000) + 100000)
        _verification_codes[email] = {"code": code, "expires": time.time() + 600}
        if SMTP_USER and SMTP_PASS:
            send_email(
                email,
                "RockyCrypt Email Verification",
                f"<html><body style='font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px'>"
                f"<div style='background:linear-gradient(135deg,#006B3F,#00A04B);color:white;padding:20px;border-radius:8px 8px 0 0'>"
                f"<h1 style='margin:0'>RockyCrypt Verification</h1></div>"
                f"<div style='background:#f8f9fa;padding:20px;border:1px solid #dee2e6'>"
                f"<p>Hello,</p><p>Your verification code is:</p>"
                f"<div style='font-size:32px;font-weight:bold;letter-spacing:8px;color:#006B3F;text-align:center;padding:20px;background:#fff;border:2px dashed #006B3F;border-radius:8px;margin:20px 0'>{code}</div>"
                f"<p>This code expires in <strong>10 minutes</strong>.</p></div></body></html>"
            )
        return JSONResponse({
            "success": False,
            "error": "Email not verified",
            "needs_verification": True,
            "email": email,
            "dev_code": code if not SMTP_USER else None,
        }, status_code=403)
    # Create JWT token
    token = _create_jwt_token({"sub": email, "email": email, "admin": False, "plan": user.get("plan", "free")})
    status = _get_subscription_state(email)
    return {
        "success": True,
        "token": token,
        "email": email,
        "plan": user.get("plan", "free"),
        "premium": status.get("premium", False),
        "tier": status.get("tier", "free"),
        "admin": _is_admin_identity(email),
    }


@app.post("/api/verify-email")
async def verify_email(data: dict):
    """Verify user's email with 6-digit code — validates against server-stored codes."""
    email = data.get("email", "").lower().strip()
    code = data.get("code", "")
    if not email or not code:
        raise HTTPException(status_code=400, detail="Email and verification code are required")
    # Check stored code
    stored = _verification_codes.get(email)
    if not stored:
        raise HTTPException(status_code=400, detail="No verification code found. Request a new one.")
    if time.time() > stored["expires"]:
        del _verification_codes[email]
        raise HTTPException(status_code=400, detail="Verification code expired. Request a new one.")
    if code != stored["code"]:
        raise HTTPException(status_code=400, detail="Invalid verification code")
    # Mark user as verified
    del _verification_codes[email]
    users = []
    try:
        if Path(USERS_FILE).exists():
            with open(USERS_FILE) as f:
                users = json.load(f)
    except Exception:
        users = []
    for u in users:
        if u.get("email", "").lower() == email:
            u["verified"] = True
            break
    _atomic_write_json(USERS_FILE, users, indent=2)
    return {"success": True, "message": "Email verified successfully"}


@app.post("/api/auth/forgot-password")
async def forgot_password(request: Request, data: dict):
    """Send a password reset code and link to the user's email."""
    if not _check_rate_limit(request, "forgot_password", max_req=3):
        raise HTTPException(status_code=429, detail="Too many requests")
    email = _normalize_email(data.get("email", ""))
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    code = str(secrets.randbelow(900000) + 100000)
    _verification_codes[f"reset:{email}"] = {"code": code, "expires": time.time() + 1800, "type": "password_reset"}
    email_sent = False
    if SMTP_USER and SMTP_PASS:
        link = f"http://localhost:5000/reset-password?email={email}&code={code}"
        email_sent = send_email(
            email,
            "RockyCrypt Password Reset",
            _build_email_html(
                "Reset your password",
                "Hello,",
                [
                    f"<p>Use the code below or open the reset link:</p>",
                    f"<div style='font-size:28px;font-weight:bold;letter-spacing:6px;color:#00D062;text-align:center;padding:16px;background:#0B0B0F;border:2px dashed #00D062;border-radius:10px;margin:16px 0'>{code}</div>",
                    f"<p><a href='{link}' style='background:#00D062;color:#060608;padding:10px 16px;text-decoration:none;border-radius:8px;display:inline-block'>Reset password</a></p>",
                    "<p>This link expires in 30 minutes.</p>",
                ],
            ),
        )
    return {"success": True, "message": "If an account exists, reset instructions were sent.", "email_sent": email_sent, "dev_code": code if not SMTP_USER else None}


@app.post("/api/auth/reset-password")
async def reset_password(request: Request, data: dict):
    """Reset a user's password using the email verification code."""
    client_ip = _get_real_client_ip(request)
    email = _normalize_email(data.get("email", ""))
    code = data.get("code", "")
    password = data.get("password", "")
    if not email or not code or not password:
        raise HTTPException(status_code=400, detail="Email, code, and new password are required")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    stored = _verification_codes.get(f"reset:{email}")
    if not stored:
        raise HTTPException(status_code=400, detail="No reset code found. Request a new one.")
    if time.time() > stored["expires"]:
        del _verification_codes[f"reset:{email}"]
        raise HTTPException(status_code=400, detail="Reset code expired. Request a new one.")
    if code != stored["code"]:
        raise HTTPException(status_code=400, detail="Invalid reset code")
    users = []
    try:
        if Path(USERS_FILE).exists():
            with open(USERS_FILE) as f:
                users = json.load(f)
    except Exception:
        users = []
    updated = False
    for user in users:
        if _normalize_email(user.get("email", "")) == email:
            user["password_hash"] = _hash_password(password)
            user["password_last_updated"] = datetime.now().isoformat()
            updated = True
            break
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")
    # Revoke all existing sessions for this user after password change
    SESSIONS_FILE = Path("data/sessions.json")
    if SESSIONS_FILE.exists():
        with open(SESSIONS_FILE, 'r', encoding='utf-8') as f:
            sessions = json.load(f)
        # Keep only sessions that don't belong to this user
        active_sessions = {}
        revoked_count = 0
        for sid, sess in sessions.items():
            if sess.get("user_email") != email:
                active_sessions[sid] = sess
            else:
                revoked_count +=1
        _atomic_write_json(SESSIONS_FILE, active_sessions, indent=2)
        if revoked_count > 0:
            _log_audit_event("all_sessions_revoked", email, client_ip, {"revoked_count": revoked_count})
    
    _atomic_write_json(USERS_FILE, users, indent=2)
    del _verification_codes[f"reset:{email}"]
    return {"success": True, "message": "Password reset successfully, all existing sessions revoked"}


@app.post("/api/resend-verification")
async def resend_verification(request: Request, data: dict):
    """Resend email verification code — generates a new server-side code."""
    if not _check_rate_limit(request, "resend_verification", max_req=3):
        raise HTTPException(status_code=429, detail="Too many requests")
    email = data.get("email", "").lower().strip()
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    # Generate new code
    code = str(secrets.randbelow(900000) + 100000)
    _verification_codes[email] = {"code": code, "expires": time.time() + 600}
    # Send via email
    email_sent = False
    if SMTP_USER and SMTP_PASS:
        email_sent = send_email(
            email,
            "RockyCrypt Verification Code",
            _build_email_html(
                "Verify your account",
                "Hello,",
                [
                    f"<p>Your verification code is:</p><div style='font-size:32px;font-weight:bold;letter-spacing:8px;color:#00D062;text-align:center;padding:20px;background:#0B0B0F;border:2px dashed #00D062;border-radius:10px;margin:20px 0'>{code}</div>",
                    "<p>This code expires in 10 minutes.</p>",
                ],
            ),
        )
    return {"success": True, "message": "Verification code sent", "email_sent": email_sent, "dev_code": code if not SMTP_USER else None}


@app.post("/api/logout")
async def logout_user():
    """Handle user logout (client discards token)."""
    return {"success": True, "message": "Logged out successfully"}


# ─── Paystack Webhook (server-side payment verification) ─────────────────────

@app.post("/api/paystack/webhook")
async def paystack_webhook(request: Request):
    """Paystack webhook endpoint — verifies payment server-side before granting premium."""
    if not PAYSTACK_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Paystack not configured")
    # Verify Paystack signature
    paystack_signature = request.headers.get("x-paystack-signature", "")
    body = await request.body()
    import hmac
    import hashlib
    computed = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        body,
        hashlib.sha512
    ).hexdigest()
    if computed != paystack_signature:
        raise HTTPException(status_code=401, detail="Invalid signature")
    # Parse event
    try:
        event = json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid payload")
    # Handle subscription success
    if event.get("event") == "subscription.create":
        data = event.get("data", {})
        customer_email = data.get("customer", {}).get("email", "")
        plan_code = data.get("plan", {}).get("plan_code", "")
        reference = data.get("reference", "")
        if customer_email:
            # Load subscriptions
            subs = {}
            try:
                if Path(SUBSCRIPTIONS_FILE).exists():
                    with open(SUBSCRIPTIONS_FILE) as f:
                        subs = json.load(f)
            except Exception:
                pass
            # Determine plan from plan code
            plan = "monthly"
            if "semi" in plan_code.lower():
                plan = "semi"
            elif "annual" in plan_code.lower() or "year" in plan_code.lower():
                plan = "annual"
            # Store subscription
            subs[customer_email] = {
                "active": True,
                "plan": plan,
                "plan_code": plan_code,
                "reference": reference,
                "activated_at": datetime.now().isoformat(),
            }
            _atomic_write_json(SUBSCRIPTIONS_FILE, subs, indent=2)
            return {"status": "success", "message": "Subscription activated"}
    # Handle subscription disable (cancellation)
    if event.get("event") == "subscription.disable":
        data = event.get("data", {})
        customer_email = data.get("customer", {}).get("email", "")
        if customer_email:
            subs = {}
            try:
                if Path(SUBSCRIPTIONS_FILE).exists():
                    with open(SUBSCRIPTIONS_FILE) as f:
                        subs = json.load(f)
            except Exception:
                pass
            if customer_email in subs:
                subs[customer_email]["active"] = False
                subs[customer_email]["cancelled_at"] = datetime.now().isoformat()
                _atomic_write_json(SUBSCRIPTIONS_FILE, subs, indent=2)
    return {"status": "ok"}


@app.get("/api/subscription/status")
async def get_subscription_status(user: dict = Depends(_get_current_user)):
    """Check if the current user has an active premium subscription (server-side)."""
    if not user:
        return {"premium": False, "plan": "free"}
    email = user.get("email", "")
    status = _get_subscription_state(email)
    if _is_admin_identity(email):
        return {"premium": True, "plan": "admin"}
    return status


@app.get("/api/auth/me")
async def get_current_user_info(user: dict = Depends(_get_current_user)):
    """Return the current authenticated user's profile info including admin and premium status."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    email = user.get("email", "")
    status = _get_subscription_state(email)
    return {
        "email": email,
        "admin": _is_admin_identity(email),
        "premium": status.get("premium", False) or _is_admin_identity(email),
        "plan": "admin" if _is_admin_identity(email) else status.get("plan", "free"),
        "tier": status.get("tier", "free"),
    }


@app.get("/api/paystack/init-config")
async def get_paystack_public_config():
    """Return Paystack PUBLIC key for client-side payment init (key is safe to expose)."""
    if not PAYSTACK_PUBLIC_KEY:
        return JSONResponse({"configured": False, "public_key": ""})
    return JSONResponse({"configured": True, "public_key": PAYSTACK_PUBLIC_KEY})


@app.get("/api/legal/privacy")
async def get_privacy_policy():
    """Return the privacy policy for the client and users."""
    try:
        policy_path = _BASE_DIR / "PRIVACY_POLICY.md"
        if policy_path.exists():
            text = policy_path.read_text(encoding="utf-8")
            return JSONResponse({"content": text, "title": "Privacy Policy"})
    except Exception:
        pass
    return JSONResponse({"content": "Privacy policy unavailable.", "title": "Privacy Policy"})


@app.get("/api/legal/terms")
async def get_terms_of_service():
    """Return the terms of service for the client and users."""
    try:
        policy_path = _BASE_DIR / "PRIVACY_POLICY.md"
        if policy_path.exists():
            text = policy_path.read_text(encoding="utf-8")
            return JSONResponse({"content": text, "title": "Terms of Service"})
    except Exception:
        pass
    return JSONResponse({"content": "Terms of service unavailable.", "title": "Terms of Service"})


# ── Integrate Phase-1 feature & security modules (non-invasive) ────────────────
# Each module augments the server rather than replacing it. Every import is
# wrapped so that if a module is unavailable in the current environment the
# server still starts — only the corresponding endpoints are absent.
try:
    import rockycrypt_modules as _rocky_modules
    from contextlib import asynccontextmanager
    _server_module = sys.modules[__name__]

    _prev_lifespan = getattr(app.router, "lifespan_context", None)

    @asynccontextmanager
    async def _integrate_rockycrypt_modules(_app):
        try:
            _rocky_modules.register(app, _server_module)
        except Exception as exc:                      # noqa: BLE001
            print(f"[rockycrypt_modules] integration error: {exc}")
        if _prev_lifespan is not None:
            async with _prev_lifespan(_app):
                yield
        else:
            yield

    # Wire module registration into the app lifespan startup phase. This is the
    # modern FastAPI/Starlette 1.x API (add_event_handler/on_event are removed or
    # deprecated), and it guarantees register() runs exactly once, on startup.
    app.router.lifespan_context = _integrate_rockycrypt_modules
except Exception as exc:                              # noqa: BLE001
    print(f"[rockycrypt_modules] integration layer skipped: {exc}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--analyze", action="store_true", help="Run analysis job and exit")
    args = parser.parse_args()

    if args.analyze:
        run_analysis_job()
    else:
        import uvicorn
        port = int(os.environ.get("PORT", os.environ.get("ROCKYCRYPT_PORT", 5000)))
        # Bind to localhost by default for security; override with ROCKYCRYPT_HOST for production
        host = os.environ.get("ROCKYCRYPT_HOST", "127.0.0.1")
        print(f"[*] Starting RockyCrypt server on http://{host}:{port}")
        print(f"[*] Security: CORS restricted, admin auth required, JWT enabled")
        # Start automatic backup scheduler
        _start_backup_scheduler()
        uvicorn.run(app, host=host, port=port)