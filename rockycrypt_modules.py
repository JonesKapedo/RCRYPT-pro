"""
RockyCrypt — Integrated Module Library (wiring layer)
======================================================
Bridges the standalone Phase-1 feature / security modules into the live
FastAPI application (``rockycrypt_server.py``) so they augment, rather than
replace, the server's native implementations.

Analysis modules -> /api/indicators/*, /api/live/*, /api/ml/*, /api/screener/*
Security  modules -> login/2FA hooks, email validation, payment fraud scoring,
                     GDPR data-rights endpoints, encrypted backups, compliance reports

Every module is imported on its own; if an import (or one of its optional
dependencies) is unavailable the rest of the integration layer stays up --
the server always keeps serving.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets as _secrets
import threading
import time
from datetime import datetime, date
from pathlib import Path

_BASE_DIR = Path(__file__).parent



from fastapi import HTTPException, Depends
from fastapi.responses import FileResponse
import pandas as pd

# ── JSON helpers ─────────────────────────────────────────────────────────────
def _json_safe(value):
    """Make numpy / pandas scalars JSON-serialisable; NaN -> None."""
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            return None
    if isinstance(value, float) and value != value:        # NaN
        return None
    if isinstance(value, (pd.Timestamp, datetime, date)):
        return value.isoformat()
    if hasattr(value, "tolist"):
        return value.tolist()
    return str(value)


def _json_dump(obj):
    return json.dumps(obj, default=_json_safe)


def _sanitize_json(obj):
    """Recursively make a structure JSON-safe for Starlette's strict JSONResponse.

    Python's ``json.dumps`` only invokes the ``default`` hook for objects that are
    *not* natively serializable -- so non-finite ``float`` values (NaN/Inf produced
    by pandas/numpy) and numpy scalars slip straight through and crash the encode
    step (which runs with ``allow_nan=False``). Walking the structure here converts
    every such value into a native JSON-safe type.
    """
    if isinstance(obj, dict):
        return {str(k): _sanitize_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_sanitize_json(v) for v in obj]
    if isinstance(obj, bool) or obj is None:
        return obj
    if isinstance(obj, float):
        if obj != obj or obj in (float("inf"), float("-inf")):
            return None
        return obj
    if isinstance(obj, (int, str)):
        return obj
    if hasattr(obj, "item"):  # numpy / pandas scalar
        try:
            return _sanitize_json(obj.item())
        except Exception:                               # noqa: BLE001
            return None
    if isinstance(obj, (pd.Timestamp, datetime, date)):
        return obj.isoformat()
    return obj



# ── Module loading (each import isolated so one failure can't break the rest) ─
def _load(module_name: str):
    try:
        mod = __import__(module_name)
        _say(f"[rockycrypt_modules] [OK] module loaded: {module_name}")
        return mod
    except Exception as exc:                               # noqa: BLE001
        _say(f"[rockycrypt_modules] [!] module '{module_name}' unavailable: {exc}")
        return None


def _say(msg: str) -> None:
    """Print helper that never raises: safe under cp1252/ASCI-impaired stdout."""
    try:
        print(msg, flush=True)
    except Exception:                                       # noqa: BLE001
        try:
            print(msg.encode("ascii", "replace").decode("ascii"), flush=True)
        except Exception:                                   # noqa: BLE001
            pass


technical_indicators = _load("technical_indicators")
nse_real_time_data   = _load("nse_real_time_data")
ml_trading_signals   = _load("ml_trading_signals")
advanced_screener    = _load("advanced_screener")
account_takeover     = _load("account_takeover_protection")
email_security       = _load("email_security")
payment_fraud        = _load("payment_fraud_prevention")
gdpr_pci             = _load("gdpr_pci_compliance")
data_encryption      = _load("data_encryption_breach_prevention")
backtest             = _load("backtest")

MODULE_NAMES = {
    "technical_indicators": technical_indicators,
    "nse_real_time_data": nse_real_time_data,
    "ml_trading_signals": ml_trading_signals,
    "advanced_screener": advanced_screener,
    "account_takeover_protection": account_takeover,
    "email_security": email_security,
    "payment_fraud_prevention": payment_fraud,
    "gdpr_pci_compliance": gdpr_pci,
    "data_encryption_breach_prevention": data_encryption,
    "backtest": backtest,
}
MODULES_LOADED = any(v is not None for v in MODULE_NAMES.values())
# MARK: === END CHUNK A ===


# ── User-record helpers (read/write the server's users.json directly) ──────────
def _find_user(server, email: str):
    """Return the user dict whose email matches, or None."""
    try:
        if not Path(server.USERS_FILE).exists():
            return None
        users = json.loads(Path(server.USERS_FILE).read_text(encoding="utf-8"))
    except Exception:
        return None
    return next((u for u in users if u.get("email", "").lower() == email.lower()), None)


def _set_user_2fa(server, email: str, enabled: bool, secret: str = "") -> bool:
    """Toggle 2FA on a user record and persist."""
    try:
        if not Path(server.USERS_FILE).exists():
            return False
        users = json.loads(Path(server.USERS_FILE).read_text(encoding="utf-8"))
    except Exception:
        return False
    found = False
    for u in users:
        if u.get("email", "").lower() == email.lower():
            u["2fa_enabled"] = enabled
            u["2fa_secret"] = secret
            found = True
            break
    if found:
        try:
            server._atomic_write_json(server.USERS_FILE, users, indent=2)
        except Exception:
            return False
    return found
# MARK: === END CHUNK B1 ===


# ── Data helpers ─────────────────────────────────────────────────────────────
def _history_df(server, symbol: str) -> pd.DataFrame:
    """Build an OHLCV DataFrame for a symbol from the server's price history."""
    hist = server.load_history()
    series = hist.get(symbol.upper()) or hist.get(symbol) or []
    if not series:
        return pd.DataFrame()
    df = pd.DataFrame(series)
    required = {"open", "high", "low", "close", "volume"}
    if not required.issubset(df.columns):
        return pd.DataFrame()
    return df[["date", "open", "high", "low", "close", "volume"]].copy()


def _stocks_table(server) -> pd.DataFrame:
    """Build the screener's stock table from the server's live market snapshot."""
    live = server.fetch_live_nse_data() or {}
    stocks = live.get("stocks") or {}
    hist = server.load_history()
    rows = []
    for sym, q in stocks.items():
        series = hist.get(sym.upper()) or hist.get(sym) or []
        prev = series[-1]["close"] if series and "close" in series[-1] else q.get("prev_price")
        prev = prev or 0
        price = q.get("price", 0) or 0
        chg = q.get("change_pct")
        if chg is None and prev:
            chg = (price - prev) / prev * 100
        rows.append({
            "symbol": sym, "name": sym, "price": float(price),
            "change_pct": float(chg or 0), "volume": float(q.get("volume", 0) or 0),
            "pe_ratio": float("nan"), "pb_ratio": float("nan"),
            "dividend_yield": float("nan"), "eps_growth": float("nan"),
            "revenue_growth": float("nan"), "roe": float("nan"), "roa": float("nan"),
            "rsi": float("nan"), "momentum": float("nan"),
            "volume_ratio": float("nan"), "trend_strength": float("nan"),
            "prev_close": float(prev),
        })
    return pd.DataFrame(rows)


# ── Live NSE feed bridge ─────────────────────────────────────────────────────
class _LiveFeedBridge:
    """Seed ``NSERealTimeDataManager`` from the server's NSE snapshot cache.

    The manager never opens a real WebSocket (that URL is a placeholder), so we
    keep its in-memory caches warm by replaying the server's periodic market
    snapshot through ``_process_market_tick``.
    """

    def __init__(self):
        self.manager = nse_real_time_data.NSERealTimeDataManager() if nse_real_time_data else None
        self.last_seed = 0.0

    async def seed(self, server):
        if self.manager is None:
            return
        if time.time() - self.last_seed < 5:          # rate-limit seeding to ~5s
            return
        self.last_seed = time.time()
        try:
            live = server.fetch_live_nse_data() or {}
            for sym, q in (live.get("stocks") or {}).items():
                price = q.get("price") or 0
                prev = q.get("prev_price") or price
                tick = {
                    "symbol": sym.upper(),
                    "lastPrice": price,
                    "openPrice": q.get("open") or prev,
                    "highPrice": q.get("high") or price,
                    "lowPrice": q.get("low") or price,
                    "closePrice": prev,
                    "totalTradedVolume": q.get("volume") or 0,
                    "totalTradedValue": q.get("turnover") or 0,
                    "change": price - prev,
                    "changePercent": q.get("change_pct") or 0,
                    "bid": round(price * 0.995, 2),
                    "ask": round(price * 1.005, 2),
                    "bidQty": 0, "askQty": 0,
                    "time": live.get("market_time", ""),
                    "bidLevels": [], "askLevels": [],
                }
                await self.manager._process_market_tick(tick)
        except Exception as exc:                      # noqa: BLE001
            print(f"[rockycrypt_modules] livefeed seed error: {exc}")


_live_bridge = _LiveFeedBridge() if nse_real_time_data else None

# Idempotency guard so register() can never double-register routes/scheduler
_registered_once = False


# ── Dispatcher: called once from the server startup hook ─────────────────────
def register(app, server):
    """Register all integrated-module endpoints on *app* and arm the scheduler.

    Parameters
    ----------
    app    : the FastAPI instance
    server : the ``rockycrypt_server`` module object (the server exposes its
             helpers / file paths as module-level attributes used below).
    """
    global _registered_once
    if _registered_once:
        return
    _registered_once = True

    if technical_indicators:
        _register_indicator_routes(app, server)
    if nse_real_time_data and _live_bridge:
        _register_live_routes(app, server)
    if ml_trading_signals:
        _register_ml_routes(app, server)
    if advanced_screener:
        _register_screener_routes(app, server)
    if account_takeover:
        _register_2fa_routes(app, server)
    if gdpr_pci:
        _register_gdpr_routes(app, server)
    if data_encryption:
        _register_security_audit_routes(app, server)
        _start_security_scheduler()
    if backtest:
        _register_track_record_routes(app, server)
# MARK: === END CHUNK B2 ===


# ── Analysis route groups ─────────────────────────────────────────────────────
def _register_indicator_routes(app, server):
    @app.get("/api/indicators/{symbol}")
    async def integrated_indicators(symbol: str):
        df = _history_df(server, symbol)
        if df.empty or len(df) < 30:
            return {
                "error": "Insufficient history for technical analysis (need >=30 bars)",
                "symbol": symbol.upper(),
                "data_points": len(df),
            }
        try:
            ind = technical_indicators.TechnicalIndicators(df)
            signals = _sanitize_json(ind.calculate_all_signals())
            return _sanitize_json({
                "symbol": symbol.upper(),
                "signals": signals,
                "buy_signals": ind.get_buy_signals(),
                "sell_signals": ind.get_sell_signals(),
                "data_points": len(df),
                "source": "technical_indicators.py (module integrated)",
            })
        except Exception as exc:                      # noqa: BLE001
            return {"error": str(exc), "symbol": symbol.upper()}

    @app.get("/api/indicators/{symbol}/moving-averages")
    async def integrated_ma(symbol: str, period: int = 20):
        df = _history_df(server, symbol)
        if df.empty:
            return {"error": "No history for symbol", "symbol": symbol.upper()}
        try:
            ind = technical_indicators.TechnicalIndicators(df)
            ma = ind.moving_average(period)
            return {"symbol": symbol.upper(), "period": period,
                    "data": json.loads(json.dumps(ma.tolist(), default=_json_safe))}
        except Exception as exc:
            return {"error": str(exc)}


def _register_ml_routes(app, server):
    _ml_lock = threading.Lock()

    @app.post("/api/ml/train/{symbol}")
    async def integrated_ml_train(symbol: str):
        df = _history_df(server, symbol)
        if df.empty or len(df) < 90:                   # need lookback(60)+train split
            return {"error": "Insufficient history to train (need >=90 bars)",
                    "symbol": symbol.upper(), "data_points": len(df)}
        with _ml_lock:
            try:
                results = _ml_singleton.train_models(df)
                _ml_singleton.trained = True
                return {"status": "trained", "symbol": symbol.upper(),
                        "results": json.loads(json.dumps(results, default=_json_safe))}
            except Exception as exc:
                return {"error": str(exc)}

    @app.get("/api/ml/signal/{symbol}")
    async def integrated_ml_signal(symbol: str):
        df = _history_df(server, symbol)
        if df.empty:
            return {"error": "No history for symbol", "symbol": symbol.upper()}
        if len(df) < 30:
            return {"error": "Insufficient history for ML signal",
                    "symbol": symbol.upper(), "data_points": len(df)}
        with _ml_lock:
            try:
                if not getattr(_ml_singleton, "trained", False):
                    _ml_singleton.load_models()
                signal = _ml_singleton.generate_signal(df)
                if signal.get("error"):
                    _ml_singleton.train_models(df)
                    _ml_singleton.trained = True
                    signal = _ml_singleton.generate_signal(df)
                signal["symbol"] = symbol.upper()
                return json.loads(json.dumps(signal, default=_json_safe))
            except Exception as exc:
                return {"error": str(exc)}

    @app.get("/api/ml/importance/{symbol}")
    async def integrated_ml_importance(symbol: str):
        with _ml_lock:
            importance = _ml_singleton.get_feature_importance()
        return {"symbol": symbol.upper(),
                "importance": json.loads(json.dumps(importance, default=_json_safe))}
# MARK: === END CHUNK C ===


# ── ML model singleton (instantiated once so /api/ml/* endpoints never block on init) ─
_ml_singleton = ml_trading_signals.MLTradingSignals() if ml_trading_signals else None


# ── Live NSE routes ─────────────────────────────────────────────────────
def _register_live_routes(app, server):
    @app.get("/api/live/quote/{symbol}")
    async def integrated_live_quote(symbol: str):
        await _live_bridge.seed(server)
        quote = await _live_bridge.manager.get_live_quote(symbol)
        if quote:
            return quote
        # Fall back to the server's native snapshot so the endpoint always answers
        stocks = (server.fetch_live_nse_data() or {}).get("stocks") or {}
        q = stocks.get(symbol.upper())
        if q:
            return {"symbol": symbol.upper(), **q,
                    "timestamp": datetime.utcnow().isoformat()}
        return {"error": "Symbol not found", "symbol": symbol}

    @app.get("/api/live/quotes")
    async def integrated_live_quotes():
        await _live_bridge.seed(server)
        return await _live_bridge.manager.get_all_quotes()

    @app.get("/api/live/bid-ask/{symbol}")
    async def integrated_bid_ask(symbol: str):
        await _live_bridge.seed(server)
        spread = await _live_bridge.manager.get_bid_ask(symbol)
        if spread:
            return spread
        return {"error": "Symbol not found", "symbol": symbol}

    @app.get("/api/live/orderbook/{symbol}")
    async def integrated_orderbook(symbol: str):
        await _live_bridge.seed(server)
        book = await _live_bridge.manager.get_order_book(symbol)
        if book:
            return book
        return {"error": "Symbol not found", "symbol": symbol}

    @app.get("/api/live/breadth")
    async def integrated_breadth():
        await _live_bridge.seed(server)
        return await _live_bridge.manager.get_market_breadth()

    @app.get("/api/live/history/{symbol}")
    async def integrated_live_history(symbol: str, period: str = "1D"):
        hist = server.load_history()
        series = hist.get(symbol.upper()) or hist.get(symbol) or []
        if not series:
            return {"error": "No history found", "symbol": symbol}
        return {"symbol": symbol.upper(), "period": period, "data": series[-120:]}

    @app.websocket("/api/live/stream")
    async def integrated_live_stream(ws):
        await ws.accept()
        try:
            while True:
                await _live_bridge.seed(server)
                quotes = await _live_bridge.manager.get_all_quotes()
                names = sorted(quotes.keys())
                await ws.send_json({"type": "quotes", "count": len(names), "quotes": quotes})
                await asyncio.sleep(3)
        except Exception:
            pass
# MARK: === END CHUNK D1 ===


# ── Screener routes ─────────────────────────────────────────────────────
def _register_screener_routes(app, server):
    @app.post("/api/screener/run")
    async def integrated_screener_run(filters: dict = {}):
        stocks = _stocks_table(server)
        if stocks.empty:
            return {"error": "No market data available"}
        try:
            s = advanced_screener.AdvancedScreener(stocks)
            pe = filters.get("pe_range")
            if pe and len(pe) == 2:
                s.pe_ratio_filter(pe[0], pe[1])
            pb = filters.get("pb_range")
            if pb and len(pb) == 2:
                s.pb_ratio_filter(pb[0], pb[1])
            dy = filters.get("dividend_yield")
            if dy:
                s.dividend_yield_filter(dy)
            eg = filters.get("eps_growth")
            if eg:
                s.eps_growth_filter(eg)
            rsi = filters.get("rsi_range")
            if rsi and len(rsi) == 2:
                s.rsi_filter(rsi[0], rsi[1])
            pm = filters.get("price_above_ma")
            if pm:
                s.price_above_ma_filter(pm)
            mv = filters.get("min_volume")
            if mv:
                s.volume_filter(mv)
            vs = filters.get("volume_spike")
            if vs:
                s.volume_spike_filter(vs)
            results = s.run_and_score(limit=filters.get("limit", 50))
            return _sanitize_json({
                "count": len(results),
                "filters_applied": len(s.rules),
                "stocks": results,
            })
        except Exception as exc:
            return {"error": str(exc)}

    @app.get("/api/screener/templates")
    async def integrated_screener_templates():
        return {
            "value_investing": {"name": "Value Investing",
                "filters": ["PE < 15", "PB < 1.5", "Dividend > 3%", "ROE > 15%"]},
            "growth_stocks": {"name": "Growth Stocks",
                "filters": ["EPS Growth > 20%", "Revenue Growth > 15%", "Price above SMA-50"]},
            "dividend_aristocrats": {"name": "Dividend Aristocrats",
                "filters": ["Dividend Yield > 4%", "EPS Growth > 5%", "ROE > 12%"]},
            "breakout_stocks": {"name": "Breakout Stocks",
                "filters": ["Price above SMA-50", "Volume Spike > 1.5x", "RSI > 50"]},
        }

    @app.post("/api/screener/save")
    async def integrated_screener_save(data: dict, user: dict = Depends(server._get_current_user)):
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        name = (data or {}).get("name", "custom-screen")
        stocks = _stocks_table(server)
        s = advanced_screener.AdvancedScreener(stocks)
        s.save_screen(f"{user.get('email')}::{name}")
        return {"status": "saved", "name": name}
# MARK: === END CHUNK D2 ===


# ── 2FA / login-security routes ────────────────────────────────────────
def _register_2fa_routes(app, server):
    @app.post("/api/account/enable-2fa")
    async def integrated_enable_2fa(user: dict = Depends(server._get_current_user)):
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        secret = base64.b32encode(_secrets.token_bytes(20)).decode()
        codes = account_takeover.TwoFactorAuth.generate_backup_codes()
        email = user.get("email", "")
        return {
            "secret": secret,
            "backup_codes": codes,
            "qr_code": f"otpauth://totp/RockyCrypt:{email}?secret={secret}&issuer=RockyCrypt",
        }

    @app.post("/api/account/confirm-2fa")
    async def integrated_confirm_2fa(data: dict, user: dict = Depends(server._get_current_user)):
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        data = data or {}
        token = data.get("token", "")
        secret = data.get("secret", "")
        if not account_takeover.TwoFactorAuth.verify_totp(secret, token):
            raise HTTPException(status_code=400, detail="Invalid 2FA token")
        email = user.get("email", "")
        if not _set_user_2fa(server, email, True, secret):
            raise HTTPException(status_code=404, detail="User not found")
        return {"success": True, "message": "2FA enabled successfully"}

    @app.post("/api/auth/verify-2fa")
    async def integrated_verify_2fa(data: dict):
        data = data or {}
        email = (data.get("email") or "").lower().strip()
        token = (data.get("token") or "").strip()
        user = _find_user(server, email)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        secret = user.get("2fa_secret") or ""
        if secret and account_takeover.TwoFactorAuth.verify_totp(secret, token):
            jwt_token = server._create_jwt_token({
                "sub": email, "email": email,
                "admin": server._is_admin_identity(email),
                "plan": user.get("plan", "free")})
            status = server._get_subscription_state(email)
            return {"success": True, "token": jwt_token, "email": email,
                    "premium": status.get("premium", False),
                    "plan": user.get("plan", "free"),
                    "admin": server._is_admin_identity(email)}
        # Fallback: email one-time code issued by TwoFactorAuth.send_2fa_code
        codes_file = Path("data") / "2fa_codes.json"
        if codes_file.exists():
            try:
                codes = json.loads(codes_file.read_text(encoding="utf-8"))
                stored = codes.get(email)
                if stored and str(stored.get("code")) == str(token):
                    if datetime.fromisoformat(stored["expires"]) > datetime.now():
                        jwt_token = server._create_jwt_token({
                            "sub": email, "email": email,
                            "admin": server._is_admin_identity(email),
                            "plan": user.get("plan", "free")})
                        return {"success": True, "token": jwt_token, "email": email}
            except Exception:
                pass
        raise HTTPException(status_code=400, detail="Invalid or expired 2FA code")
# MARK: === END CHUNK E1 ===


# ── GDPR / compliance routes ───────────────────────────────────────────
def _register_gdpr_routes(app, server):
    @app.post("/api/user/export-data")
    async def integrated_export_data(user: dict = Depends(server._get_current_user)):
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        email = user.get("email", "")
        ok, path = gdpr_pci.GDPRCompliance.export_user_data_as_json(email)
        if not ok:
            raise HTTPException(status_code=500, detail="Data export failed")
        return FileResponse(path, filename=f"{email}_data.json")

    @app.post("/api/user/request-deletion")
    async def integrated_request_deletion(user: dict = Depends(server._get_current_user)):
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        email = user.get("email", "")
        req = gdpr_pci.GDPRCompliance.delete_user_data_request(email)
        if data_encryption:
            try:
                data_encryption.DataRetentionPolicy.schedule_user_data_deletion(email)
            except Exception:
                pass
        return {"success": True, "message": "Deletion request received (grace period enforced)",
                "grace_period_ends": req.get("grace_period_ends"),
                "can_cancel_until": req.get("can_cancel_until")}

    @app.post("/api/user/cancel-deletion")
    async def integrated_cancel_deletion(user: dict = Depends(server._get_current_user)):
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        email = user.get("email", "")
        cancelled = True
        if data_encryption:
            try:
                cancelled = data_encryption.DataRetentionPolicy.cancel_scheduled_deletion(email)
            except Exception:
                pass
        return {"success": True,
                "message": "Deletion request cancelled" if cancelled
                         else "No pending deletion request"}

    @app.post("/api/user/consent")
    async def integrated_record_consent(data: dict, user: dict = Depends(server._get_current_user)):
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        data = data or {}
        consent_type = data.get("type", "privacy")
        given = bool(data.get("given", True))
        gdpr_pci.GDPRCompliance.record_user_consent(user.get("email", ""), consent_type, given)
        return {"success": True, "message": "Consent recorded"}

    @app.get("/api/compliance/privacy-policy")
    async def integrated_compliance_privacy():
        module_policy = gdpr_pci.GDPRCompliance.get_privacy_policy()
        local = _BASE_DIR / "PRIVACY_POLICY.md"
        existing = local.read_text(encoding="utf-8") if local.exists() else ""
        return {"title": "Privacy Policy", "content": existing or module_policy, "module": True}

    @app.get("/api/compliance/report")
    async def integrated_compliance_report(admin: dict = Depends(server._require_admin)):
        return gdpr_pci.ComplianceReporting.generate_compliance_dashboard()

    @app.get("/api/compliance/dpia")
    async def integrated_compliance_dpia(admin: dict = Depends(server._require_admin)):
        return gdpr_pci.ComplianceReporting.generate_dpia_report("RockyCrypt NSE Analytics")
# MARK: === END CHUNK E2 ===


# ── Security audit / breach-prevention routes ─────────────────────────────────
def _register_security_audit_routes(app, server):
    @app.get("/api/security/breach-indicators")
    async def integrated_breach_indicators(admin: dict = Depends(server._require_admin)):
        if not data_encryption:
            raise HTTPException(503, "Security module unavailable")
        report = data_encryption.BreachDetection.detect_breach_indicators()
        return {"checked_at": datetime.utcnow().isoformat(),
                "indicators": _sanitize_json(report)}

    @app.get("/api/security/retention/process")
    async def integrated_retention_process(admin: dict = Depends(server._require_admin)):
        if not data_encryption:
            raise HTTPException(503, "Data encryption module unavailable")
        dp = data_encryption.DataRetentionPolicy()
        processed = dp.process_scheduled_deletions()
        cleaned = dp.cleanup_expired_data()
        return {"processed_deletions": processed, "cleaned": cleaned,
                "timestamp": datetime.utcnow().isoformat()}

    @app.post("/api/security/encrypt-field")
    async def integrated_encrypt_field(data: dict, admin: dict = Depends(server._require_admin)):
        if not data_encryption:
            raise HTTPException(503, "Encryption module unavailable")
        er = data_encryption.EncryptionAtRest()
        ciphertext = er.encrypt_field(data.get("value", "") or "")
        return {"encrypted": ciphertext}

    @app.post("/api/security/decrypt-field")
    async def integrated_decrypt_field(data: dict, admin: dict = Depends(server._require_admin)):
        if not data_encryption:
            raise HTTPException(503, "Encryption module unavailable")
        er = data_encryption.EncryptionAtRest()
        plaintext = er.decrypt_field(data.get("value", "") or "")
        return {"decrypted": plaintext}

    @app.post("/api/security/anonymize")
    async def integrated_anonymize(data: dict, admin: dict = Depends(server._require_admin)):
        if not data_encryption:
            raise HTTPException(503, "Anonymization module unavailable")
        az = data_encryption.DataAnonymization()
        field = (data.get("field", "") or "").lower()
        value = data.get("value", "") or ""
        fn = {"email": az.anonymize_email, "ip": az.anonymize_ip_address,
              "card": az.anonymize_card_number}.get(field)
        if not fn:
            raise HTTPException(400, "field must be 'email', 'ip', or 'card'")
        return {"field": field, "original": value, "anonymized": fn(value)}

    @app.get("/api/security/backups")
    async def integrated_backups_create(admin: dict = Depends(server._require_admin)):
        if not data_encryption:
            raise HTTPException(503, "Backup module unavailable")
        bs = data_encryption.BackupSecurity()
        ok, path = bs.create_encrypted_backup("backups")
        return {"created": ok, "backup_path": path}

    @app.get("/api/security/backups/{file_path:path}")
    async def integrated_backup_integrity(file_path: str, admin: dict = Depends(server._require_admin)):
        if not data_encryption:
            raise HTTPException(503, "Backup module unavailable")
        bs = data_encryption.BackupSecurity()
        ok, msg = bs.verify_backup_integrity(file_path)
        return {"valid": ok, "message": msg}

    @app.get("/api/security/compliance-score")
    async def integrated_compliance_score(admin: dict = Depends(server._require_admin)):
        loaded_count = sum(1 for v in MODULE_NAMES.values() if v is not None)
        total = len(MODULE_NAMES)
        return {"modules": {k: bool(v) for k, v in MODULE_NAMES.items()},
                "loaded": loaded_count, "total": total,
                "health": "healthy" if loaded_count >= total * 0.6 else "degraded",
                "timestamp": datetime.utcnow().isoformat()}
# MARK: === END CHUNK F1 ===


# ── Track-record / backtest routes ────────────────────────────────────────────
_TRACK_RECORD_TTL = 3600          # published numbers change at most hourly
_track_record_cache: dict = {"at": 0.0, "report": None}


def _register_track_record_routes(app, server):
    """Publish signal performance: what the engine called, and what happened.

    ``/api/track-record`` is deliberately public and unauthenticated — it is the
    trust anchor for the whole product, so it has to be visible before signup.
    Evaluation walks the full price history, so results are cached for an hour;
    the work runs in a worker thread to keep the event loop free.
    """

    @app.get("/api/track-record")
    async def track_record(refresh: bool = False):
        now = time.time()
        cached = _track_record_cache["report"]
        if cached and not refresh and now - _track_record_cache["at"] < _TRACK_RECORD_TTL:
            return cached

        report = await asyncio.to_thread(
            backtest.evaluate_track_record,
            None, None, backtest.DEFAULT_HORIZONS,
            backtest.SIGNAL_LOG_FILE, server.HISTORY_FILE,
        )
        payload = _sanitize_json(report)
        _track_record_cache.update({"at": now, "report": payload})
        return payload

    @app.get("/api/track-record/signals")
    async def track_record_signals(limit: int = 100):
        limit = max(1, min(limit, 500))
        rows = await asyncio.to_thread(
            backtest.recent_signals,
            limit, backtest.DEFAULT_HORIZONS,
            backtest.SIGNAL_LOG_FILE, server.HISTORY_FILE,
        )
        return {"count": len(rows), "signals": _sanitize_json(rows)}

    @app.get("/api/backtest")
    async def run_backtest(
        horizons: str = "5,20,60",
        min_history: int = 20,
        symbol: str = "",
        admin: dict = Depends(server._require_admin),
    ):
        try:
            parsed = tuple(int(h) for h in horizons.split(",") if h.strip())
        except ValueError:
            raise HTTPException(400, "horizons must be comma-separated integers")
        if not parsed or any(h < 1 or h > 250 for h in parsed):
            raise HTTPException(400, "horizons must be between 1 and 250 sessions")

        symbols = [s.strip().upper() for s in symbol.split(",") if s.strip()] or None
        report = await asyncio.to_thread(
            backtest.run_backtest,
            backtest.load_history(server.HISTORY_FILE),
            parsed, max(2, min_history), symbols,
        )
        return _sanitize_json(report)


# ── Background schedulers ─────────────────────────────────────────────────────
_security_scheduler_started = False


def _start_security_scheduler():
    """Spawn a daemon thread that periodically runs retention / cleanup jobs.

    Only armed when ``data_encryption`` is available; in every other case
    (module missing in the current environment) it is a no-op so the server
    keeps serving.
    """
    global _security_scheduler_started
    if _security_scheduler_started or not data_encryption:
        return
    _security_scheduler_started = True

    def _tick():
        while True:
            try:
                dp = data_encryption.DataRetentionPolicy()
                dp.process_scheduled_deletions()
                dp.cleanup_expired_data()
            except Exception as exc:                         # noqa: BLE001
                print(f"[rockycrypt_modules] retention tick error: {exc}")
            time.sleep(900)                                  # every 15 min

    t = threading.Thread(target=_tick, daemon=True, name="rcm-security-scheduler")
    t.start()
    print("[rockycrypt_modules] security retention scheduler started (15 min interval)")
# MARK: === END CHUNK F2 ===







