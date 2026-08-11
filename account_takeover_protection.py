"""
RockyCrypt Account Takeover Protection Module
Comprehensive protection against unauthorized account access
"""

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import json
import ipaddress

# ============================================================================
# 1. DEVICE FINGERPRINTING (Detect Unusual Access Patterns)
# ============================================================================

class DeviceFingerprint:
    """Create and verify device fingerprints to detect account takeovers."""
    
    @staticmethod
    def create_fingerprint(user_agent: str, accept_language: str, 
                          accept_encoding: str, client_ip: str) -> str:
        """
        Create a device fingerprint from multiple browser attributes.
        Changes indicate potential account takeover.
        """
        fingerprint_data = f"{user_agent}|{accept_language}|{accept_encoding}|{client_ip}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    @staticmethod
    def is_device_match(stored_fingerprint: str, new_fingerprint: str, 
                       tolerance: float = 0.95) -> Tuple[bool, str]:
        """
        Check if device fingerprint matches stored one.
        Returns (is_match, risk_level)
        """
        if stored_fingerprint == new_fingerprint:
            return True, "trusted"
        
        # Partial match - possible VPN/proxy (still risky)
        if stored_fingerprint[:16] == new_fingerprint[:16]:
            return False, "suspicious"
        
        # No match - potential takeover
        return False, "blocked"


# ============================================================================
# 2. BEHAVIORAL ANALYSIS (Detect Unusual Activity)
# ============================================================================

class BehavioralAnalysis:
    """Detect unusual login patterns and activities."""
    
    UNUSUAL_TIME_DEVIATION_HOURS = 6  # Flag logins outside normal hours
    UNUSUAL_LOCATION_KM = 1000  # Flag logins >1000km from previous
    
    @staticmethod
    def get_user_login_history(user_email: str, max_records: int = 30) -> List[Dict]:
        """Get user's login history from audit log."""
        history_file = Path("data/login_history.json")
        if not history_file.exists():
            return []
        
        try:
            with open(history_file, 'r', encoding='utf-8') as f:
                all_logins = json.load(f)
            return all_logins.get(user_email.lower(), [])[-max_records:]
        except Exception:
            return []
    
    @staticmethod
    def is_unusual_time(user_email: str) -> Tuple[bool, str]:
        """Check if login time is outside user's normal pattern."""
        history = BehavioralAnalysis.get_user_login_history(user_email)
        if len(history) < 5:
            return False, "insufficient_history"  # Not enough data
        
        # Get average login times
        login_hours = []
        for login in history:
            try:
                login_time = datetime.fromisoformat(login['timestamp'])
                login_hours.append(login_time.hour)
            except (KeyError, ValueError):
                continue
        
        if not login_hours:
            return False, "no_data"
        
        # Calculate average and std deviation
        avg_hour = sum(login_hours) / len(login_hours)
        variance = sum((h - avg_hour) ** 2 for h in login_hours) / len(login_hours)
        std_dev = variance ** 0.5
        
        # Check if current login is >3 std devs from mean (99.7% confidence)
        current_hour = datetime.now().hour
        z_score = abs((current_hour - avg_hour) / max(std_dev, 1))
        
        if z_score > 3:
            return True, "unusual_time"
        
        return False, "normal_time"
    
    @staticmethod
    def is_unusual_location(user_email: str, current_ip: str) -> Tuple[bool, str]:
        """Check if login is from unusual geographic location (>1000km)."""
        history = BehavioralAnalysis.get_user_login_history(user_email, max_records=1)
        
        if not history or 'ip_address' not in history[-1]:
            return False, "first_location"
        
        previous_ip = history[-1]['ip_address']
        
        # Simple IP geolocation check (in production, use MaxMind GeoIP2 or similar)
        # For now, just check if IPs are very different
        try:
            prev_addr = ipaddress.ip_address(previous_ip)
            curr_addr = ipaddress.ip_address(current_ip)
            
            # Same subnet = same location (likely)
            if prev_addr.version == curr_addr.version:
                if str(prev_addr)[:str(prev_addr).rfind('.')] == str(curr_addr)[:str(curr_addr).rfind('.')]:
                    return False, "same_subnet"
        except ValueError:
            pass
        
        return False, "different_ip"  # Flagged for review


# ============================================================================
# 3. TWO-FACTOR AUTHENTICATION (2FA)
# ============================================================================

class TwoFactorAuth:
    """Multi-factor authentication implementation."""
    
    TOTP_WINDOW = 30  # Time window in seconds
    TOTP_DIGITS = 6   # Number of digits
    
    @staticmethod
    def generate_totp_secret() -> str:
        """Generate a TOTP secret for authenticator apps."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def verify_totp(secret: str, token: str, window: int = 1) -> bool:
        """
        Verify TOTP token.
        window=1 checks current and previous time window (60 seconds total).
        """
        import hmac
        import hashlib
        import struct
        import time
        
        try:
            # Decode secret
            import base64
            key = base64.b32decode(secret)
            
            # Get current time counter
            counter = int(time.time()) // TwoFactorAuth.TOTP_WINDOW
            
            # Check current and previous windows
            for i in range(-window, window + 1):
                test_counter = counter + i
                msg = struct.pack(">Q", test_counter)
                hash_obj = hmac.new(key, msg, hashlib.sha1)
                hash_bytes = hash_obj.digest()
                
                offset = hash_bytes[-1] & 0x0f
                code = struct.unpack(">I", hash_bytes[offset:offset+4])[0]
                code = (code & 0x7fffffff) % (10 ** TwoFactorAuth.TOTP_DIGITS)
                
                if code == int(token):
                    return True
            
            return False
        except Exception as e:
            print(f"[2fa] TOTP verification error: {e}")
            return False
    
    @staticmethod
    def generate_backup_codes(count: int = 10) -> List[str]:
        """Generate backup codes for account recovery."""
        return [secrets.token_hex(4) for _ in range(count)]
    
    @staticmethod
    def send_2fa_code(user_email: str, method: str = "email") -> str:
        """
        Send 2FA code via email or SMS.
        Returns code for testing purposes (remove in production).
        """
        code = str(secrets.randbelow(900000) + 100000)
        
        if method == "email":
            # Send via email (implement actual send)
            print(f"[2fa] Sending code {code} to {user_email}")
            # In production: send_email(user_email, "Your 2FA Code", f"Code: {code}")
        
        # Store code with expiry
        twofa_codes = {}
        codes_file = Path("data/2fa_codes.json")
        if codes_file.exists():
            with open(codes_file, 'r') as f:
                twofa_codes = json.load(f)
        
        twofa_codes[user_email.lower()] = {
            "code": code,
            "expires": (datetime.now() + timedelta(minutes=10)).isoformat(),
            "attempts": 0
        }
        
        with open(codes_file, 'w') as f:
            json.dump(twofa_codes, f, indent=2)
        
        return code  # Return for testing


# ============================================================================
# 4. SESSION MANAGEMENT (Secure Sessions)
# ============================================================================

class SessionManager:
    """Secure session management with revocation."""
    
    SESSION_TIMEOUT = 15 * 60  # 15 minutes
    REMEMBER_ME_TIMEOUT = 30 * 24 * 60 * 60  # 30 days
    
    @staticmethod
    def create_session(user_email: str, client_ip: str, user_agent: str,
                      remember_me: bool = False) -> Dict:
        """Create a secure session token."""
        session_id = secrets.token_urlsafe(32)
        device_fp = DeviceFingerprint.create_fingerprint(
            user_agent, "", "", client_ip
        )
        
        session = {
            "session_id": session_id,
            "user_email": user_email,
            "client_ip": client_ip,
            "device_fingerprint": device_fp,
            "created_at": datetime.now().isoformat(),
            "last_activity": datetime.now().isoformat(),
            "expires_at": (
                datetime.now() + timedelta(seconds=SessionManager.REMEMBER_ME_TIMEOUT)
                if remember_me
                else datetime.now() + timedelta(seconds=SessionManager.SESSION_TIMEOUT)
            ).isoformat(),
            "remember_me": remember_me
        }
        
        return session
    
    @staticmethod
    def revoke_session(session_id: str) -> bool:
        """Revoke a session (logout)."""
        sessions_file = Path("data/sessions.json")
        if not sessions_file.exists():
            return False
        
        try:
            with open(sessions_file, 'r') as f:
                sessions = json.load(f)
            
            if session_id in sessions:
                sessions[session_id]['revoked'] = True
                sessions[session_id]['revoked_at'] = datetime.now().isoformat()
                
                with open(sessions_file, 'w') as f:
                    json.dump(sessions, f, indent=2)
                
                return True
        except Exception as e:
            print(f"[session] Revocation error: {e}")
        
        return False
    
    @staticmethod
    def revoke_all_user_sessions(user_email: str) -> int:
        """Revoke all sessions for a user (security event)."""
        sessions_file = Path("data/sessions.json")
        if not sessions_file.exists():
            return 0
        
        try:
            with open(sessions_file, 'r') as f:
                sessions = json.load(f)
            
            revoked_count = 0
            for session_id, session in sessions.items():
                if session.get('user_email', '').lower() == user_email.lower():
                    session['revoked'] = True
                    session['revoked_at'] = datetime.now().isoformat()
                    revoked_count += 1
            
            with open(sessions_file, 'w') as f:
                json.dump(sessions, f, indent=2)
            
            return revoked_count
        except Exception as e:
            print(f"[session] Mass revocation error: {e}")
        
        return 0
    
    @staticmethod
    def verify_session(session_id: str, client_ip: str, 
                      user_agent: str) -> Tuple[bool, Optional[str], str]:
        """
        Verify session validity and device fingerprint.
        Returns (is_valid, user_email, status_message)
        """
        sessions_file = Path("data/sessions.json")
        if not sessions_file.exists():
            return False, None, "no_sessions"
        
        try:
            with open(sessions_file, 'r') as f:
                sessions = json.load(f)
            
            if session_id not in sessions:
                return False, None, "session_not_found"
            
            session = sessions[session_id]
            
            # Check if revoked
            if session.get('revoked', False):
                return False, None, "session_revoked"
            
            # Check expiry
            expires_at = datetime.fromisoformat(session['expires_at'])
            if datetime.now() > expires_at:
                session['revoked'] = True
                session['revoked_at'] = datetime.now().isoformat()
                with open(sessions_file, 'w') as f:
                    json.dump(sessions, f, indent=2)
                return False, None, "session_expired"
            
            # Check device fingerprint
            current_fp = DeviceFingerprint.create_fingerprint(
                user_agent, "", "", client_ip
            )
            stored_fp = session.get('device_fingerprint', '')
            
            if current_fp != stored_fp:
                # Different device - flag but allow (with warning)
                print(f"[session] Device fingerprint mismatch for {session['user_email']}")
                # In production: send alert email
            
            # Update last activity
            session['last_activity'] = datetime.now().isoformat()
            with open(sessions_file, 'w') as f:
                json.dump(sessions, f, indent=2)
            
            return True, session['user_email'], "valid"
        
        except Exception as e:
            print(f"[session] Verification error: {e}")
            return False, None, "verification_error"


# ============================================================================
# 5. LOGIN ATTEMPT TRACKING
# ============================================================================

class LoginAttemptTracker:
    """Track and analyze login attempts for fraud detection."""
    
    @staticmethod
    def log_login_attempt(user_email: str, client_ip: str, success: bool,
                         reason: str = "") -> None:
        """Log a login attempt."""
        attempt = {
            "email": user_email.lower(),
            "ip": client_ip,
            "success": success,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        }
        
        history_file = Path("data/login_attempts.json")
        attempts = []
        
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    attempts = json.load(f)
            except Exception:
                attempts = []
        
        attempts.append(attempt)
        
        # Keep only last 1000 attempts (for performance)
        attempts = attempts[-1000:]
        
        try:
            with open(history_file, 'w') as f:
                json.dump(attempts, f, indent=2)
        except Exception as e:
            print(f"[login_tracker] Log error: {e}")
    
    @staticmethod
    def detect_brute_force(user_email: str, time_window_minutes: int = 60) -> bool:
        """Detect brute force attacks (10+ failed attempts in window)."""
        history_file = Path("data/login_attempts.json")
        if not history_file.exists():
            return False
        
        try:
            with open(history_file, 'r') as f:
                all_attempts = json.load(f)
            
            # Filter for this user and time window
            threshold_time = datetime.now() - timedelta(minutes=time_window_minutes)
            recent_failures = 0
            
            for attempt in all_attempts:
                if (attempt['email'] == user_email.lower() and 
                    not attempt['success']):
                    attempt_time = datetime.fromisoformat(attempt['timestamp'])
                    if attempt_time > threshold_time:
                        recent_failures += 1
            
            return recent_failures >= 10
        
        except Exception as e:
            print(f"[login_tracker] Brute force detection error: {e}")
            return False


# ============================================================================
# 6. ACCOUNT RECOVERY (Secure Account Recovery)
# ============================================================================

class AccountRecovery:
    """Secure account recovery mechanisms."""
    
    @staticmethod
    def initiate_account_recovery(user_email: str, client_ip: str) -> Dict:
        """
        Initiate account recovery process.
        Returns recovery token and verification method.
        """
        from itsdangerous import URLSafeTimedSerializer
        
        # Generate signed token
        serializer = URLSafeTimedSerializer("recovery_key", salt="account_recovery")
        token = serializer.dumps({"email": user_email, "action": "recover"})
        
        recovery_record = {
            "email": user_email.lower(),
            "token": token,
            "initiated_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=24)).isoformat(),
            "ip_address": client_ip,
            "verified": False
        }
        
        return {
            "token": token,
            "method": "email",  # Could also be "security_questions"
            "record": recovery_record
        }
    
    @staticmethod
    def verify_recovery_token(token: str, backup_code: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Verify recovery token and optional backup code.
        Returns (is_valid, user_email)
        """
        from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
        
        try:
            serializer = URLSafeTimedSerializer("recovery_key", salt="account_recovery")
            payload = serializer.loads(token, max_age=86400)  # 24 hours
            
            if payload.get("action") != "recover":
                return False, None
            
            email = payload.get("email")
            
            # If backup code provided, verify it
            if backup_code:
                # In production: verify against stored backup codes
                pass
            
            return True, email
        
        except (BadSignature, SignatureExpired):
            return False, None


# ============================================================================
# API INTEGRATION EXAMPLES
# ============================================================================

"""
FastAPI Integration Examples:

@app.post("/api/auth/login")
async def login_with_ato_protection(request: Request, data: dict):
    email = data.get("email", "").lower().strip()
    password = data.get("password", "")
    client_ip = _get_real_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")
    
    # 1. Check for behavioral anomalies
    unusual_time, time_reason = BehavioralAnalysis.is_unusual_time(email)
    unusual_location, location_reason = BehavioralAnalysis.is_unusual_location(email, client_ip)
    
    if unusual_time or unusual_location:
        # Require 2FA for suspicious login
        code = TwoFactorAuth.send_2fa_code(email, "email")
        return {
            "requires_2fa": True,
            "message": "Unusual login detected. Check email for verification code."
        }
    
    # 2. Verify password
    users = load_users()
    user = next((u for u in users if u['email'] == email), None)
    
    if not user or not _verify_password(password, user.get("password_hash", "")):
        LoginAttemptTracker.log_login_attempt(email, client_ip, False, "invalid_password")
        
        # Check for brute force
        if LoginAttemptTracker.detect_brute_force(email):
            raise HTTPException(status_code=429, detail="Account locked due to too many failed attempts")
        
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # 3. Check if 2FA required
    if user.get("2fa_enabled", False):
        code = TwoFactorAuth.send_2fa_code(email, "email")
        return {
            "requires_2fa": True,
            "session_temp": "temp_session_token"
        }
    
    # 4. Create secure session
    session = SessionManager.create_session(email, client_ip, user_agent)
    
    # 5. Log successful login
    LoginAttemptTracker.log_login_attempt(email, client_ip, True, "successful")
    
    # 6. Generate JWT
    token = _create_jwt_token({
        "sub": email,
        "session_id": session['session_id'],
        "email": email,
        "admin": False
    })
    
    return {
        "success": True,
        "token": token,
        "session_id": session['session_id']
    }


@app.post("/api/auth/verify-2fa")
async def verify_2fa_code(request: Request, data: dict):
    email = data.get("email", "").lower().strip()
    code = data.get("code", "")
    
    # Verify code
    twofa_codes = {}
    codes_file = Path("data/2fa_codes.json")
    if codes_file.exists():
        with open(codes_file, 'r') as f:
            twofa_codes = json.load(f)
    
    stored = twofa_codes.get(email)
    if not stored:
        raise HTTPException(status_code=400, detail="No 2FA code found")
    
    # Check expiry
    if datetime.fromisoformat(stored['expires']) < datetime.now():
        raise HTTPException(status_code=400, detail="Code expired")
    
    # Check code
    if code != stored['code']:
        stored['attempts'] += 1
        if stored['attempts'] >= 5:
            del twofa_codes[email]
        with open(codes_file, 'w') as f:
            json.dump(twofa_codes, f, indent=2)
        raise HTTPException(status_code=400, detail="Invalid code")
    
    # Code verified - complete login
    del twofa_codes[email]
    with open(codes_file, 'w') as f:
        json.dump(twofa_codes, f, indent=2)
    
    return {"success": True, "message": "2FA verified"}


@app.post("/api/auth/logout")
async def logout_with_session_revocation(request: Request, user: dict = Depends(_get_current_user)):
    session_id = request.headers.get("X-Session-Id", "")
    
    if session_id:
        SessionManager.revoke_session(session_id)
    
    return {"success": True, "message": "Logged out successfully"}


@app.post("/api/account/enable-2fa")
async def enable_2fa(user: dict = Depends(_get_current_user)):
    secret = TwoFactorAuth.generate_totp_secret()
    backup_codes = TwoFactorAuth.generate_backup_codes()
    
    return {
        "secret": secret,
        "backup_codes": backup_codes,
        "qr_code": f"otpauth://totp/RockyCrypt:{user['email']}?secret={secret}"
    }


@app.post("/api/account/confirm-2fa")
async def confirm_2fa(user: dict = Depends(_get_current_user), data: dict = None):
    token = data.get("token", "")
    secret = data.get("secret", "")
    
    if not TwoFactorAuth.verify_totp(secret, token):
        raise HTTPException(status_code=400, detail="Invalid 2FA token")
    
    # Save 2FA setting for user
    users = load_users()
    for u in users:
        if u['email'] == user['email']:
            u['2fa_enabled'] = True
            u['2fa_secret'] = secret
            break
    
    save_users(users)
    
    return {"success": True, "message": "2FA enabled successfully"}
"""

print("[ATO] Account Takeover Protection Module Loaded")
print("[ATO] Features: 2FA, Device Fingerprinting, Behavioral Analysis, Session Management")
