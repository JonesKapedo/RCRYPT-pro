"""
RockyCrypt Email Security Module
Comprehensive email protection against compromise and spoofing
"""

import smtplib
import dkim
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from pathlib import Path
import json
import hashlib
from typing import Tuple, Dict, Optional, List

# ============================================================================
# 1. EMAIL AUTHENTICATION SETUP (SPF, DKIM, DMARC)
# ============================================================================

class EmailAuthentication:
    """Email authentication configuration and validation."""
    
    @staticmethod
    def generate_dkim_key_pair() -> Tuple[str, str]:
        """
        Generate DKIM key pair for email signing.
        Private key for server, public key for DNS records.
        """
        import os
        
        # Generate 2048-bit RSA key
        os.system("openssl genrsa -out dkim_private.pem 2048")
        os.system("openssl rsa -in dkim_private.pem -pubout -out dkim_public.pem")
        
        with open("dkim_private.pem", "r") as f:
            private_key = f.read()
        
        with open("dkim_public.pem", "r") as f:
            public_key = f.read()
        
        return private_key, public_key
    
    @staticmethod
    def get_spf_record() -> str:
        """
        Generate SPF record for domain.
        Add to DNS TXT records.
        """
        return "v=spf1 ip4:YOUR_SERVER_IP include:sendgrid.net ~all"
    
    @staticmethod
    def get_dmarc_record() -> str:
        """
        Generate DMARC record for domain.
        Add to DNS TXT records (_dmarc.yourdomain.com).
        """
        return (
            "v=DMARC1; p=quarantine; "
            "rua=mailto:dmarc@yourdomain.com; "
            "ruf=mailto:forensics@yourdomain.com; "
            "fo=1; aspf=s; adkim=s"
        )
    
    @staticmethod
    def validate_email_headers(message_str: str) -> Dict[str, bool]:
        """Validate email headers for spoofing."""
        headers = {
            "has_from": False,
            "has_to": False,
            "has_subject": False,
            "has_date": False,
            "has_message_id": False,
        }
        
        for line in message_str.split('\n')[:20]:
            if line.startswith("From:"):
                headers["has_from"] = True
            elif line.startswith("To:"):
                headers["has_to"] = True
            elif line.startswith("Subject:"):
                headers["has_subject"] = True
            elif line.startswith("Date:"):
                headers["has_date"] = True
            elif line.startswith("Message-ID:"):
                headers["has_message_id"] = True
        
        return headers


# ============================================================================
# 2. SECURE EMAIL SENDING (Encrypted & Authenticated)
# ============================================================================

class SecureEmailSender:
    """Send emails securely with authentication and encryption."""
    
    def __init__(self, smtp_host: str, smtp_port: int, username: str, password: str,
                 dkim_private_key: Optional[str] = None):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.dkim_private_key = dkim_private_key
    
    def _sign_message_with_dkim(self, message_str: str, domain: str,
                               selector: str = "default") -> str:
        """Sign email with DKIM for authentication."""
        if not self.dkim_private_key:
            return message_str
        
        try:
            sig = dkim.sign(
                message_str.encode(),
                selector.encode(),
                domain.encode(),
                self.dkim_private_key.encode()
            )
            return sig.decode() + message_str
        except Exception as e:
            print(f"[email] DKIM signing failed: {e}")
            return message_str
    
    def send_secure_email(self, to_email: str, subject: str, html_body: str,
                         plain_body: str = "", from_name: str = "RockyCrypt",
                         domain: str = "yourdomain.com") -> Tuple[bool, str]:
        """
        Send secure email with:
        - DKIM signing
        - TLS encryption
        - Unsubscribe headers
        - Audit logging
        """
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{from_name} <noreply@{domain}>"
            msg['To'] = to_email
            msg['Subject'] = subject
            msg['Message-ID'] = f"<{self._generate_message_id()}@{domain}>"
            msg['Date'] = self._format_email_date()
            
            # Add unsubscribe header (CAN-SPAM compliance)
            msg['List-Unsubscribe'] = self._get_unsubscribe_header(to_email, domain)
            
            # Add body parts
            if plain_body:
                msg.attach(MIMEText(plain_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            # Sign with DKIM
            message_str = msg.as_string()
            signed_message = self._sign_message_with_dkim(message_str, domain)
            
            # Send via SMTP with TLS
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()  # Encrypt connection
                server.login(self.username, self.password)
                server.sendmail(msg['From'], to_email, signed_message)
            
            # Log successful send
            self._log_email_send(to_email, subject, True, "")
            
            return True, "Email sent successfully"
        
        except Exception as e:
            error_msg = str(e)
            self._log_email_send(to_email, subject, False, error_msg)
            return False, error_msg
    
    @staticmethod
    def _generate_message_id() -> str:
        """Generate unique Message-ID header."""
        import secrets
        timestamp = int(datetime.now().timestamp() * 1000)
        random = secrets.token_hex(8)
        return f"{timestamp}.{random}"
    
    @staticmethod
    def _format_email_date() -> str:
        """Format date header for email."""
        from email.utils import formatdate
        return formatdate(localtime=True)
    
    @staticmethod
    def _get_unsubscribe_header(email: str, domain: str) -> str:
        """Generate List-Unsubscribe header (CAN-SPAM)."""
        from itsdangerous import URLSafeTimedSerializer
        
        serializer = URLSafeTimedSerializer("unsubscribe_key", salt="email_unsubscribe")
        token = serializer.dumps(email)
        
        return f"<https://{domain}/api/unsubscribe?token={token}>"
    
    @staticmethod
    def _log_email_send(to_email: str, subject: str, success: bool, error: str) -> None:
        """Log email send for audit trail."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "recipient": to_email,
            "subject": subject,
            "success": success,
            "error": error
        }
        
        log_file = Path("data/email_audit.json")
        logs = []
        
        if log_file.exists():
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    logs = json.load(f)
            except Exception:
                logs = []
        
        logs.append(log_entry)
        
        # Keep last 10000 emails for audit
        logs = logs[-10000:]
        
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(logs, f, indent=2)
        except Exception as e:
            print(f"[email] Failed to log send: {e}")


# ============================================================================
# 3. EMAIL VERIFICATION & VALIDATION
# ============================================================================

class EmailVerification:
    """Email verification and validation."""
    
    @staticmethod
    def verify_email_format(email: str) -> Tuple[bool, str]:
        """Validate email format."""
        import re
        
        # RFC 5322 basic validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(pattern, email):
            return False, "Invalid email format"
        
        return True, "Valid format"
    
    @staticmethod
    def check_disposable_email(email: str) -> Tuple[bool, str]:
        """
        Check if email is from disposable email service.
        Prevent registrations from temp email providers.
        """
        disposable_domains = {
            "tempmail.com", "throwaway.email", "guerrillamail.com",
            "mailinator.com", "10minutemail.com", "maildrop.cc",
            "sharklasers.com", "spam4.me", "traplist.com"
        }
        
        domain = email.split("@")[1].lower()
        
        if domain in disposable_domains:
            return True, "Disposable email detected"
        
        return False, "Valid email provider"
    
    @staticmethod
    def send_verification_email(to_email: str, sender: SecureEmailSender) -> Tuple[bool, str, str]:
        """Send email verification link."""
        from itsdangerous import URLSafeTimedSerializer
        
        # Generate signed token
        serializer = URLSafeTimedSerializer("verification_key", salt="email_verification")
        token = serializer.dumps(to_email)
        
        # Create email
        verification_link = f"https://yourdomain.com/verify-email?token={token}"
        
        html_body = f"""
        <html>
            <body style='font-family: Arial, sans-serif; color: #333;'>
                <h2>Verify Your Email Address</h2>
                <p>Click the link below to verify your email:</p>
                <p><a href="{verification_link}" style="
                    background-color: #00D062;
                    color: white;
                    padding: 10px 20px;
                    text-decoration: none;
                    border-radius: 5px;
                    display: inline-block;
                ">Verify Email</a></p>
                <p>This link expires in 24 hours.</p>
                <p>If you didn't request this, ignore this email.</p>
            </body>
        </html>
        """
        
        plain_body = f"""
        Verify Your Email Address
        
        Click the link below to verify your email:
        {verification_link}
        
        This link expires in 24 hours.
        """
        
        success, message = sender.send_secure_email(
            to_email,
            "Verify Your RockyCrypt Email",
            html_body,
            plain_body
        )
        
        return success, message, token
    
    @staticmethod
    def verify_email_token(token: str, max_age_hours: int = 24) -> Tuple[bool, Optional[str]]:
        """Verify email verification token."""
        from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
        
        try:
            serializer = URLSafeTimedSerializer("verification_key", salt="email_verification")
            email = serializer.loads(token, max_age=max_age_hours * 3600)
            return True, email
        except SignatureExpired:
            return False, "Verification link expired"
        except BadSignature:
            return False, "Invalid verification link"


# ============================================================================
# 4. EMAIL SECURITY MONITORING
# ============================================================================

class EmailSecurityMonitor:
    """Monitor email security and detect compromises."""
    
    @staticmethod
    def detect_email_spoofing(from_header: str, sender_email: str) -> Tuple[bool, str]:
        """Detect if email is spoofed."""
        
        # Extract email from From header
        import re
        match = re.search(r'<(.+?)>', from_header)
        from_email = match.group(1) if match else from_header
        
        # Check if matches sender
        if from_email.lower() != sender_email.lower():
            return True, "Potential spoofing detected"
        
        return False, "Email authenticated"
    
    @staticmethod
    def check_phishing_indicators(email_body: str) -> Dict[str, bool]:
        """Check email body for phishing indicators."""
        
        indicators = {
            "has_urgent_language": any(
                word in email_body.lower()
                for word in ["urgent", "act now", "verify account", "confirm identity"]
            ),
            "has_suspicious_links": any(
                pattern in email_body
                for pattern in ["http://", "click here", "suspicious"]
            ),
            "has_attachment_request": "attachment" in email_body.lower(),
            "has_credential_request": any(
                word in email_body.lower()
                for word in ["password", "username", "pin", "credit card"]
            ),
        }
        
        return indicators
    
    @staticmethod
    def log_email_security_event(event_type: str, email: str, details: Dict) -> None:
        """Log email security events for audit."""
        
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "email": email,
            "details": details
        }
        
        log_file = Path("data/email_security_events.json")
        events = []
        
        if log_file.exists():
            try:
                with open(log_file, 'r') as f:
                    events = json.load(f)
            except Exception:
                events = []
        
        events.append(event)
        events = events[-5000:]  # Keep last 5000 events
        
        try:
            with open(log_file, 'w') as f:
                json.dump(events, f, indent=2)
        except Exception as e:
            print(f"[email_security] Log error: {e}")


# ============================================================================
# 5. BULK EMAIL SAFETY
# ============================================================================

class BulkEmailSafety:
    """Safety checks for bulk email sending."""
    
    @staticmethod
    def check_recipient_list(recipients: List[str]) -> Dict[str, any]:
        """Validate recipient list for bulk send."""
        
        analysis = {
            "total_recipients": len(recipients),
            "invalid_emails": 0,
            "disposable_emails": 0,
            "duplicate_emails": 0,
            "warnings": []
        }
        
        seen = set()
        valid_recipients = []
        
        for email in recipients:
            # Check format
            valid, _ = EmailVerification.verify_email_format(email)
            if not valid:
                analysis["invalid_emails"] += 1
                continue
            
            # Check for disposable
            disposable, _ = EmailVerification.check_disposable_email(email)
            if disposable:
                analysis["disposable_emails"] += 1
                continue
            
            # Check duplicates
            if email in seen:
                analysis["duplicate_emails"] += 1
                continue
            
            seen.add(email)
            valid_recipients.append(email)
        
        analysis["valid_recipients"] = len(valid_recipients)
        
        # Warn if too many invalid
        if analysis["invalid_emails"] > len(recipients) * 0.1:
            analysis["warnings"].append("More than 10% invalid emails detected")
        
        return analysis
    
    @staticmethod
    def should_send_bulk_email(recipients_analysis: Dict) -> Tuple[bool, str]:
        """Determine if bulk email should be sent."""
        
        if recipients_analysis["valid_recipients"] == 0:
            return False, "No valid recipients"
        
        if recipients_analysis["invalid_emails"] > recipients_analysis["valid_recipients"]:
            return False, "Too many invalid email addresses"
        
        if recipients_analysis["warnings"]:
            return False, f"Warnings: {', '.join(recipients_analysis['warnings'])}"
        
        return True, "Ready to send"


# ============================================================================
# API INTEGRATION EXAMPLES
# ============================================================================

"""
FastAPI Integration:

@app.post("/api/auth/register")
async def register_with_email_verification(request: Request, data: dict):
    email = data.get("email", "").lower().strip()
    
    # Validate email format
    valid_format, msg = EmailVerification.verify_email_format(email)
    if not valid_format:
        raise HTTPException(status_code=400, detail=msg)
    
    # Check for disposable email
    is_disposable, msg = EmailVerification.check_disposable_email(email)
    if is_disposable:
        raise HTTPException(status_code=400, detail="Disposable email addresses not allowed")
    
    # Create user (unverified)
    user = {
        "email": email,
        "password_hash": _hash_password(data.get("password", "")),
        "verified": False,
        "created_at": datetime.now().isoformat()
    }
    
    # Send verification email
    sender = SecureEmailSender(
        os.environ.get("SMTP_HOST"),
        int(os.environ.get("SMTP_PORT")),
        os.environ.get("SMTP_USER"),
        os.environ.get("SMTP_PASS")
    )
    
    success, message, token = EmailVerification.send_verification_email(email, sender)
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to send verification email")
    
    return {
        "success": True,
        "message": "Registration successful. Check email for verification link.",
        "email": email
    }


@app.get("/api/verify-email")
async def verify_email_endpoint(token: str):
    valid, email_or_error = EmailVerification.verify_email_token(token)
    
    if not valid:
        raise HTTPException(status_code=400, detail=email_or_error)
    
    # Mark user as verified
    users = load_users()
    for user in users:
        if user['email'].lower() == email_or_error.lower():
            user['verified'] = True
            break
    
    save_users(users)
    
    return {
        "success": True,
        "message": "Email verified successfully! You can now log in."
    }
"""

print("[EMAIL] Email Security Module Loaded")
print("[EMAIL] Features: DKIM/SPF/DMARC, Email Verification, Phishing Detection")
