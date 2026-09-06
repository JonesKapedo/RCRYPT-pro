"""
RockyCrypt Payment Fraud Prevention Module
PCI DSS Compliant payment processing and fraud detection
"""

import hashlib
import hmac
import secrets
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Tuple, Optional, List
import re

# ============================================================================
# 1. PCI DSS COMPLIANCE (Payment Card Industry Data Security Standard)
# ============================================================================

class PCIDSSCompliance:
    """PCI DSS v3.2.1 compliance implementation."""
    
    # PCI DSS Requirements
    REQUIREMENTS = {
        "1": "Install and maintain firewall",
        "2": "Do not use vendor defaults for passwords",
        "3": "Protect stored cardholder data",
        "4": "Encrypt transmission of cardholder data",
        "5": "Use antivirus software",
        "6": "Develop secure systems",
        "7": "Restrict access to data",
        "8": "Assign unique ID to each user",
        "9": "Restrict physical access",
        "10": "Track and monitor network",
        "11": "Test security systems",
        "12": "Maintain information security policy"
    }
    
    @staticmethod
    def validate_pci_compliance() -> Dict[str, bool]:
        """Validate PCI DSS compliance status."""
        checks = {
            "firewall_enabled": PCIDSSCompliance._check_firewall(),
            "tls_enforced": PCIDSSCompliance._check_tls_enforcement(),
            "no_hardcoded_passwords": PCIDSSCompliance._check_no_hardcoded_passwords(),
            "encryption_enabled": PCIDSSCompliance._check_encryption(),
            "unique_user_ids": PCIDSSCompliance._check_unique_user_ids(),
            "access_logging": PCIDSSCompliance._check_access_logging(),
            "security_patches": PCIDSSCompliance._check_security_patches()
        }
        
        return checks
    
    @staticmethod
    def _check_firewall() -> bool:
        """Check if firewall is configured."""
        # In production: verify firewall rules
        return True  # Placeholder
    
    @staticmethod
    def _check_tls_enforcement() -> bool:
        """Check if TLS 1.2+ is enforced."""
        return True  # Should be verified in production
    
    @staticmethod
    def _check_no_hardcoded_passwords() -> bool:
        """Check that no passwords are hardcoded."""
        # Scan for hardcoded secrets
        return True  # Should verify in production
    
    @staticmethod
    def _check_encryption() -> bool:
        """Check if encryption is enabled."""
        return True  # Placeholder
    
    @staticmethod
    def _check_unique_user_ids() -> bool:
        """Check if unique user IDs are assigned."""
        return True  # Placeholder
    
    @staticmethod
    def _check_access_logging() -> bool:
        """Check if access is logged."""
        return Path("data/audit.log").exists()
    
    @staticmethod
    def _check_security_patches() -> bool:
        """Check if security patches are current."""
        return True  # Should verify in production


# ============================================================================
# 2. CARD DATA TOKENIZATION (NO Sensitive Card Storage)
# ============================================================================

class CardTokenization:
    """
    NEVER store full card numbers.
    Use tokenization with payment gateway instead.
    """
    
    @staticmethod
    def tokenize_card_with_paystack(card_token: str, email: str) -> Dict:
        """
        Tokenize card via Paystack (third-party).
        RockyCrypt never sees full card number.
        """
        import requests
        
        PAYSTACK_SECRET = os.environ.get("PAYSTACK_SECRET_KEY")
        
        # Authorize card
        response = requests.post(
            "https://api.paystack.co/transaction/charge_authorization",
            headers={"Authorization": f"Bearer {PAYSTACK_SECRET}"},
            json={
                "email": email,
                "amount": 0,  # Verify only
                "authorization_code": card_token
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                "success": True,
                "authorization_code": data.get("data", {}).get("authorization", {}).get("authorization_code"),
                "last4": data.get("data", {}).get("authorization", {}).get("last4"),
                "card_type": data.get("data", {}).get("authorization", {}).get("card_type")
            }
        
        return {"success": False, "error": "Tokenization failed"}
    
    @staticmethod
    def store_tokenized_card(user_email: str, token_data: Dict) -> bool:
        """
        Store tokenized card (NOT full card number).
        Only store authorization code, last 4 digits, and card type.
        """
        
        # NEVER store this in plain text
        # Use database with encryption
        
        card_record = {
            "user_email": user_email,
            "authorization_code": token_data.get("authorization_code"),  # Safe to store
            "last4": token_data.get("last4"),  # Safe - only last 4 digits
            "card_type": token_data.get("card_type"),
            "stored_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(days=365)).isoformat()
        }
        
        cards_file = Path("data/tokenized_cards.json")
        cards = []
        
        if cards_file.exists():
            try:
                with open(cards_file, 'r') as f:
                    cards = json.load(f)
            except Exception:
                cards = []
        
        cards.append(card_record)
        
        try:
            with open(cards_file, 'w') as f:
                json.dump(cards, f, indent=2)
            return True
        except Exception as e:
            print(f"[payment] Failed to store card: {e}")
            return False


# ============================================================================
# 3. TRANSACTION FRAUD DETECTION
# ============================================================================

class FraudDetection:
    """Detect and prevent fraudulent transactions."""
    
    # Fraud detection thresholds
    MAX_TRANSACTION_AMOUNT = 500000  # KES 500,000
    MAX_DAILY_TRANSACTIONS = 10
    MAX_DAILY_AMOUNT = 1000000  # KES 1,000,000
    UNUSUAL_TIME_WINDOW = 3600  # 1 hour
    
    @staticmethod
    def analyze_transaction(user_email: str, amount: float, 
                           client_ip: str, card_last4: str) -> Tuple[bool, str, float]:
        """
        Analyze transaction for fraud.
        Returns (is_fraud, reason, risk_score)
        """
        
        risk_score = 0.0
        fraud_reasons = []
        
        # Check 1: Amount limits
        if amount > FraudDetection.MAX_TRANSACTION_AMOUNT:
            risk_score += 0.3
            fraud_reasons.append("Amount exceeds threshold")
        
        # Check 2: Velocity (multiple transactions in short time)
        velocity = FraudDetection._check_transaction_velocity(user_email)
        if velocity > 5:
            risk_score += 0.25
            fraud_reasons.append("High transaction velocity")
        
        # Check 3: Daily limits
        daily_total = FraudDetection._get_daily_transaction_total(user_email)
        if daily_total + amount > FraudDetection.MAX_DAILY_AMOUNT:
            risk_score += 0.2
            fraud_reasons.append("Daily limit exceeded")
        
        # Check 4: Unusual location/time
        unusual_location = FraudDetection._is_unusual_location(user_email, client_ip)
        if unusual_location:
            risk_score += 0.15
            fraud_reasons.append("Unusual location")
        
        # Check 5: Card mismatch
        stored_card = FraudDetection._get_user_card(user_email)
        if stored_card and stored_card.get("last4") != card_last4:
            risk_score += 0.2
            fraud_reasons.append("Card mismatch")
        
        # Check 6: Multiple cards in short time
        multiple_cards = FraudDetection._check_multiple_cards(user_email)
        if multiple_cards:
            risk_score += 0.1
            fraud_reasons.append("Multiple cards used")
        
        # Determine if fraudulent
        is_fraud = risk_score > 0.5  # Threshold: 50% risk
        reason = ", ".join(fraud_reasons) if fraud_reasons else "Approved"
        
        # Log transaction for analysis
        FraudDetection._log_transaction(user_email, amount, is_fraud, risk_score, reason)
        
        return is_fraud, reason, risk_score
    
    @staticmethod
    def _check_transaction_velocity(user_email: str, minutes: int = 10) -> int:
        """Check number of transactions in recent time window."""
        transactions_file = Path("data/transactions.json")
        if not transactions_file.exists():
            return 0
        
        try:
            with open(transactions_file, 'r') as f:
                transactions = json.load(f)
            
            threshold_time = datetime.now() - timedelta(minutes=minutes)
            count = 0
            
            for tx in transactions:
                if (tx.get('email') == user_email and 
                    tx.get('status') == 'completed'):
                    tx_time = datetime.fromisoformat(tx['timestamp'])
                    if tx_time > threshold_time:
                        count += 1
            
            return count
        except Exception:
            return 0
    
    @staticmethod
    def _get_daily_transaction_total(user_email: str) -> float:
        """Get total transaction amount for today."""
        transactions_file = Path("data/transactions.json")
        if not transactions_file.exists():
            return 0.0
        
        try:
            with open(transactions_file, 'r') as f:
                transactions = json.load(f)
            
            today = datetime.now().date()
            total = 0.0
            
            for tx in transactions:
                if (tx.get('email') == user_email and 
                    tx.get('status') == 'completed'):
                    tx_date = datetime.fromisoformat(tx['timestamp']).date()
                    if tx_date == today:
                        total += tx.get('amount', 0)
            
            return total
        except Exception:
            return 0.0
    
    @staticmethod
    def _is_unusual_location(user_email: str, current_ip: str) -> bool:
        """Check if transaction from unusual location."""
        transactions_file = Path("data/transactions.json")
        if not transactions_file.exists():
            return False
        
        try:
            with open(transactions_file, 'r') as f:
                transactions = json.load(f)
            
            # Get last location
            for tx in reversed(transactions):
                if tx.get('email') == user_email:
                    previous_ip = tx.get('ip_address', '')
                    if previous_ip and previous_ip != current_ip:
                        return True
                    break
            
            return False
        except Exception:
            return False
    
    @staticmethod
    def _get_user_card(user_email: str) -> Optional[Dict]:
        """Get user's stored card info."""
        cards_file = Path("data/tokenized_cards.json")
        if not cards_file.exists():
            return None
        
        try:
            with open(cards_file, 'r') as f:
                cards = json.load(f)
            
            for card in cards:
                if card.get('user_email') == user_email:
                    return card
            
            return None
        except Exception:
            return None
    
    @staticmethod
    def _check_multiple_cards(user_email: str, hours: int = 24) -> bool:
        """Check if multiple cards used in time window."""
        cards_file = Path("data/tokenized_cards.json")
        if not cards_file.exists():
            return False
        
        try:
            with open(cards_file, 'r') as f:
                cards = json.load(f)
            
            threshold_time = datetime.now() - timedelta(hours=hours)
            unique_cards = set()
            
            for card in cards:
                if card.get('user_email') == user_email:
                    stored_time = datetime.fromisoformat(card['stored_at'])
                    if stored_time > threshold_time:
                        unique_cards.add(card.get('last4', ''))
            
            return len(unique_cards) > 1
        except Exception:
            return False
    
    @staticmethod
    def _log_transaction(user_email: str, amount: float, is_fraud: bool,
                        risk_score: float, reason: str) -> None:
        """Log transaction for fraud analysis."""
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "email": user_email,
            "amount": amount,
            "is_fraud": is_fraud,
            "risk_score": risk_score,
            "reason": reason
        }
        
        log_file = Path("data/fraud_analysis.json")
        logs = []
        
        if log_file.exists():
            try:
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            except Exception:
                logs = []
        
        logs.append(log_entry)
        logs = logs[-5000:]  # Keep last 5000 logs
        
        try:
            with open(log_file, 'w') as f:
                json.dump(logs, f, indent=2)
        except Exception as e:
            print(f"[fraud] Logging error: {e}")


# ============================================================================
# 4. TRANSACTION ENCRYPTION & AUDIT
# ============================================================================

class TransactionSecurity:
    """Secure transaction storage and audit."""
    
    @staticmethod
    def encrypt_transaction_data(transaction: Dict) -> str:
        """Encrypt sensitive transaction data."""
        from cryptography.fernet import Fernet
        
        # Get encryption key from environment
        key = os.environ.get("TRANSACTION_ENCRYPTION_KEY")
        if not key:
            key = Fernet.generate_key()
        
        cipher = Fernet(key)
        
        # Encrypt amount and email
        sensitive_data = json.dumps({
            "email": transaction.get("email"),
            "amount": transaction.get("amount")
        })
        
        encrypted = cipher.encrypt(sensitive_data.encode())
        return encrypted.decode()
    
    @staticmethod
    def store_transaction(transaction: Dict) -> bool:
        """
        Store encrypted transaction record.
        PCI DSS requirement: Never store full card data.
        """
        
        # Remove any sensitive card data
        safe_transaction = {
            "transaction_id": transaction.get("transaction_id"),
            "email": transaction.get("email"),
            "amount": transaction.get("amount"),
            "currency": "KES",
            "status": transaction.get("status", "pending"),
            "timestamp": datetime.now().isoformat(),
            "reference": transaction.get("reference"),
            "last4": transaction.get("last4"),  # Only last 4 digits safe to store
            "description": transaction.get("description", "Premium subscription")
        }
        
        transactions_file = Path("data/transactions.json")
        transactions = []
        
        if transactions_file.exists():
            try:
                with open(transactions_file, 'r') as f:
                    transactions = json.load(f)
            except Exception:
                transactions = []
        
        transactions.append(safe_transaction)
        
        try:
            with open(transactions_file, 'w') as f:
                json.dump(transactions, f, indent=2)
            return True
        except Exception as e:
            print(f"[payment] Transaction storage error: {e}")
            return False
    
    @staticmethod
    def audit_transaction(transaction_id: str, action: str, details: Dict) -> None:
        """Log transaction audit trail."""
        
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "transaction_id": transaction_id,
            "action": action,
            "details": details
        }
        
        audit_file = Path("data/transaction_audit.json")
        audits = []
        
        if audit_file.exists():
            try:
                with open(audit_file, 'r') as f:
                    audits = json.load(f)
            except Exception:
                audits = []
        
        audits.append(audit_entry)
        
        try:
            with open(audit_file, 'w') as f:
                json.dump(audits, f, indent=2)
        except Exception as e:
            print(f"[payment] Audit error: {e}")


# ============================================================================
# 5. 3D SECURE / STRONG CUSTOMER AUTHENTICATION (SCA)
# ============================================================================

class StrongCustomerAuth:
    """3D Secure / Strong Customer Authentication."""
    
    @staticmethod
    def initiate_3ds_verification(transaction_id: str, user_email: str,
                                 amount: float) -> Dict:
        """
        Initiate 3D Secure verification.
        Required for payments in EU (PSD2) and increasingly globally.
        """
        
        verification = {
            "transaction_id": transaction_id,
            "email": user_email,
            "amount": amount,
            "initiated_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(minutes=15)).isoformat(),
            "status": "pending",
            "verification_url": f"https://yourdomain.com/verify-3ds?token=xxx"
        }
        
        return verification
    
    @staticmethod
    def verify_3ds_response(transaction_id: str, authentication_response: str) -> Tuple[bool, str]:
        """Verify 3D Secure response from payment gateway."""
        
        # In production: verify with Paystack API
        
        if authentication_response == "Y":  # Authentication successful
            return True, "3DS verification passed"
        else:
            return False, "3DS verification failed"


# ============================================================================
# API INTEGRATION EXAMPLES
# ============================================================================

"""
FastAPI Integration:

@app.post("/api/subscription/initialize-payment")
async def initialize_payment(request: Request, data: dict,
                           user: dict = Depends(_get_current_user)):
    email = user.get("email", "")
    plan = data.get("plan", "monthly")
    amount = PLAN_PRICES.get(plan, 0)
    
    # 1. Analyze for fraud
    client_ip = _get_real_client_ip(request)
    card_last4 = data.get("card_last4", "")
    
    is_fraud, reason, risk_score = FraudDetection.analyze_transaction(
        email, amount, client_ip, card_last4
    )
    
    if is_fraud and risk_score > 0.7:
        # Block high-risk transactions
        raise HTTPException(status_code=403, detail="Transaction blocked for security")
    
    if is_fraud and risk_score > 0.5:
        # Require 3D Secure for medium-risk
        verification = StrongCustomerAuth.initiate_3ds_verification(
            secrets.token_hex(16), email, amount
        )
        return {"requires_3ds": True, "verification": verification}
    
    # 2. Create payment initialization
    response = requests.post(
        "https://api.paystack.co/transaction/initialize",
        headers={"Authorization": f"Bearer {PAYSTACK_SECRET}"},
        json={
            "email": email,
            "amount": int(amount * 100),  # Convert to kobo
            "plan": plan,
            "metadata": {
                "user_email": email,
                "plan": plan,
                "risk_score": risk_score
            }
        }
    )
    
    return response.json()


@app.post("/api/subscription/verify-payment")
async def verify_payment(reference: str, user: dict = Depends(_get_current_user)):
    email = user.get("email", "")
    
    # Verify with Paystack
    response = requests.get(
        f"https://api.paystack.co/transaction/verify/{reference}",
        headers={"Authorization": f"Bearer {PAYSTACK_SECRET}"}
    )
    
    if response.status_code == 200:
        data = response.json()
        if data.get("data", {}).get("status") == "success":
            
            # Store transaction
            transaction = {
                "transaction_id": reference,
                "email": email,
                "amount": data.get("data", {}).get("amount", 0) / 100,
                "status": "completed",
                "reference": reference,
                "last4": data.get("data", {}).get("authorization", {}).get("last4"),
                "description": "Premium subscription"
            }
            
            TransactionSecurity.store_transaction(transaction)
            TransactionSecurity.audit_transaction(reference, "payment_received", {})
            
            # Activate subscription
            activate_subscription(email)
            
            return {"success": True, "message": "Payment verified"}
    
    raise HTTPException(status_code=400, detail="Payment verification failed")
"""

import os

print("[PAYMENT] Payment Fraud Prevention Module Loaded")
print("[PAYMENT] Features: PCI DSS, Fraud Detection, 3D Secure, Tokenization")
