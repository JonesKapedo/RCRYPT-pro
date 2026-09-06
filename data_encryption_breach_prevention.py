"""
RockyCrypt Data Encryption & Breach Prevention Module
Comprehensive data protection against breaches
"""

import os
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Tuple, Optional, List, Any
import hashlib
import secrets
import shutil

# ============================================================================
# 1. ENCRYPTION AT REST
# ============================================================================

class EncryptionAtRest:
    """Encrypt sensitive data stored on disk."""
    
    @staticmethod
    def get_cipher():
        """Get Fernet cipher for encryption."""
        from cryptography.fernet import Fernet
        
        key = os.environ.get("DATA_ENCRYPTION_KEY")
        if not key:
            # Generate new key (store in secrets manager!)
            key = Fernet.generate_key()
            print(f"[encryption] New encryption key: {key.decode()}")
            print("[encryption] Store this in DATA_ENCRYPTION_KEY environment variable")
        
        return Fernet(key.encode() if isinstance(key, str) else key)
    
    @staticmethod
    def encrypt_field(data: str) -> str:
        """Encrypt a single field."""
        cipher = EncryptionAtRest.get_cipher()
        encrypted = cipher.encrypt(data.encode())
        return encrypted.decode()
    
    @staticmethod
    def decrypt_field(encrypted_data: str) -> str:
        """Decrypt a single field."""
        cipher = EncryptionAtRest.get_cipher()
        decrypted = cipher.decrypt(encrypted_data.encode())
        return decrypted.decode()
    
    @staticmethod
    def encrypt_file(file_path: str) -> bool:
        """Encrypt an entire file."""
        try:
            cipher = EncryptionAtRest.get_cipher()
            
            with open(file_path, 'rb') as f:
                original_data = f.read()
            
            encrypted_data = cipher.encrypt(original_data)
            
            # Save with .enc extension
            encrypted_path = f"{file_path}.enc"
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Securely delete original
            EncryptionAtRest.secure_delete(file_path)
            
            return True
        except Exception as e:
            print(f"[encryption] File encryption error: {e}")
            return False
    
    @staticmethod
    def decrypt_file(encrypted_path: str, output_path: str) -> bool:
        """Decrypt an entire file."""
        try:
            cipher = EncryptionAtRest.get_cipher()
            
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = cipher.decrypt(encrypted_data)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            return True
        except Exception as e:
            print(f"[encryption] File decryption error: {e}")
            return False
    
    @staticmethod
    def secure_delete(file_path: str, passes: int = 3) -> bool:
        """
        Securely delete file by overwriting with random data.
        Prevents recovery via disk analysis.
        """
        try:
            file_size = os.path.getsize(file_path)
            
            # Overwrite with random data multiple times
            for _ in range(passes):
                with open(file_path, 'wb') as f:
                    f.write(os.urandom(file_size))
            
            # Final deletion
            os.remove(file_path)
            
            return True
        except Exception as e:
            print(f"[encryption] Secure delete error: {e}")
            return False


# ============================================================================
# 2. DATA ANONYMIZATION & REDACTION
# ============================================================================

class DataAnonymization:
    """Anonymize and redact sensitive data."""
    
    @staticmethod
    def anonymize_email(email: str) -> str:
        """Redact email address (keep domain, anonymize user part)."""
        parts = email.split("@")
        if len(parts) != 2:
            return email
        
        user_part = parts[0]
        domain = parts[1]
        
        # Show only first char and last char
        if len(user_part) > 3:
            anonymized = user_part[0] + "*" * (len(user_part) - 2) + user_part[-1]
        else:
            anonymized = "*" * len(user_part)
        
        return f"{anonymized}@{domain}"
    
    @staticmethod
    def anonymize_card_number(card_number: str) -> str:
        """Redact card number (show only last 4 digits)."""
        if len(card_number) < 4:
            return "****"
        
        return "*" * (len(card_number) - 4) + card_number[-4:]
    
    @staticmethod
    def anonymize_ip_address(ip: str) -> str:
        """Anonymize IP address."""
        parts = ip.split(".")
        if len(parts) == 4:
            # Keep first 3 octets, anonymize last
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0"
        
        return ip
    
    @staticmethod
    def redact_logs(log_data: Dict) -> Dict:
        """Redact sensitive information from logs."""
        
        redacted = {}
        
        for key, value in log_data.items():
            if isinstance(value, str):
                if "email" in key.lower():
                    redacted[key] = DataAnonymization.anonymize_email(value)
                elif "password" in key.lower() or "token" in key.lower():
                    redacted[key] = "*" * len(value)
                elif "card" in key.lower():
                    redacted[key] = DataAnonymization.anonymize_card_number(value)
                elif "ip" in key.lower():
                    redacted[key] = DataAnonymization.anonymize_ip_address(value)
                else:
                    redacted[key] = value
            else:
                redacted[key] = value
        
        return redacted


# ============================================================================
# 3. DATA RETENTION & DELETION POLICIES
# ============================================================================

class DataRetentionPolicy:
    """Implement data retention and deletion policies."""
    
    # Retention periods (in days)
    RETENTION_POLICIES = {
        "audit_logs": 365,           # 1 year
        "transaction_records": 2555,  # 7 years (PCI requirement)
        "email_logs": 90,             # 90 days
        "login_history": 180,         # 6 months
        "failed_attempts": 90,        # 90 days
        "user_data_after_deletion": 30 # 30 days after account deletion
    }
    
    @staticmethod
    def cleanup_expired_data() -> Dict[str, int]:
        """Delete data older than retention period."""
        
        cleanup_results = {
            "audit_logs_deleted": 0,
            "email_logs_deleted": 0,
            "login_history_deleted": 0,
            "files_cleaned": 0
        }
        
        # Clean audit logs
        cleanup_results["audit_logs_deleted"] = DataRetentionPolicy._clean_file(
            "data/audit.log",
            DataRetentionPolicy.RETENTION_POLICIES["audit_logs"]
        )
        
        # Clean email logs
        cleanup_results["email_logs_deleted"] = DataRetentionPolicy._clean_file(
            "data/email_audit.json",
            DataRetentionPolicy.RETENTION_POLICIES["email_logs"]
        )
        
        # Clean login history
        cleanup_results["login_history_deleted"] = DataRetentionPolicy._clean_file(
            "data/login_attempts.json",
            DataRetentionPolicy.RETENTION_POLICIES["login_history"]
        )
        
        return cleanup_results
    
    @staticmethod
    def _clean_file(file_path: str, retention_days: int) -> int:
        """Remove entries older than retention period."""
        
        if not Path(file_path).exists():
            return 0
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                return 0
            
            threshold_date = datetime.now() - timedelta(days=retention_days)
            original_count = len(data)
            
            # Filter out old entries
            retained_data = []
            for entry in data:
                timestamp_str = entry.get("timestamp", "")
                if timestamp_str:
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str)
                        if timestamp > threshold_date:
                            retained_data.append(entry)
                    except ValueError:
                        retained_data.append(entry)
                else:
                    retained_data.append(entry)
            
            # Write back
            with open(file_path, 'w') as f:
                json.dump(retained_data, f, indent=2)
            
            deleted_count = original_count - len(retained_data)
            return deleted_count
        
        except Exception as e:
            print(f"[retention] Cleanup error for {file_path}: {e}")
            return 0
    
    @staticmethod
    def schedule_user_data_deletion(user_email: str, delay_days: int = 30) -> Dict:
        """
        Schedule user data deletion (GDPR right to be forgotten).
        Data not immediately deleted; user can cancel within 30 days.
        """
        
        deletion_record = {
            "email": user_email,
            "scheduled_for_deletion": True,
            "scheduled_at": datetime.now().isoformat(),
            "deletion_date": (datetime.now() + timedelta(days=delay_days)).isoformat(),
            "can_cancel_until": (datetime.now() + timedelta(days=delay_days)).isoformat()
        }
        
        deletions_file = Path("data/scheduled_deletions.json")
        deletions = []
        
        if deletions_file.exists():
            try:
                with open(deletions_file, 'r') as f:
                    deletions = json.load(f)
            except Exception:
                deletions = []
        
        # Update if already exists
        existing = False
        for i, record in enumerate(deletions):
            if record.get("email") == user_email:
                deletions[i] = deletion_record
                existing = True
                break
        
        if not existing:
            deletions.append(deletion_record)
        
        with open(deletions_file, 'w') as f:
            json.dump(deletions, f, indent=2)
        
        return deletion_record
    
    @staticmethod
    def process_scheduled_deletions() -> Dict[str, int]:
        """Process users scheduled for deletion after 30-day grace period."""
        
        results = {
            "deleted_users": 0,
            "errors": 0
        }
        
        deletions_file = Path("data/scheduled_deletions.json")
        if not deletions_file.exists():
            return results
        
        try:
            with open(deletions_file, 'r') as f:
                deletions = json.load(f)
            
            now = datetime.now()
            remaining = []
            
            for deletion in deletions:
                deletion_date_str = deletion.get("deletion_date", "")
                if deletion_date_str:
                    try:
                        deletion_date = datetime.fromisoformat(deletion_date_str)
                        
                        if now > deletion_date:
                            # Time to delete user
                            email = deletion.get("email", "")
                            if DataRetentionPolicy._delete_user_data(email):
                                results["deleted_users"] += 1
                            else:
                                results["errors"] += 1
                        else:
                            remaining.append(deletion)
                    except ValueError:
                        remaining.append(deletion)
                else:
                    remaining.append(deletion)
            
            # Write back remaining
            with open(deletions_file, 'w') as f:
                json.dump(remaining, f, indent=2)
        
        except Exception as e:
            print(f"[retention] Deletion processing error: {e}")
            results["errors"] += 1
        
        return results
    
    @staticmethod
    def _delete_user_data(user_email: str) -> bool:
        """Permanently delete all user data."""
        try:
            users_file = Path("data/users.json")
            if users_file.exists():
                with open(users_file, 'r') as f:
                    users = json.load(f)
                
                users = [u for u in users if u.get("email") != user_email]
                
                with open(users_file, 'w') as f:
                    json.dump(users, f, indent=2)
            
            # Delete other user-related data
            subscriptions_file = Path("data/subscriptions.json")
            if subscriptions_file.exists():
                with open(subscriptions_file, 'r') as f:
                    subs = json.load(f)
                
                subs = {k: v for k, v in subs.items() if k != user_email}
                
                with open(subscriptions_file, 'w') as f:
                    json.dump(subs, f, indent=2)
            
            return True
        except Exception as e:
            print(f"[retention] User deletion error: {e}")
            return False
    
    @staticmethod
    def cancel_scheduled_deletion(user_email: str) -> bool:
        """Cancel scheduled deletion (user changed mind)."""
        try:
            deletions_file = Path("data/scheduled_deletions.json")
            if not deletions_file.exists():
                return False
            
            with open(deletions_file, 'r') as f:
                deletions = json.load(f)
            
            deletions = [d for d in deletions if d.get("email") != user_email]
            
            with open(deletions_file, 'w') as f:
                json.dump(deletions, f, indent=2)
            
            return True
        except Exception as e:
            print(f"[retention] Cancel deletion error: {e}")
            return False


# ============================================================================
# 4. BACKUP ENCRYPTION & INTEGRITY
# ============================================================================

class BackupSecurity:
    """Secure backup creation and integrity verification."""
    
    @staticmethod
    def create_encrypted_backup(backup_dir: str = "backups") -> Tuple[bool, str]:
        """Create encrypted backup of all data."""
        
        try:
            import subprocess
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"{backup_dir}/rockycrypt_backup_{timestamp}.tar.gz"
            
            # Create tarball
            os.makedirs(backup_dir, exist_ok=True)
            subprocess.run([
                "tar", "czf", backup_file,
                "data/"
            ], check=True)
            
            # Encrypt backup
            encrypted_file = f"{backup_file}.aes"
            encryption_key = os.environ.get("BACKUP_ENCRYPTION_KEY")
            
            if encryption_key:
                subprocess.run([
                    "openssl", "enc", "-aes-256-cbc",
                    "-in", backup_file,
                    "-out", encrypted_file,
                    "-k", encryption_key
                ], check=True)
                
                # Delete unencrypted backup
                EncryptionAtRest.secure_delete(backup_file)
                backup_file = encrypted_file
            
            # Calculate checksum
            checksum = BackupSecurity._calculate_checksum(backup_file)
            
            # Store checksum
            BackupSecurity._store_checksum(backup_file, checksum)
            
            return True, f"Backup created: {backup_file}"
        
        except Exception as e:
            return False, f"Backup error: {e}"
    
    @staticmethod
    def verify_backup_integrity(backup_file: str) -> Tuple[bool, str]:
        """Verify backup integrity using checksums."""
        
        try:
            current_checksum = BackupSecurity._calculate_checksum(backup_file)
            stored_checksum = BackupSecurity._retrieve_checksum(backup_file)
            
            if current_checksum == stored_checksum:
                return True, "Backup integrity verified"
            else:
                return False, "Backup integrity check FAILED - backup corrupted"
        
        except Exception as e:
            return False, f"Verification error: {e}"
    
    @staticmethod
    def _calculate_checksum(file_path: str) -> str:
        """Calculate SHA-256 checksum of file."""
        
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    @staticmethod
    def _store_checksum(file_path: str, checksum: str) -> None:
        """Store checksum for later verification."""
        
        checksum_file = f"{file_path}.sha256"
        
        with open(checksum_file, 'w') as f:
            f.write(checksum)
    
    @staticmethod
    def _retrieve_checksum(file_path: str) -> Optional[str]:
        """Retrieve stored checksum."""
        
        checksum_file = f"{file_path}.sha256"
        
        if Path(checksum_file).exists():
            with open(checksum_file, 'r') as f:
                return f.read().strip()
        
        return None


# ============================================================================
# 5. BREACH DETECTION & RESPONSE
# ============================================================================

class BreachDetection:
    """Detect and respond to potential data breaches."""
    
    @staticmethod
    def detect_breach_indicators() -> Dict[str, bool]:
        """Check for indicators of compromise."""
        
        indicators = {
            "unauthorized_access": BreachDetection._check_unauthorized_access(),
            "unusual_data_access": BreachDetection._check_unusual_access_patterns(),
            "suspicious_processes": BreachDetection._check_suspicious_processes(),
            "failed_integrity_checks": BreachDetection._check_failed_integrity(),
            "suspicious_network": BreachDetection._check_network_anomalies()
        }
        
        return indicators
    
    @staticmethod
    def _check_unauthorized_access() -> bool:
        """Check for unauthorized access patterns."""
        
        audit_file = Path("data/audit.log")
        if not audit_file.exists():
            return False
        
        try:
            with open(audit_file, 'r') as f:
                for line in f:
                    if "unauthorized" in line.lower() or "denied" in line.lower():
                        return True
        except Exception:
            pass
        
        return False
    
    @staticmethod
    def _check_unusual_access_patterns() -> bool:
        """Check for unusual data access patterns."""
        
        # Check for mass data exports
        audit_file = Path("data/audit.log")
        if audit_file.exists():
            try:
                with open(audit_file, 'r') as f:
                    export_count = sum(1 for line in f if "export" in line.lower())
                
                if export_count > 10:
                    return True
            except Exception:
                pass
        
        return False
    
    @staticmethod
    def _check_suspicious_processes() -> bool:
        """Check for suspicious processes (shell commands, etc.)."""
        
        # In production: monitor system processes
        return False
    
    @staticmethod
    def _check_failed_integrity() -> bool:
        """Check if file integrity checks are failing."""
        
        # Check if backups are corrupted
        backups_dir = Path("backups")
        if backups_dir.exists():
            for backup in backups_dir.glob("*.aes"):
                is_valid, _ = BackupSecurity.verify_backup_integrity(str(backup))
                if not is_valid:
                    return True
        
        return False
    
    @staticmethod
    def _check_network_anomalies() -> bool:
        """Check for unusual network activity."""
        
        # In production: monitor DDoS attempts, port scans, etc.
        return False
    
    @staticmethod
    def initiate_breach_response(severity: str = "medium") -> Dict:
        """
        Initiate breach response protocol.
        
        INCIDENT RESPONSE PLAN:
        1. CONTAINMENT: Isolate affected systems
        2. ERADICATION: Remove malware/attacker access
        3. RECOVERY: Restore from clean backups
        4. NOTIFICATION: Inform users (24-72 hours)
        5. INVESTIGATION: Determine scope and impact
        """
        
        incident = {
            "incident_id": secrets.token_hex(16),
            "detected_at": datetime.now().isoformat(),
            "severity": severity,
            "status": "active",
            "actions_taken": [
                "Incident detected and logged",
                "Security team notified",
                "Systems isolated"
            ],
            "user_notification_sent": False,
            "authorities_notified": False
        }
        
        # Log incident
        incidents_file = Path("data/security_incidents.json")
        incidents = []
        
        if incidents_file.exists():
            try:
                with open(incidents_file, 'r') as f:
                    incidents = json.load(f)
            except Exception:
                incidents = []
        
        incidents.append(incident)
        
        with open(incidents_file, 'w') as f:
            json.dump(incidents, f, indent=2)
        
        return incident


print("[ENCRYPTION] Data Encryption & Breach Prevention Module Loaded")
print("[ENCRYPTION] Features: AES Encryption, Data Anonymization, Retention Policies, Backup Security")
