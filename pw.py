#!/usr/bin/env python3

import json
import os
import sys
import getpass
import secrets
import string
import pyperclip
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Configuration
VAULT_FILE = 'vault.json'
SALT_FILE = 'vault.salt'

class PasswordManager:
    def __init__(self):
        self.vault_data = {}
        
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # Strong iteration count
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _get_or_create_salt(self) -> bytes:
        """Get existing salt or create new one"""
        if os.path.exists(SALT_FILE):
            with open(SALT_FILE, 'rb') as f:
                return f.read()
        else:
            salt = os.urandom(16)  # 16 bytes = 128 bits
            with open(SALT_FILE, 'wb') as f:
                f.write(salt)
            return salt
    
    def _get_master_password(self, prompt: str = "Enter master password: ") -> str:
        """Securely get master password from user"""
        return getpass.getpass(prompt)
    
    def _encrypt_data(self, data: dict, master_password: str) -> bytes:
        """Encrypt vault data with master password"""
        salt = self._get_or_create_salt()
        key = self._derive_key(master_password, salt)
        f = Fernet(key)
        
        json_data = json.dumps(data, indent=2).encode()
        encrypted_data = f.encrypt(json_data)
        return encrypted_data
    
    def _decrypt_data(self, encrypted_data: bytes, master_password: str) -> dict:
        """Decrypt vault data with master password"""
        try:
            salt = self._get_or_create_salt()
            key = self._derive_key(master_password, salt)
            f = Fernet(key)
            
            decrypted_data = f.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception:
            raise ValueError("Invalid master password or corrupted vault")
    
    def load_vault(self, master_password: str) -> bool:
        """Load and decrypt the password vault"""
        if not os.path.exists(VAULT_FILE):
            self.vault_data = {}
            return True
        
        try:
            with open(VAULT_FILE, 'rb') as f:
                encrypted_data = f.read()
            
            if not encrypted_data:  # Empty file
                self.vault_data = {}
                return True
                
            self.vault_data = self._decrypt_data(encrypted_data, master_password)
            return True
        except ValueError as e:
            print(f"Error: {e}")
            return False
        except Exception as e:
            print(f"Error loading vault: {e}")
            return False
    
    def save_vault(self, master_password: str):
        """Encrypt and save the password vault"""
        try:
            encrypted_data = self._encrypt_data(self.vault_data, master_password)
            with open(VAULT_FILE, 'wb') as f:
                f.write(encrypted_data)
        except Exception as e:
            print(f"Error saving vault: {e}")
            sys.exit(1)
    
    def add_password(self, account: str, password: str = None):
        """Add a password for an account"""
        if password is None:
            password = getpass.getpass(f"Enter password for '{account}': ")
        
        if not password.strip():
            print("Error: Password cannot be empty")
            return False
        
        self.vault_data[account] = {
            'password': password,
            'created': self._get_timestamp()
        }
        return True
    
    def get_password(self, account: str) -> bool:
        """Get password for an account and copy to clipboard"""
        if account not in self.vault_data:
            print(f"No password found for '{account}'")
            return False
        
        password = self.vault_data[account]['password']
        try:
            pyperclip.copy(password)
            print(f"Password for '{account}' copied to clipboard!")
            
            # Show when password was created
            if 'created' in self.vault_data[account]:
                print(f"Created: {self.vault_data[account]['created']}")
            
            return True
        except Exception as e:
            print(f"Error copying to clipboard: {e}")
            print(f"Password for '{account}': {password}")
            return False
    
    def list_accounts(self):
        """List all stored accounts"""
        if not self.vault_data:
            print("No passwords stored.")
            return
        
        print(f"Stored accounts ({len(self.vault_data)}):")
        for account, data in sorted(self.vault_data.items()):
            created = data.get('created', 'Unknown date')
            print(f"  • {account} (created: {created})")
    
    def delete_password(self, account: str) -> bool:
        """Delete password for an account"""
        if account not in self.vault_data:
            print(f"No password found for '{account}'")
            return False
        
        confirm = input(f"Delete password for '{account}'? (yes/no): ").lower()
        if confirm in ['yes', 'y']:
            del self.vault_data[account]
            print(f"Password for '{account}' deleted.")
            return True
        else:
            print("Deletion cancelled.")
            return False
    
    def generate_password(self, account: str, length: int = 16):
        """Generate a strong random password"""
        if length < 8:
            print("Error: Password length must be at least 8 characters")
            return False
        
        if length > 128:
            print("Error: Password length cannot exceed 128 characters")
            return False
        
        # Character sets for strong password
        chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
        
        # Ensure password has at least one character from each type
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice("!@#$%^&*()-_=+")
        ]
        
        # Fill the rest randomly
        for _ in range(length - 4):
            password.append(secrets.choice(chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        final_password = ''.join(password)
        
        print(f"Generated password for '{account}' (length: {length})")
        print("Password:", final_password)
        
        save = input("Save this password? (yes/no): ").lower()
        if save in ['yes', 'y']:
            return self.add_password(account, final_password)
        
        return False
    
    def change_master_password(self):
        """Change the master password"""
        print("Changing master password...")
        old_password = self._get_master_password("Enter current master password: ")
        
        # Verify current password by trying to load vault
        if not self.load_vault(old_password):
            print("Error: Invalid current master password")
            return False
        
        new_password = self._get_master_password("Enter new master password: ")
        confirm_password = self._get_master_password("Confirm new master password: ")
        
        if new_password != confirm_password:
            print("Error: Passwords don't match")
            return False
        
        if len(new_password) < 8:
            print("Error: Master password must be at least 8 characters long")
            return False
        
        # Save vault with new password
        self.save_vault(new_password)
        print("Master password changed successfully!")
        return True
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def show_usage():
    """Show usage instructions"""
    print("Secure Password Manager")
    print("Usage:")
    print("  python password_manager.py add <account>")
    print("  python password_manager.py get <account>")
    print("  python password_manager.py list")
    print("  python password_manager.py delete <account>")
    print("  python password_manager.py generate <account> [length]")
    print("  python password_manager.py change-master")
    print()
    print("Examples:")
    print("  python password_manager.py add gmail")
    print("  python password_manager.py get gmail")
    print("  python password_manager.py generate work_email 20")

def main():
    if len(sys.argv) < 2:
        show_usage()
        return
    
    command = sys.argv[1].lower()
    pm = PasswordManager()
    
    # Commands that don't need vault access
    if command == 'change-master':
        pm.change_master_password()
        return
    
    # Get master password and load vault
    master_password = pm._get_master_password()
    if not pm.load_vault(master_password):
        print("Failed to unlock vault. Exiting.")
        return
    
    try:
        if command == 'add':
            if len(sys.argv) != 3:
                print("Usage: add <account>")
                return
            account = sys.argv[2]
            if pm.add_password(account):
                pm.save_vault(master_password)
                print(f"Password saved for '{account}'")
        
        elif command == 'get':
            if len(sys.argv) != 3:
                print("Usage: get <account>")
                return
            account = sys.argv[2]
            pm.get_password(account)
        
        elif command == 'list':
            pm.list_accounts()
        
        elif command == 'delete':
            if len(sys.argv) != 3:
                print("Usage: delete <account>")
                return
            account = sys.argv[2]
            if pm.delete_password(account):
                pm.save_vault(master_password)
        
        elif command == 'generate':
            if len(sys.argv) < 3:
                print("Usage: generate <account> [length]")
                return
            account = sys.argv[2]
            length = 16  # default length
            if len(sys.argv) == 4:
                try:
                    length = int(sys.argv[3])
                except ValueError:
                    print("Error: Length must be a number")
                    return
            
            if pm.generate_password(account, length):
                pm.save_vault(master_password)
        
        else:
            print(f"Unknown command: {command}")
            show_usage()
    
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    main()