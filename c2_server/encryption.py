#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# c2_server/encryption.py
# BlackHunter Pro - Encryption Module
# AES-256 encryption, key exchange, and secure communication
# Academic Penetration Testing Tool - Isolated Lab Only

import os
import sys
import json
import hmac
import base64
import hashlib
import secrets
import struct
import time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# =============================================
# CONFIGURATION
# =============================================

AES_KEY_SIZE = 32  # 256 bits
AES_BLOCK_SIZE = 16
AES_NONCE_SIZE = 12  # GCM nonce
AES_TAG_SIZE = 16    # GCM auth tag
PBKDF2_ITERATIONS = 100000
RSA_KEY_SIZE = 2048
SESSION_KEY_SIZE = 32

# =============================================
# COLORS
# =============================================

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    DIM = '\033[2m'
    RESET = '\033[0m'

C = Colors

# =============================================
# LOGGING
# =============================================

def log(message, level="INFO"):
    """Log message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    colors = {
        "INFO": C.CYAN,
        "OK": C.GREEN,
        "WARN": C.YELLOW,
        "ERROR": C.RED,
        "CRYPTO": C.MAGENTA,
    }

    color = colors.get(level, C.WHITE)
    print(f"{color}[{timestamp}] [{level}]{C.RESET} {message}")

# =============================================
# AES-256-GCM ENCRYPTION
# =============================================

class AESCipher:
    """AES-256-GCM authenticated encryption"""

    @staticmethod
    def generate_key():
        """Generate random 256-bit key"""
        return os.urandom(AES_KEY_SIZE)

    @staticmethod
    def generate_nonce():
        """Generate random 96-bit nonce"""
        return os.urandom(AES_NONCE_SIZE)

    @staticmethod
    def encrypt(key, plaintext, associated_data=None):
        """
        Encrypt with AES-256-GCM

        Returns: (nonce, ciphertext, tag) tuple
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        nonce = AESCipher.generate_nonce()

        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )

        encryptor = cipher.encryptor()

        if associated_data:
            if isinstance(associated_data, str):
                associated_data = associated_data.encode()
            encryptor.authenticate_additional_data(associated_data)

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return nonce, ciphertext, encryptor.tag

    @staticmethod
    def decrypt(key, nonce, ciphertext, tag, associated_data=None):
        """
        Decrypt with AES-256-GCM

        Returns: plaintext (bytes)
        """
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )

        decryptor = cipher.decryptor()

        if associated_data:
            if isinstance(associated_data, str):
                associated_data = associated_data.encode()
            decryptor.authenticate_additional_data(associated_data)

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext

    @staticmethod
    def encrypt_to_base64(key, plaintext, associated_data=None):
        """Encrypt and encode as base64"""
        nonce, ciphertext, tag = AESCipher.encrypt(key, plaintext, associated_data)

        # Format: nonce + tag + ciphertext
        combined = nonce + tag + ciphertext

        return base64.b64encode(combined).decode()

    @staticmethod
    def decrypt_from_base64(key, b64_data, associated_data=None):
        """Decrypt from base64"""
        try:
            combined = base64.b64decode(b64_data)

            if len(combined) < AES_NONCE_SIZE + AES_TAG_SIZE:
                return None

            nonce = combined[:AES_NONCE_SIZE]
            tag = combined[AES_NONCE_SIZE:AES_NONCE_SIZE + AES_TAG_SIZE]
            ciphertext = combined[AES_NONCE_SIZE + AES_TAG_SIZE:]

            return AESCipher.decrypt(key, nonce, ciphertext, tag, associated_data)
        except Exception as e:
            log(f"Decryption failed: {e}", "ERROR")
            return None

    @staticmethod
    def encrypt_file(key, input_path, output_path):
        """Encrypt a file"""
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        nonce, ciphertext, tag = AESCipher.encrypt(key, plaintext)

        with open(output_path, 'wb') as f:
            f.write(nonce)
            f.write(tag)
            f.write(ciphertext)

        return os.path.getsize(output_path)

    @staticmethod
    def decrypt_file(key, input_path, output_path):
        """Decrypt a file"""
        with open(input_path, 'rb') as f:
            data = f.read()

        nonce = data[:AES_NONCE_SIZE]
        tag = data[AES_NONCE_SIZE:AES_NONCE_SIZE + AES_TAG_SIZE]
        ciphertext = data[AES_NONCE_SIZE + AES_TAG_SIZE:]

        plaintext = AESCipher.decrypt(key, nonce, ciphertext, tag)

        with open(output_path, 'wb') as f:
            f.write(plaintext)

        return len(plaintext)

# =============================================
# RSA KEY EXCHANGE
# =============================================

class RSACipher:
    """RSA for key exchange and signatures"""

    @staticmethod
    def generate_keypair(key_size=RSA_KEY_SIZE):
        """Generate RSA keypair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        return private_key, public_key

    @staticmethod
    def serialize_public_key(public_key):
        """Serialize public key to PEM"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def serialize_private_key(private_key, password=None):
        """Serialize private key to PEM"""
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

    @staticmethod
    def load_public_key(pem_data):
        """Load public key from PEM"""
        return serialization.load_pem_public_key(pem_data, backend=default_backend())

    @staticmethod
    def load_private_key(pem_data, password=None):
        """Load private key from PEM"""
        if password:
            password = password.encode()

        return serialization.load_pem_private_key(
            pem_data, password=password, backend=default_backend()
        )

    @staticmethod
    def encrypt(public_key, plaintext):
        """Encrypt with RSA public key"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return ciphertext

    @staticmethod
    def decrypt(private_key, ciphertext):
        """Decrypt with RSA private key"""
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return plaintext

    @staticmethod
    def sign(private_key, data):
        """Sign data with RSA private key"""
        if isinstance(data, str):
            data = data.encode()

        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return signature

    @staticmethod
    def verify(public_key, signature, data):
        """Verify signature"""
        try:
            if isinstance(data, str):
                data = data.encode()

            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

# =============================================
# KEY DERIVATION
# =============================================

class KeyDerivation:
    """Key derivation functions"""

    @staticmethod
    def pbkdf2(password, salt=None, iterations=PBKDF2_ITERATIONS, key_length=AES_KEY_SIZE):
        """Derive key using PBKDF2-HMAC-SHA256"""
        if isinstance(password, str):
            password = password.encode()

        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )

        key = kdf.derive(password)
        return key, salt

    @staticmethod
    def hkdf(input_key, info=b'', length=AES_KEY_SIZE):
        """HKDF key derivation"""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info,
            backend=default_backend()
        )

        return kdf.derive(input_key)

    @staticmethod
    def derive_key_from_shared(shared_secret, salt=None, length=AES_KEY_SIZE):
        """Derive AES key from shared secret"""
        if salt is None:
            salt = b'BlackHunter-C2-Salt'

        return KeyDerivation.hkdf(shared_secret, salt, length)

# =============================================
# HMAC AUTHENTICATION
# =============================================

class HMACAuth:
    """HMAC message authentication"""

    @staticmethod
    def sign(key, message):
        """Create HMAC signature"""
        if isinstance(key, str):
            key = key.encode()
        if isinstance(message, str):
            message = message.encode()

        h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message)
        return h.finalize()

    @staticmethod
    def verify(key, message, signature):
        """Verify HMAC signature"""
        if isinstance(key, str):
            key = key.encode()
        if isinstance(message, str):
            message = message.encode()

        h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message)

        try:
            h.verify(signature)
            return True
        except Exception:
            return False

    @staticmethod
    def sign_base64(key, message):
        """Sign and encode as base64"""
        sig = HMACAuth.sign(key, message)
        return base64.b64encode(sig).decode()

# =============================================
# SECURE SESSION
# =============================================

class SecureSession:
    """Secure session for C2 communication"""

    def __init__(self, session_id=None):
        self.session_id = session_id or secrets.token_hex(16)

        # Session keys
        self.send_key = None
        self.recv_key = None
        self.hmac_key = None

        # Counters (for replay protection)
        self.send_counter = 0
        self.recv_counter = 0

        # Handshake state
        self.handshake_complete = False
        self.established_at = None

        # RSA keys (for handshake)
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None

    def generate_keys(self):
        """Generate session keys"""
        self.send_key = AESCipher.generate_key()
        self.recv_key = AESCipher.generate_key()
        self.hmac_key = AESCipher.generate_key()

    def init_handshake(self):
        """Initialize handshake (server side)"""
        self.private_key, self.public_key = RSACipher.generate_keypair()
        log(f"Session {self.session_id[:8]}... RSA keypair generated", "CRYPTO")

        return RSACipher.serialize_public_key(self.public_key)

    def complete_handshake(self, peer_public_key_pem, encrypted_session_key):
        """Complete handshake with client"""
        try:
            # Load peer's public key
            self.peer_public_key = RSACipher.load_public_key(peer_public_key_pem)

            # Decrypt session key with our private key
            session_key = RSACipher.decrypt(self.private_key, encrypted_session_key)

            # Derive session keys
            self.send_key = KeyDerivation.derive_key_from_shared(session_key, b'send')
            self.recv_key = KeyDerivation.derive_key_from_shared(session_key, b'recv')
            self.hmac_key = KeyDerivation.derive_key_from_shared(session_key, b'hmac')

            self.handshake_complete = True
            self.established_at = datetime.now()

            log(f"Session {self.session_id[:8]}... handshake complete", "OK")
            return True

        except Exception as e:
            log(f"Handshake failed: {e}", "ERROR")
            return False

    def encrypt(self, plaintext):
        """Encrypt outgoing message"""
        if not self.handshake_complete:
            raise Exception("Handshake not complete")

        # Add counter for replay protection
        self.send_counter += 1
        counter_bytes = struct.pack('>Q', self.send_counter)

        # Associated data: session_id + counter
        aad = f"{self.session_id}:{self.send_counter}".encode()

        # Encrypt
        encrypted = AESCipher.encrypt_to_base64(
            self.send_key,
            plaintext,
            aad
        )

        # Build message
        message = {
            'session': self.session_id,
            'counter': self.send_counter,
            'data': encrypted,
        }

        # HMAC
        message_json = json.dumps(message, sort_keys=True)
        signature = HMACAuth.sign_base64(self.hmac_key, message_json)
        message['sig'] = signature

        return json.dumps(message)

    def decrypt(self, message_json):
        """Decrypt incoming message"""
        if not self.handshake_complete:
            raise Exception("Handshake not complete")

        try:
            message = json.loads(message_json)

            # Verify session
            if message.get('session') != self.session_id:
                log("Session mismatch", "WARN")
                return None

            # Verify HMAC
            signature = message.pop('sig', None)
            if signature:
                message_check = json.dumps(message, sort_keys=True)
                if not HMACAuth.verify(self.hmac_key, message_check, base64.b64decode(signature)):
                    log("HMAC verification failed", "WARN")
                    return None

            # Check counter (replay protection)
            counter = message.get('counter', 0)
            if counter <= self.recv_counter:
                log(f"Replay detected: counter {counter} <= {self.recv_counter}", "WARN")
                return None

            self.recv_counter = counter

            # Decrypt
            aad = f"{self.session_id}:{counter}".encode()
            plaintext = AESCipher.decrypt_from_base64(
                self.recv_key,
                message['data'],
                aad
            )

            return plaintext

        except Exception as e:
            log(f"Decrypt error: {e}", "ERROR")
            return None

# =============================================
# UTILITIES
# =============================================

class CryptoUtils:
    """Utility functions"""

    @staticmethod
    def hash_sha256(data):
        """SHA256 hash"""
        if isinstance(data, str):
            data = data.encode()

        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def hash_sha1(data):
        """SHA1 hash"""
        if isinstance(data, str):
            data = data.encode()

        return hashlib.sha1(data).hexdigest()

    @staticmethod
    def hash_md5(data):
        """MD5 hash"""
        if isinstance(data, str):
            data = data.encode()

        return hashlib.md5(data).hexdigest()

    @staticmethod
    def hash_file(file_path, algorithm='sha256'):
        """Hash a file"""
        if algorithm == 'sha256':
            h = hashlib.sha256()
        elif algorithm == 'sha1':
            h = hashlib.sha1()
        elif algorithm == 'md5':
            h = hashlib.md5()
        else:
            h = hashlib.sha256()

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)

        return h.hexdigest()

    @staticmethod
    def constant_time_compare(a, b):
        """Constant-time comparison"""
        return hmac.compare_digest(a, b)

    @staticmethod
    def random_bytes(length):
        """Generate random bytes"""
        return secrets.token_bytes(length)

    @staticmethod
    def random_hex(length):
        """Generate random hex string"""
        return secrets.token_hex(length)

    @staticmethod
    def random_b64(length):
        """Generate random base64 string"""
        return base64.b64encode(secrets.token_bytes(length)).decode()

# =============================================
# XOR OBFUSCATION (quick & simple)
# =============================================

class XORCipher:
    """Simple XOR encryption for obfuscation"""

    @staticmethod
    def encrypt(data, key):
        """XOR encrypt"""
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()

        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % len(key)])

        return bytes(result)

    @staticmethod
    def decrypt(data, key):
        """XOR decrypt (same as encrypt)"""
        return XORCipher.encrypt(data, key)

    @staticmethod
    def encrypt_hex(data, key):
        """XOR encrypt and hex encode"""
        encrypted = XORCipher.encrypt(data, key)
        return encrypted.hex()

    @staticmethod
    def decrypt_hex(hex_data, key):
        """Decrypt hex-encoded XOR data"""
        encrypted = bytes.fromhex(hex_data)
        return XORCipher.decrypt(encrypted, key)

    @staticmethod
    def encrypt_b64(data, key):
        """XOR encrypt and base64 encode"""
        encrypted = XORCipher.encrypt(data, key)
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def decrypt_b64(b64_data, key):
        """Decrypt base64-encoded XOR data"""
        encrypted = base64.b64decode(b64_data)
        return XORCipher.decrypt(encrypted, key)

# =============================================
# TEST & DEMO
# =============================================

def demo():
    """Demonstration of encryption functions"""
    print(f"\n{C.CYAN}{'='*60}{C.RESET}")
    print(f"{C.WHITE}  BlackHunter Encryption Module - Demo{C.RESET}")
    print(f"{C.CYAN}{'='*60}{C.RESET}\n")

    # AES-256-GCM
    print(f"{C.YELLOW}[*] AES-256-GCM:{C.RESET}")
    key = AESCipher.generate_key()
    print(f"  Key: {key.hex()[:32]}...")

    plaintext = "Hello, this is a secret message!"
    encrypted = AESCipher.encrypt_to_base64(key, plaintext)
    print(f"  Encrypted: {encrypted[:50]}...")

    decrypted = AESCipher.decrypt_from_base64(key, encrypted)
    print(f"  Decrypted: {decrypted.decode()}")
    print()

    # RSA
    print(f"{C.YELLOW}[*] RSA-2048:{C.RESET}")
    private_key, public_key = RSACipher.generate_keypair(2048)
    print(f"  Keypair generated")

    message = b"Session key exchange"
    rsa_encrypted = RSACipher.encrypt(public_key, message)
    rsa_decrypted = RSACipher.decrypt(private_key, rsa_encrypted)
    print(f"  RSA encrypt/decrypt: {rsa_decrypted.decode()}")
    print()

    # PBKDF2
    print(f"{C.YELLOW}[*] PBKDF2 Key Derivation:{C.RESET}")
    derived_key, salt = KeyDerivation.pbkdf2("password123")
    print(f"  Salt: {salt.hex()}")
    print(f"  Derived key: {derived_key.hex()[:32]}...")
    print()

    # HMAC
    print(f"{C.YELLOW}[*] HMAC-SHA256:{C.RESET}")
    hmac_key = os.urandom(32)
    message = b"Important message"
    sig = HMACAuth.sign(hmac_key, message)
    print(f"  Signature: {sig.hex()[:32]}...")
    print(f"  Valid: {HMACAuth.verify(hmac_key, message, sig)}")
    print()

    # XOR
    print(f"{C.YELLOW}[*] XOR Obfuscation:{C.RESET}")
    xor_key = "BlackHunter"
    original = "This is hidden text"
    encrypted_xor = XORCipher.encrypt_b64(original, xor_key)
    print(f"  Encrypted: {encrypted_xor}")
    decrypted_xor = XORCipher.decrypt_b64(encrypted_xor, xor_key)
    print(f"  Decrypted: {decrypted_xor.decode()}")
    print()

    # Hashes
    print(f"{C.YELLOW}[*] Hash Functions:{C.RESET}")
    print(f"  MD5:    {CryptoUtils.hash_md5('test')}")
    print(f"  SHA1:   {CryptoUtils.hash_sha1('test')}")
    print(f"  SHA256: {CryptoUtils.hash_sha256('test')}")
    print()

    # Session Demo
    print(f"{C.YELLOW}[*] Secure Session:{C.RESET}")
    session = SecureSession()
    session.generate_keys()
    print(f"  Session ID: {session.session_id}")
    print(f"  Keys generated")

    # Encrypt/decrypt
    session.handshake_complete = True
    session.send_key = AESCipher.generate_key()
    session.recv_key = session.send_key
    session.hmac_key = AESCipher.generate_key()

    msg = "Secure C2 message"
    encrypted_msg = session.encrypt(msg)
    print(f"  Encrypted: {encrypted_msg[:80]}...")

    decrypted_msg = session.decrypt(encrypted_msg)
    print(f"  Decrypted: {decrypted_msg.decode() if decrypted_msg else 'FAILED'}")
    print()

    print(f"{C.GREEN}[+] Demo complete!{C.RESET}\n")

# =============================================
# CLI
# =============================================

def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="BlackHunter Pro - Encryption Module")
    parser.add_argument('--demo', action='store_true', help="Run demonstration")
    parser.add_argument('--genkey', action='store_true', help="Generate AES key")
    parser.add_argument('--genrsa', action='store_true', help="Generate RSA keypair")
    parser.add_argument('--hash', help="Hash text (SHA256)")
    parser.add_argument('--encrypt', nargs=2, metavar=('KEY', 'TEXT'), help="AES encrypt")
    parser.add_argument('--decrypt', nargs=2, metavar=('KEY', 'DATA'), help="AES decrypt")
    parser.add_argument('--xor', nargs=2, metavar=('KEY', 'TEXT'), help="XOR encrypt")
    parser.add_argument('--unxor', nargs=2, metavar=('KEY', 'DATA'), help="XOR decrypt")
    parser.add_argument('--hashfile', help="Hash a file (SHA256)")

    args = parser.parse_args()

    if args.demo:
        demo()

    elif args.genkey:
        key = AESCipher.generate_key()
        print(f"AES-256 Key (hex): {key.hex()}")
        print(f"AES-256 Key (b64): {base64.b64encode(key).decode()}")

    elif args.genrsa:
        private_key, public_key = RSACipher.generate_keypair()
        private_pem = RSACipher.serialize_private_key(private_key)
        public_pem = RSACipher.serialize_public_key(public_key)

        print("Private Key:")
        print(private_pem.decode())
        print("\nPublic Key:")
        print(public_pem.decode())

    elif args.hash:
        print(f"SHA256: {CryptoUtils.hash_sha256(args.hash)}")
        print(f"SHA1:   {CryptoUtils.hash_sha1(args.hash)}")
        print(f"MD5:    {CryptoUtils.hash_md5(args.hash)}")

    elif args.hashfile:
        if os.path.exists(args.hashfile):
            print(f"SHA256: {CryptoUtils.hash_file(args.hashfile, 'sha256')}")
            print(f"SHA1:   {CryptoUtils.hash_file(args.hashfile, 'sha1')}")
            print(f"MD5:    {CryptoUtils.hash_file(args.hashfile, 'md5')}")
        else:
            print(f"File not found: {args.hashfile}")

    elif args.encrypt:
        key_str, text = args.encrypt
        # Convert key (hex or base64)
        try:
            key = bytes.fromhex(key_str)
        except:
            try:
                key = base64.b64decode(key_str)
            except:
                key = key_str.encode()[:32].ljust(32, b'\0')

        encrypted = AESCipher.encrypt_to_base64(key, text)
        print(f"Encrypted: {encrypted}")

    elif args.decrypt:
        key_str, data = args.decrypt
        try:
            key = bytes.fromhex(key_str)
        except:
            try:
                key = base64.b64decode(key_str)
            except:
                key = key_str.encode()[:32].ljust(32, b'\0')

        decrypted = AESCipher.decrypt_from_base64(key, data)
        if decrypted:
            print(f"Decrypted: {decrypted.decode('utf-8', errors='replace')}")
        else:
            print("Decryption failed")

    elif args.xor:
        key, text = args.xor
        encrypted = XORCipher.encrypt_b64(text, key)
        print(f"Encrypted (b64): {encrypted}")
        print(f"Encrypted (hex): {XORCipher.encrypt_hex(text, key)}")

    elif args.unxor:
        key, data = args.unxor
        try:
            decrypted = XORCipher.decrypt_b64(data, key)
        except:
            try:
                decrypted = XORCipher.decrypt_hex(data, key)
            except:
                decrypted = None

        if decrypted:
            print(f"Decrypted: {decrypted.decode('utf-8', errors='replace')}")
        else:
            print("Decryption failed")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()

# =============================================
# EXPORTS
# =============================================

__all__ = [
    'AESCipher',
    'RSACipher',
    'KeyDerivation',
    'HMACAuth',
    'SecureSession',
    'CryptoUtils',
    'XORCipher',
    'demo',
]