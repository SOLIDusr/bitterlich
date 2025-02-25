import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .generate import generate_password
from ..utils.loggerHandler import LoggerInstance

logger = LoggerInstance()

def encrypt(data: bytes, password: bytes, salt: bytes, nonce: bytes) -> bytes:
    """Encrypts data using AES GCM after deriving a 256-bit key via PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return ciphertext

def decrypt(data: bytes, password: bytes, salt: bytes, nonce: bytes) -> bytes:
    """Decrypts data using AES GCM after deriving the key."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, data, None)
    return plaintext

def encrypt_vault(data: bytes, password_file: str | None = None) -> bytes:
    """
    Encrypts the entire vault (JSON bytes) by triple-encrypting with three keys.
    Keys (and the salt and nonce) are obtained from generate_password.
    """
    password1, password2, password3, salt, nonce = generate_password(password_file)
    # Triple-layer encryption (first with key1, then key2, then key3)
    ct = encrypt(data, password1, salt, nonce)
    ct = encrypt(ct, password2, salt, nonce)
    ct = encrypt(ct, password3, salt, nonce)
    return ct

def decrypt_vault(ciphertext: bytes, password_file: str) -> bytes:
    """
    Decrypts the vault ciphertext by reversing the triple encryption.
    The keys, salt, and nonce are obtained from generate_password.
    """
    password1, password2, password3, salt, nonce = generate_password(password_file)
    pt = decrypt(ciphertext, password3, salt, nonce)
    pt = decrypt(pt, password2, salt, nonce)
    pt = decrypt(pt, password1, salt, nonce)
    return pt
