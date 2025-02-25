import os
import string
import secrets
from ..utils.loggerHandler import LoggerInstance
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

logger = LoggerInstance()

def generate_entropy_pool(size=64):
    entropy = os.urandom(size)
    logger.debug("Entropy pool generated")
    return entropy

def derive_value(entropy_pool, modifier, size):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=size,
        salt=None,
        info=modifier,
        backend=default_backend()
    )
    derived_value = hkdf.derive(entropy_pool)
    logger.debug(f"Derived value for {modifier.decode()} generated")
    return derived_value

def save_to_file(filename: str, values: list[bytes]) -> None:
    # Write keys joined by newline without a trailing newline
    with open(filename, "wb") as f:
        f.write(b"\n".join(values))
    logger.info(f"Values saved to {filename}")

def generate_password(filename: str | None = None) -> tuple[bytes, ...]:
    filename = filename or "password.ini"
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            lines = f.read().splitlines()
            if len(lines) < 5:
                raise ValueError("Password file does not contain enough keys.")
            return tuple(lines[:5])
    
    entropy_pool = generate_entropy_pool()
    password1 = derive_value(entropy_pool, b"bitterl1", 32)
    password2 = derive_value(entropy_pool, b"bitterl2", 32)
    password3 = derive_value(entropy_pool, b"bitterl3", 32)
    salt = derive_value(entropy_pool, b"salt", 16)
    nonce = derive_value(entropy_pool, b"nonce", 12)
    
    keys = [password1, password2, password3, salt, nonce]
    save_to_file(filename, keys)
    return (password1, password2, password3, salt, nonce)

def generate_single_password(length: int) -> str:
    if length < 4:
        raise ValueError("Password length must be at least 4 to include all character types.")
    
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    special = string.punctuation

    # Ensure each character type is represented
    password_chars = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    
    all_chars = lower + upper + digits + special
    password_chars.extend(secrets.choice(all_chars) for _ in range(length - 4))
    secrets.SystemRandom().shuffle(password_chars)

    return ''.join(password_chars)
