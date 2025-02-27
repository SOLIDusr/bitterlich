import os
import string
import secrets
from ..utils.loggerHandler import LoggerInstance
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from ..settings import get_global_settings


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
    settings = get_global_settings()
    filename = filename or settings.get('password_filepath', 'password.ini')
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
    # Use only the allowed special characters.
    special = "!@#$%^&*()_-+={[}]|:;\"'<,>.?/"
    
    # Ensure each category gets at least one character.
    counts = {'lower': 1, 'upper': 1, 'digits': 1, 'special': 1}
    remaining = length - 4
    categories = ['lower', 'upper', 'digits', 'special']
    
    # Randomly distribute the remaining characters among the categories.
    for _ in range(remaining):
        category = secrets.choice(categories)
        counts[category] += 1

    password_chars = []
    password_chars.extend(secrets.choice(lower) for _ in range(counts['lower']))
    password_chars.extend(secrets.choice(upper) for _ in range(counts['upper']))
    password_chars.extend(secrets.choice(digits) for _ in range(counts['digits']))
    password_chars.extend(secrets.choice(special) for _ in range(counts['special']))

    # Shuffle to ensure the order is random.
    secrets.SystemRandom().shuffle(password_chars)

    return ''.join(password_chars)