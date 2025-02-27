# vault.py
import json
import os
from pathlib import Path
from .crypto.enc import encrypt_vault, decrypt_vault
from .settings import get_global_settings


def normalize_filepath(file_input: str, extension: str) -> str:
    """
    Strips whitespace and ensures the file name ends with the provided extension.
    """
    file_input = file_input.strip()
    if not file_input.endswith(extension):
        file_input += extension
    return file_input

def resolve_password_file(provided: str | None = None) -> str:
    """
    Returns a normalized password file path.
    If not provided, retrieves the default from global settings.
    """
    if provided:
        return normalize_filepath(provided, '.ini')
    settings = get_global_settings()
    default = settings.get('password_filepath', 'password.ini')
    return normalize_filepath(default, '.ini')

def resolve_vault_file(file_input: str) -> str:
    """
    Returns a normalized vault file path ensuring the proper vault extension.
    """
    return normalize_filepath(file_input, '.btl')

def read_vault(vault_file: str, password_file: str) -> dict:
    """
    Reads and decrypts the vault file, returning its JSON content as a dictionary.
    """
    with open(vault_file, "rb") as f:
        ciphertext = f.read()
    decrypted = decrypt_vault(ciphertext, password_file)
    return json.loads(decrypted.decode('utf-8'))

def write_vault(vault_file: str, vault_data: dict, password_file: str) -> None:
    """
    Encrypts and writes the vault data back to the vault file.
    """
    data = json.dumps(vault_data).encode('utf-8')
    settings = get_global_settings()
    ciphertext = encrypt_vault(data, password_file)
    with open(vault_file, "wb") as f:
        f.write(ciphertext)

def create_vault(vault_file: str, password_file: str) -> None:
    """
    Creates a new vault file with an empty JSON object.
    Raises an error if the vault file already exists.
    """
    if os.path.exists(vault_file):
        raise FileExistsError(f"Vault '{vault_file}' already exists.")
    empty_vault = {}
    data = json.dumps(empty_vault).encode('utf-8')
    ciphertext = encrypt_vault(data, password_file)
    with open(vault_file, "wb") as f:
        f.write(ciphertext)
