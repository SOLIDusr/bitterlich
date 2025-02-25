import json
import pathlib
import os
import click
from .crypto.enc import encrypt_vault, decrypt_vault
from .crypto.generate import generate_single_password
from .settings import get_global_settings

def get_password_file(provided: str | None) -> str:
    """Return the password file to use – either the provided one or the default from global settings."""
    if provided:
        return provided if provided.endswith('.ini') else provided + '.ini'
    settings = get_global_settings()
    default = settings.get('password_filepath', 'password.ini')
    return default if default.endswith('.ini') else default + '.ini'

@click.group()
def cli():
    """A CLI vault tool for encrypted JSON storage."""
    pass

@cli.command()
@click.option('-f', '--filename', prompt='Filename', type=click.Path(dir_okay=False, writable=True), required=True)
@click.option('-p', '--password', help='Password file path', default=None)
@click.option('-v', '--verbose', is_flag=True)
def create(filename, password, verbose):
    """Create a new vault (an empty JSON object) encrypted with keys from the password file."""
    vault_path = pathlib.Path(filename)
    if vault_path.suffix != ".btl":
        vault_path = vault_path.with_suffix('.btl')
    if os.path.exists(vault_path):
        click.echo(f"Vault '{vault_path}' already exists.")
        return

    vault_data = {}  # starting with an empty vault
    json_data = json.dumps(vault_data).encode('utf-8')
    pw_file = get_password_file(password)
    encrypted = encrypt_vault(json_data, pw_file)
    with open(vault_path, "wb") as f:
        f.write(encrypted)
    click.echo(f"Vault '{vault_path}' created successfully.")

@cli.command()
@click.option('-f', '--filename', prompt='Filename', type=click.Path(exists=True, dir_okay=False, readable=True, writable=True), required=True, help='Path to the vault file')
@click.option('-p', '--password', help='Password file path', default=None, help='Path to the password file')
@click.option('-k', '--key', prompt='Key', required=True, help='Key to add or update')
@click.option('-v', '--value', prompt='Value', required=True, hide_input=False, help='Value to store in the vault')
@click.option('--verbose', is_flag=True, help='Print verbose output')
def add(filename, password, key, value, verbose):
    """Add or update a key-value pair in the vault.
    
    If the provided value can be converted to an integer between 4 and 26, a new random password of that length is generated.
    """
    vault_path = pathlib.Path(filename)
    pw_file = get_password_file(password)
    try:
        with open(vault_path, "rb") as f:
            ciphertext = f.read()
        decrypted = decrypt_vault(ciphertext, pw_file)
        vault = json.loads(decrypted.decode('utf-8'))
    except Exception as e:
        click.echo("Failed to decrypt vault. Check your password file.")
        return

    try:
        length = int(value)
        if 4 <= length <= 26:
            value = generate_single_password(length)
    except ValueError:
        pass

    vault[key] = value
    new_data = json.dumps(vault).encode('utf-8')
    new_ciphertext = encrypt_vault(new_data, pw_file)
    with open(vault_path, "wb") as f:
        f.write(new_ciphertext)
    click.echo(f"Key '{key}' added to vault.")

@cli.command(name='list')
@click.option('-f', '--filename', prompt='Filename', type=click.Path(exists=True, dir_okay=False, readable=True), required=True, help='Path to the vault file')
@click.option('-p', '--password', help='Password file path', default=None, help='Path to the password file')
def list_keys(filename, password):
    """List all keys stored in the vault."""
    vault_path = pathlib.Path(filename)
    pw_file = get_password_file(password)
    try:
        with open(vault_path, "rb") as f:
            ciphertext = f.read()
        decrypted = decrypt_vault(ciphertext, pw_file)
        vault = json.loads(decrypted.decode('utf-8'))
    except Exception as e:
        click.echo("Failed to decrypt vault. Check your password file.")
        return

    if not vault:
        click.echo("Vault is empty.")
    else:
        click.echo("Vault keys:")
        for k in vault.keys():
            click.echo(f" - {k}")

@cli.command()
@click.option('-f', '--filename', prompt='Filename', type=click.Path(exists=True, dir_okay=False, readable=True), required=True)
@click.option('-p', '--password', help='Password file path', default=None)
@click.option('-k', '--key', prompt='Key', required=True)
@click.option('-c', '--clipboard', is_flag=True, default=False)
def get(filename, password, key, clipboard):
    """Retrieve and display (or copy) a value from the vault."""
    vault_path = pathlib.Path(filename)
    pw_file = get_password_file(password)
    try:
        with open(vault_path, "rb") as f:
            ciphertext = f.read()
        decrypted = decrypt_vault(ciphertext, pw_file)
        vault = json.loads(decrypted.decode('utf-8'))
    except Exception as e:
        click.echo("Failed to decrypt vault. Check your password file.")
        return

    if key not in vault:
        click.echo("Key not found in vault.")
        return

    value = vault[key]
    if clipboard:
        try:
            import pyperclip
            pyperclip.copy(value)
            click.echo("Value copied to clipboard.")
        except ImportError:
            click.echo("pyperclip is not installed. Cannot copy to clipboard.")
    else:
        click.echo(f"Value for '{key}': {value}")

@cli.command()
@click.option('-f', '--filename', prompt='Filename', type=click.Path(exists=True, dir_okay=False, readable=True, writable=True), required=True)
@click.option('-p', '--password', help='Password file path', required=True)
@click.option('-k', '--key', prompt='Key', required=True)
def remove(filename, password, key):
    """Remove a key-value pair from the vault."""
    vault_path = pathlib.Path(filename)
    pw_file = get_password_file(password)
    try:
        with open(vault_path, "rb") as f:
            ciphertext = f.read()
        decrypted = decrypt_vault(ciphertext, pw_file)
        vault = json.loads(decrypted.decode('utf-8'))
    except Exception as e:
        click.echo("Failed to decrypt vault. Check your password file.")
        return

    if key not in vault:
        click.echo("Key not found in vault.")
        return

    del vault[key]
    new_data = json.dumps(vault).encode('utf-8')
    new_ciphertext = encrypt_vault(new_data, pw_file)
    with open(vault_path, "wb") as f:
        f.write(new_ciphertext)
    click.echo(f"Key '{key}' removed from vault.")

def entry():
    """Entry point function for CLI integration."""
    cli()