import os
import click
from .vault import (
    resolve_password_file,
    resolve_vault_file,
    create_vault,
    read_vault,
    write_vault)
from .crypto.generate import generate_single_password
from .settings import get_global_settings, load_global_settings, init_global_settings
from .utils.loggerHandler import LoggerInstance


@click.group()
def cli():
    """A CLI vault tool for encrypted JSON storage."""
    pass

@cli.command()
@click.option('-f', '--filename', prompt='Vault filename', type=click.Path(writable=True, dir_okay=False), required=True)
@click.option('-p', '--password', default=None, help='Password file path (optional)')
@click.option('-v', '--verbose', is_flag=True)
def create(filename, password, verbose):
    """Create a new vault with an empty JSON object."""
    logger = LoggerInstance(verbose=verbose)
    vault_file = resolve_vault_file(filename)
    password_file = resolve_password_file(password)
    logger.info(f"Creating vault at {vault_file}")
    if os.path.exists(vault_file):
        logger.error(f"Vault '{vault_file}' already exists.", "cli")
        click.echo(f"Vault '{vault_file}' already exists.")
        return
    try:
        create_vault(vault_file, password_file)
        logger.info(f"Vault '{vault_file}' created successfully.")
        click.echo(f"Vault '{vault_file}' created successfully.")
    except Exception as e:
        logger.error(f"Error creating vault: {e}", "cli")
        click.echo(f"Error creating vault: {e}")


@cli.command()
@click.option('-f', '--filename', prompt='Vault filename', type=click.Path(exists=True, dir_okay=False, readable=True, writable=True), required=True, help='Path to the vault file')
@click.option('-p', '--password', default=None, help='Password file path (optional)')
@click.option('-k', '--key', prompt='Key', required=True, help='Key to add or update')
@click.option('-v', '--value', prompt='Value', required=True, help='Value to store in the vault')
@click.option('--verbose', is_flag=True, help='Enable verbose output')
def add(filename, password, key, value, verbose):
    """Add or update a key-value pair in the vault."""
    logger = LoggerInstance(verbose=verbose)
    vault_file = resolve_vault_file(filename)
    password_file = resolve_password_file(password)
    try:
        vault_data = read_vault(vault_file, password_file)
    except Exception as e:
        logger.error(f"Failed to read vault: {e}", "cli")
        click.echo("Failed to decrypt vault. Check your password file.")
        return

    vault_data[key] = value
    settings = get_global_settings()
    try:
        write_vault(vault_file, vault_data, password_file)
        logger.info("Key added/updated successfully.", "cli")
        click.echo("Key added/updated successfully.")
    except Exception as e:
        logger.error(f"Failed to write vault: {e}", "cli")
        click.echo("Failed to update vault. Check your password file or settings.")
    
@cli.command("generate-password")
@click.option('-l', '--length', prompt='Password length (4-26)', type=click.IntRange(4, 26), required=True, help='Length of the generated password')
def generate_password_cmd(length):
    """Generate a secure random password of a given length."""
    new_password = generate_single_password(length)
    click.echo(f"Generated password: {new_password}")

@cli.command(name='list')
@click.option('-f', '--filename', prompt='Vault filename', type=click.Path(exists=True, dir_okay=False, readable=True), required=True, help='Path to the vault file')
@click.option('-p', '--password', default=None, help='Password file path (optional)')
@click.option('--verbose', is_flag=True, help='Enable verbose output')
def list_keys(filename, password, verbose):
    """List all keys stored in the vault."""
    logger = LoggerInstance(verbose=verbose)
    vault_file = resolve_vault_file(filename)
    password_file = resolve_password_file(password)
    try:
        vault_data = read_vault(vault_file, password_file)
    except Exception as e:
        logger.error(f"Failed to read vault: {e}", "cli")
        click.echo("Failed to decrypt vault. Check your password file.")
        return

    if not vault_data:
        logger.info("Vault is empty.", "cli")
        click.echo("Vault is empty.")
    else:
        logger.info("Listing keys in the vault.", "cli")
        click.echo("Vault keys:")
        for key in vault_data.keys():
            click.echo(f" - {key}")

@cli.command()
@click.option('-f', '--filename', prompt='Vault filename', type=click.Path(exists=True, dir_okay=False, readable=True, writable=True), required=True)
@click.option('-p', '--password', default=None, help='Password file path (optional)')
@click.option('-k', '--key', prompt='Key', required=True)
@click.option('-c', '--clipboard', is_flag=True, default=False, help='Copy the value to clipboard')
@click.option('--verbose', is_flag=True, help='Enable verbose output')
def get(filename, password, key, clipboard, verbose):
    """Retrieve and display (or copy) a value from the vault."""
    logger = LoggerInstance(verbose=verbose)
    vault_file = resolve_vault_file(filename)
    password_file = resolve_password_file(password)
    try:
        vault_data = read_vault(vault_file, password_file)
    except Exception as e:
        logger.error(f"Failed to read vault: {e}", "cli")
        click.echo("Failed to decrypt vault. Check your password file.")
        return

    if key not in vault_data:
        logger.info("Key not found in vault.", "cli")
        click.echo("Key not found in vault.")
        return

    value = vault_data[key]
    if clipboard:
        try:
            import pyperclip
            pyperclip.copy(value)
            logger.info("Value copied to clipboard.", "cli")
            click.echo("Value copied to clipboard.")
        except ImportError:
            logger.error("pyperclip is not installed. Cannot copy to clipboard.", "cli")
            click.echo("pyperclip is not installed. Cannot copy to clipboard.")
    else:
        logger.info(f"Value for '{key}': {value}", "cli")
        click.echo(f"Value for '{key}': {value}")

@cli.command()
@click.option('-f', '--filename', prompt='Vault filename', type=click.Path(exists=True, dir_okay=False, readable=True, writable=True), required=True)
@click.option('-p', '--password', default=None, help='Password file path (optional)')
@click.option('-k', '--key', prompt='Key', required=True)
@click.option('--verbose', is_flag=True, help='Enable verbose output')
def remove(filename, password, key, verbose):
    """Remove a key-value pair from the vault."""
    vault_file = resolve_vault_file(filename)
    password_file = resolve_password_file(password)
    try:
        vault_data = read_vault(vault_file, password_file)
    except Exception as e:
        click.echo("Failed to decrypt vault. Check your password file.")
        return

    if key not in vault_data:
        click.echo("Key not found in vault.")
        return

    del vault_data[key]
    try:
        write_vault(vault_file, vault_data, password_file)
        click.echo(f"Key '{key}' removed from vault.")
    except Exception as e:
        click.echo("Failed to update vault. Check your password file or settings.")

@cli.command()
def settings():
    """Display global settings."""
    click.echo(load_global_settings())

def entry():
    init_global_settings()
    cli()

if __name__ == '__main__':
    entry()
