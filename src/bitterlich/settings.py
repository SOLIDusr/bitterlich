import json
import os
import sys


if sys.platform == "win32":
    GLOBAL_SETTINGS_FILE = os.path.join(os.getenv('APPDATA'), 'bitterlich', 'config.json')
else:
    GLOBAL_SETTINGS_FILE = os.path.expanduser('~/.config/bitterlich/config.json')

GLOBAL_SETTINGS_TEMPLATE = {
    "password_filepath": "./password.ini", 
    "password_iteration": 100000,
    "password_rotation": True
}

def init_global_settings():
    if not os.path.exists(GLOBAL_SETTINGS_FILE):
        os.makedirs(os.path.dirname(GLOBAL_SETTINGS_FILE), exist_ok=True)
        with open(GLOBAL_SETTINGS_FILE, 'w') as f:
            json.dump(GLOBAL_SETTINGS_TEMPLATE, f, indent=4)
        
def get_global_settings() -> dict:
    if os.path.exists(GLOBAL_SETTINGS_FILE):
        with open(GLOBAL_SETTINGS_FILE, 'r') as f:
            return json.load(f)
    return {}


def load_global_settings() -> bool:
    if os.path.exists(GLOBAL_SETTINGS_FILE):
        os.system(f"start {GLOBAL_SETTINGS_FILE}")
        return True
    return False


def save_global_settings(settings):
    with open(GLOBAL_SETTINGS_FILE, 'w') as f:
        json.dump(settings, f, indent=4)

