import json
import os
from .crypto.enc import decrypt, encrypt
import subprocess
import sys


GLOBAL_SETTINGS_FILE = 'src\\bitterlich\\config\\settings.json'
def get_global_settings() -> dict:
    if os.path.exists(GLOBAL_SETTINGS_FILE):
        with open(GLOBAL_SETTINGS_FILE, 'r') as f:
            return json.load(f)
    return {}


def load_global_settings() -> bool:
    if os.path.exists(GLOBAL_SETTINGS_FILE):
        if sys.platform == "win32":
            os.startfile(GLOBAL_SETTINGS_FILE)
        elif sys.platform == "darwin":
            subprocess.run(["open", GLOBAL_SETTINGS_FILE])
        else:
            subprocess.run(["xdg-open", GLOBAL_SETTINGS_FILE])
        return True
    return False


def save_global_settings(settings):
    with open(GLOBAL_SETTINGS_FILE, 'w') as f:
        json.dump(settings, f, indent=4)

