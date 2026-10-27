import fnmatch
import json
import os


def load_config(file="config.json"):
    try:
        with open(file) as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"[!] Config file not found: {file}")
        return None
    except json.JSONDecodeError as e:
        print(f"[!] Config file has a mistake: {e}")
        return None

    for item in config.get("monitored_folders", []):
        item["path"] = os.path.abspath(os.path.expanduser(item["path"]))
    return config


def should_ignore(path, config):
    name = os.path.basename(path)
    for pattern in config.get("ignore_patterns", []):
        if fnmatch.fnmatch(name, pattern):
            return True
    parts = path.replace("\\", "/").split("/")
    for folder in config.get("ignore_folders", []):
        if folder in parts:
            return True
    return False