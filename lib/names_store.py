# persist device names to flash so they survive reboots.
# separate file from config.json: renaming must not risk wifi creds.
import json

NAMES_PATH = "/names.json"


def load_names():
    # returns {ip: name} or {} if missing/corrupt
    try:
        with open(NAMES_PATH) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {}


def save_names(names):
    # write-then-verify: if the verify read fails, the old file is untouched.
    try:
        with open(NAMES_PATH, "w") as f:
            json.dump(names, f)
        # verify the write by reading back
        with open(NAMES_PATH) as f:
            json.load(f)
        return True
    except (OSError, ValueError):
        return False