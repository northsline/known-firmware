"""
Known - USB WebSerial provisioning

During first-time setup the device is plugged into a PC over Micro USB. The
hosted PWA opens a WebSerial connection (USB CDC/ACM, 115200 baud) and speaks a
line-delimited JSON protocol with this module:

    {"cmd":"identify"}
        -> {"status":"ok","code":"KNOWN-ABCD-1234","device_id":"..."}

    {"cmd":"provision","ssid":"HomeWiFi","pass":"hunter2","code":"KNOWN-ABCD-1234"}
        -> {"status":"ok"}  (Wi-Fi creds saved to /config.json)
        -> {"status":"error","reason":"..."}

Config lives on the Pico's internal flash filesystem at /config.json. There is
no MicroSD dependency in Known. The per-device fields (sticker_code,
device_secret, device_id) are injected at manufacturing time; provisioning adds
the user's Wi-Fi credentials to the same file.

WebSerial is a Chrome/Edge-only browser API; other browsers cannot run setup.
"""

import sys
import json

CONFIG_PATH = "/config.json"

# KNOWN-XXXX-XXXX, segments [A-Z0-9]. MicroPython has no `re` guarantees on the
# Pico build we target, so validate by hand.
_ALPHANUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _valid_code(code):
    if not isinstance(code, str):
        return False
    parts = code.split("-")
    if len(parts) != 3:
        return False
    prefix, a, b = parts
    if prefix != "KNOWN":
        return False
    if len(a) != 4 or len(b) != 4:
        return False
    for ch in a + b:
        if ch not in _ALPHANUM:
            return False
    return True


def load_config():
    """Read /config.json and return it as a dict, or {} if missing/unreadable."""
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_config(data):
    """Write the given dict to /config.json as JSON."""
    with open(CONFIG_PATH, "w") as f:
        json.dump(data, f)


def is_provisioned():
    """True once Wi-Fi credentials have been written to the config."""
    cfg = load_config()
    return bool(cfg.get("ssid")) and "pass" in cfg


def _send(obj):
    """Emit one JSON response line over the serial link (stdout)."""
    sys.stdout.write(json.dumps(obj))
    sys.stdout.write("\n")


def _handle(line):
    """Process one inbound JSON command line. Returns True once provisioned."""
    try:
        msg = json.loads(line)
    except ValueError:
        _send({"status": "error", "reason": "bad_json"})
        return False

    cmd = msg.get("cmd")

    if cmd == "identify":
        cfg = load_config()
        _send({
            "status": "ok",
            "code": cfg.get("sticker_code"),
            "device_id": cfg.get("device_id"),
        })
        return False

    if cmd == "provision":
        ssid = msg.get("ssid")
        password = msg.get("pass")
        code = msg.get("code")

        if not ssid or password is None:
            _send({"status": "error", "reason": "missing_wifi"})
            return False
        if not _valid_code(code):
            _send({"status": "error", "reason": "bad_code"})
            return False

        cfg = load_config()
        # Manufacturing injects the sticker code; reject a mismatch if present.
        existing = cfg.get("sticker_code")
        if existing and existing != code:
            _send({"status": "error", "reason": "code_mismatch"})
            return False

        cfg["sticker_code"] = code
        cfg["ssid"] = ssid
        cfg["pass"] = password
        try:
            save_config(cfg)
        except OSError as e:
            _send({"status": "error", "reason": "write_failed:%s" % e})
            return False

        _send({"status": "ok"})
        return True

    _send({"status": "error", "reason": "unknown_cmd"})
    return False


def enter_provisioning_mode():
    """
    Wait on serial input, processing JSON commands until the device is
    provisioned (Wi-Fi credentials saved). Returns when setup is complete so the
    caller can reboot or continue into normal operation.
    """
    print("Entering provisioning mode. Waiting for USB setup...")
    while True:
        line = sys.stdin.readline()
        if not line:
            continue
        line = line.strip()
        if not line:
            continue
        if _handle(line):
            print("Provisioning complete.")
            return
