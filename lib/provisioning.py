"""
Known - USB WebSerial provisioning

Line-delimited JSON over USB CDC (115200 baud). See the onboarding PWA for the
host side of this protocol.
"""

import sys
import json
import time

CONFIG_PATH = "/config.json"

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
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_config(data):
    with open(CONFIG_PATH, "w") as f:
        json.dump(data, f)


def is_provisioned():
    cfg = load_config()
    return bool(cfg.get("ssid")) and "pass" in cfg


def _send(obj):
    print(json.dumps(obj))


def _clean_line(line):
    if not line:
        return ""
    line = line.strip("\r\n\x00")
    if line and line[0] == "\ufeff":
        line = line[1:]
    return line.strip()


def _handle(line):
    line = _clean_line(line)
    if not line:
        return False
    if line[0] != "{":
        return False

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
    print("Entering provisioning mode. Waiting for USB setup...")
    _send({"status": "ready"})

    poll = None
    try:
        import uselect

        poll = uselect.poll()
        poll.register(sys.stdin, uselect.POLLIN)
    except Exception:
        poll = None

    buf = ""
    last_ready = time.ticks_ms()

    while True:
        now = time.ticks_ms()
        if time.ticks_diff(now, last_ready) > 2000:
            _send({"status": "ready"})
            last_ready = now

        ch = None
        if poll is not None:
            if poll.poll(0):
                try:
                    ch = sys.stdin.read(1)
                except Exception:
                    ch = None
        else:
            try:
                ch = sys.stdin.read(1)
            except Exception:
                ch = None

        if not ch:
            time.sleep_ms(10)
            continue

        if ch in ("\n", "\r"):
            if buf:
                if _handle(buf):
                    print("Provisioning complete.")
                    return
                buf = ""
            continue

        buf += ch
