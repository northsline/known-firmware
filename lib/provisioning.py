# usb webserial provisioning — line-delimited json over usb cdc (115200 baud).
# see the onboarding pwa for the host side.

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


def _rand_hex(n=32):
    # Random hex string using machine.rng() — available on RP2 port.
    # Falls back to ubinascii if rng is missing (should not happen on Pico 2 W).
    try:
        from machine import rng
        return "".join("{:02x}".format(rng()) for _ in range(n // 2 + 1))[:n]
    except Exception:
        import ubinascii
        import os
        return ubinascii.hexlify(os.urandom(n // 2)).decode()[:n]


def ensure_device_token():
    """Generate and persist a random device token if one does not exist yet.
    Called once on first boot. The token is stored in config.json and can
    later be used for API authentication without a firmware reflash."""
    cfg = load_config()
    if cfg.get("device_token"):
        return cfg["device_token"]
    token = _rand_hex(32)
    cfg["device_token"] = token
    try:
        save_config(cfg)
        print("Device token generated:", token[:8] + "...")
    except OSError as e:
        print("Failed to save device token:", e)
        return None
    return token


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

    if cmd == "scan":
        # Return available WiFi networks as JSON so the PWA can show
        # a dropdown instead of asking the user to type the SSID.
        try:
            import network
            wlan = network.WLAN(network.STA_IF)
            wlan.active(True)
            nets = wlan.scan()
            # Each result: (ssid, bssid, channel, rssi, authmode, hidden)
            # Cap at 15 to keep the payload small.
            out = []
            for n in nets[:15]:
                try:
                    ssid = n[0].decode("utf-8", "ignore") if n[0] else ""
                except Exception:
                    ssid = ""
                bssid = ":".join("{:02x}".format(b) for b in n[1]) if n[1] else ""
                out.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "channel": n[2] if len(n) > 2 else 0,
                    "rssi": n[3] if len(n) > 3 else 0,
                    "hidden": bool(n[5]) if len(n) > 5 else False,
                })
            _send({"status": "ok", "networks": out})
        except Exception as e:
            _send({"status": "error", "reason": "scan_failed:%s" % e})
        return False

    if cmd == "router_info":
        # Return the connected AP's BSSID and the Pico's IP address.
        # Called by the PWA after provisioning to identify the router
        # vendor (OUI lookup on BSSID prefix) and show router-specific
        # setup instructions.
        try:
            import network
            wlan = network.WLAN(network.STA_IF)
            if not wlan.isconnected():
                # Freshly provisioned devices have not rebooted yet. Try to
                # connect using the saved config so the PWA can read the
                # AP's BSSID while still on USB.
                cfg = load_config()
                ssid = cfg.get("ssid")
                pwd = cfg.get("pass")
                if ssid and pwd is not None:
                    wlan.active(True)
                    wlan.connect(ssid, pwd)
                    start = time.time()
                    while not wlan.isconnected() and (time.time() - start) < 15:
                        time.sleep(0.5)
            if not wlan.isconnected():
                _send({"status": "error", "reason": "not_connected"})
                return False
            bssid = ":".join("{:02x}".format(b) for b in wlan.config("bssid"))
            ip = wlan.ifconfig()[0]
            _send({"status": "ok", "bssid": bssid, "ip": ip})
        except Exception as e:
            _send({"status": "error", "reason": "router_info_failed:%s" % e})
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
