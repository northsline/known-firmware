# Heron Firmware Modules

Supporting code for the Pico firmware. All run on MicroPython (RP2 port).

## Modules

- `provisioning.py`. USB WebSerial provisioning. Line-delimited JSON over
  CDC/ACM at 115200 baud. Commands: `identify` (return serial + has_keys),
  `challenge` (sign nonce with private key, return cert + signature),
  `scan` (WiFi network scan), `router_info` (BSSID + IP), `provision`
  (write WiFi credentials to /config.json). Emits `ready` beacon every ~2s.
- `ecdsa.py`. Pure-MicroPython ECDSA P-256 signing with SHA-256 and DER
  encoding. ~150 lines, ~3s per signature on RP2350. No external deps.
- `otp_keys.py`. Device key storage. Selects between RP2350 OTP and a
  flash file at /keys.bin at import time. Layout: private key (32B),
  public key (65B), serial (8B), certificate (148B padded), magic
  byte. Total: 254 bytes, all within 8KB OTP. Functions: `has_keys()`,
  `get_private_key_int()`, `get_serial()`, `get_certificate()`,
  `burn_keys()`. The burn is atomic-by-construction: data fields
  are written and read-back-verified first, the magic byte (the
  commit signal) is written last. If read-back fails, the magic
  byte is never set and the device is still recoverable.

  As of 2026-07-11: stock MicroPython (v1.28.0, master) has no
  `machine.OTP` class. The OTP backend is a custom C module that
  does not exist yet; see the `rp2350-otp-c-module` skill. Until
  then, every device lands on the flash backend and
  `flash_known.py` refuses to ship (the guard is the production
  safety net).
- `dns_monitor.py`. UDP DNS server on port 53. Receives queries, forwards
  to 1.1.1.1, logs them. Non-blocking, capped at 150 entries (ring buffer in
  RAM, zero flash writes). In-flight tracking with 8-slot cap and 3s TTL.
- `http_server.py`. Non-blocking HTTP server on port 8080. Raw sockets, no
  threads. Routes: /health, /stats, /devices, /audit/weekly, /debug, /token,
  /allowlist (GET/PUT/DELETE). CORS `*`. MemoryError-safe serialization.
- `devices.py`. DeviceTracker. Keys LAN devices by source IP. Best-effort
  reverse DNS for friendly names, fallback to "Device #N". Tracks query_count,
  first_seen, last_seen. Stubs for trust_level and flagged_count (heuristics
  not implemented yet).
- `dns_diag.py`. Network diagnostic tool. Four tests (T1-T4) for debugging
  DNS forwarding issues: bind test, echo server, upstream test, end-to-end
  forwarder. Run via mpremote. See firmware README for usage.
- `ssd1306.py`. SSD1306 OLED display driver (128x64, I2C).