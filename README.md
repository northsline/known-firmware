# Known Firmware

Runs on Raspberry Pi Pico 2 W. Listens for DNS queries from your network, logs
them, forwards them to a real DNS server, and serves the logs over HTTP.

## Files

- `main.py`. Entry point, hardware control, main loop, OLED view
- `lib/`. Supporting modules (see lib/README.md for details)

## Flash to Pico

1. Install MicroPython on the Pico (UF2 from micropython.org)
2. Copy `main.py` and the `lib/` folder to the device

For automated manufacturing (key generation, flashing, key burning, sticker
printing), use `backend/flash_known.py`. It does all of this in one command.

## Boot paths

**Unprovisioned** (no `/config.json` with ssid+pass):
- OLED shows setup hints briefly
- Enters USB serial provisioning mode immediately (serial-first, no I2C delay)
- PWA verifies device via cryptographic challenge-response (ECDSA P-256)
- Writes WiFi credentials, reboots

**Provisioned:**
- OLED + Wi-Fi + DNS :53 + HTTP :8080 at known.local
- Main loop: poll DNS packets, poll HTTP connections, render OLED, reconnect WiFi every 30s if dropped

## HTTP API (port 8080)

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | `{status: ok}` |
| GET | /stats | Query count, device count, unique domains, flagged, period start, `pico_mac` (the Known device's own MAC for OUI lookup) |
| GET | /devices | Wrapper `{pico_mac, devices: [...]}`. Per-device list with IP, name, query_count, first/last seen. Per-device `mac` is best-effort (None on RP2350). |
| GET | /audit/weekly | Recent DNS log entries (source, domain, timestamp) |
| GET | /debug | Raw internal state (DNS count, device dump, last error) |
| GET | /token | Device token hint (first 8 chars) |
| GET | /allowlist | List allowlist entries |
| PUT | /allowlist | Add entry `{pattern: "..."}` → `{status: ok, id: "..."}` |
| DELETE | /allowlist/\<id\> | Remove entry |

CORS `*`. No auth (LAN access only). Consumed by the dashboard and the `known` CLI.

## OLED display

128x64 SSD1306 over I2C (GP2 SDA, GP3 SCL). Cycles between screens:
- **Online:** query count + data / WiFi % + uptime
- **Connecting:** SSID + "connecting"
- **WiFi lost:** pulsing "WiFi Lost / Retrying..."
- **Restarting:** spinner
- **Unprovisioned:** setup hints ("Plug into PC / Open known.local")

Heartbeat dot blinks in the top-right corner on every screen.

## Router Compatibility

The Pico 2 W uses 2.4 GHz Wi-Fi only (no 5 GHz support) and acts as a passive
DNS forwarder on UDP/53. Three router settings commonly break this. If devices
on your network can't reach the Pico or DNS queries don't forward, check each one.

### 1. SSID Separation (band isolation)

Some routers create separate subnets for 2.4 GHz and 5 GHz bands even when both
share the same Wi-Fi name. The Pico connects on 2.4 GHz and your devices may
connect on 5 GHz. They land on different subnets and can't talk to each other.

**Symptom:** Pico gets an IP like `192.168.5.x` while your laptop gets
`192.168.1.x`. `nslookup` from the laptop times out.

**Fix:** Disable SSID separation (also called "Band Steering" or "Smart Connect"
on some routers). Both bands should use one SSID and one subnet. On Vodafone
Power Station this setting is called "Separazione SSID". Turn it off.

### 2. DNS Hijacking / "Secure DNS"

Many ISP routers intercept all UDP/53 traffic and redirect it to the ISP's own
DNS resolver. Queries that should reach the Pico get silently swallowed by the
router.

**Symptom:** T4 in the diagnostic shows `queries=0` even though devices are on
the same subnet and `nslookup` appears to "work" (it gets answers from the ISP's
resolver, not from the Pico).

**Fix:** Disable "DNS Sicuro" (Vodafone), "Secure DNS", "DNS Security", "DNS
Hijacking Protection", or similarly-named features. Set the router's DNS to
manual/static mode if available. Some routers also have a per-device "automatic
DNS" toggle. Disable it for devices that should query the Pico.

### 3. AP / Client Isolation

Some routers block wireless clients from talking to each other, even on the same
SSID. This is common on guest networks but sometimes enabled by default on the
main network too.

**Symptom:** Devices are on the same subnet but can't ping each other. T2 echo
server shows no incoming packets.

**Fix:** Disable "AP Isolation", "Client Isolation", "Wireless Isolation", or
"Intra-BSS Blocking". If the Pico is on a guest network, move it to the main
network.

### Diagnostic Tool

The firmware includes `lib/dns_diag.py`. It runs four tests on the Pico:

| Test | What it checks |
|------|---------------|
| T1   | Can the Pico receive UDP/53 at all? |
| T2   | Echo server: run `nslookup` from a PC, see if it arrives |
| T3   | Can the Pico send upstream DNS to 1.1.1.1? |
| T4   | End-to-end forwarder: query comes in, gets forwarded, answer comes back |

Run it with:

    mpremote connect /dev/ttyACM0 exec "from lib.dns_diag import run; run(my_ip='192.168.1.X')"

Replace `192.168.1.X` with the Pico's actual IP. The tool prints results and
tells you which test failed. Match the failure to one of the three router
issues above.