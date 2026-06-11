# Known Firmware Modules

Supporting code for the Pico firmware.

- `dns_monitor.py` — listens for DNS queries, forwards them, logs them
- `http_server.py` — serves the local HTTP API for the dashboard
- `devices.py` — tracks devices seen on the network
- `provisioning.py` — handles WiFi setup over USB serial
- `ssd1306.py` — OLED display driver