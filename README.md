# Known Firmware

Runs on Raspberry Pi Pico 2 W. Listens for DNS queries from your network, logs them, and forwards them to a real DNS server.

## Files

- `main.py` — entry point, hardware control
- `lib/` — supporting modules

## Flash to Pico

1. Install MicroPython on the Pico
2. Copy `main.py` and the `lib/` folder to the device

More info in the docs repo.