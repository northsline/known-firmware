# Known Hardware Pinout
**Version:** Phase 1 Breadboard Prototype  
**Date:** 2026-05-31  
**Author:** Northsline

## Overview
Known Phase 1 is built on a Raspberry Pi Pico 2 W with three peripherals:
- SSD1306 OLED display (I2C)
- Passive buzzer (PWM)
- MicroSD card adapter (SPI)

All components run at 3.3V. USB port faces Row 1.

---

## Pin Assignments

| Pico Pin | GPIO | Function | Destination |
|----------|------|----------|-------------|
| 1 | — | VBUS | — |
| 3 | GND | GND | Blue rail |
| 5 | 3V3 | Power | Red rail |
| 2 | GP1 | — | — |
| 4 | GP2 | I2C1 SDA | OLED SDA |
| 5 | GP3 | I2C1 SCL | OLED SCL |
| 15 | GP15 | PWM7 B | Buzzer (+) |
| 16 | GP16 | SPI0 RX | MicroSD MISO |
| 17 | GP17 | SPI0 CSn | MicroSD CS |
| 18 | GP18 | SPI0 SCK | MicroSD SCK |
| 19 | GP19 | SPI0 TX | MicroSD MOSI |
| 36 | 3V3 | Power | — |
| 38 | GND | GND | — |

---

## Peripherals

### OLED Display (I2C1)
| Signal | Breadboard | Pico Pin |
|--------|-----------|----------|
| GND | A25 → Blue rail | 3 (GND) |
| VCC | A26 → Red rail | 5 (3V3) |
| SCL | A27 → B5 | 5 (GP3) |
| SDA | A28 → B4 | 4 (GP2) |

**Library:** `ssd1306` or `framebuf` via MicroPython.

### Passive Buzzer (PWM)
| Signal | Breadboard | Pico Pin |
|--------|-----------|----------|
| (+) | A35 → B20 | 15 (GP15) |
| GND | A38 → Blue rail | 3 (GND) |

**Library:** `machine.PWM`. Frequency ~2000Hz for alerts.

### MicroSD Adapter (SPI0)
| Signal | Breadboard | Pico Pin |
|--------|-----------|----------|
| GND | J25 → Blue rail | 3 (GND) |
| VCC | J26 → I1 (VBUS) | 1 (VBUS) |
| MISO | J27 → I20 | 16 (GP16) |
| MOSI | J28 → I16 | 19 (GP19) |
| SCK | J29 → I17 | 18 (GP18) |
| CS | J30 → I19 | 17 (GP17) |

**Library:** `sdcard` (MicroPython built-in) or `os.mount`.

---

## Power
- **Main rail:** 3.3V from Pico pin 5 (3V3 OUT) → Red rail
- **Ground:** Pico pin 3 (GND) → Blue rail
- **MicroSD VCC:** VBUS (5V) via pin 1. Adapter has onboard regulator.

---

## Notes
- I2C1 (GP2/GP3) is the default I2C bus on Pico 2 W.
- SPI0 (GP16-GP19) is the default SPI bus.
- GP15 is PWM-capable. Buzzer uses `PWM.duty_u16()` for tone generation.
- All pins are 3.3V logic. Do not connect 5V signals directly to GPIO.
