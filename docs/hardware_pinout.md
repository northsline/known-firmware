# Known Hardware Pin Layout
Version: Phase 1 Breadboard Prototype

## Components

### Breadboard
- Left Side: C1 → C20
- Right Side: H1 → H20
- Working Area: A1 → J63

---

### Pico 2 W
> IMPORTANT: **Orientation:** USB port MUST face Row 1. Pin 1 = C1, Pin 40 = H1.

- Left Side Pins: C1-C20
- Right Side Pins: H1-H20

---

### OLED Display (I2C)

| Signal | Breadboard Pin |
|--------|----------------|
| GND    | A25            |
| VCC    | A26            |
| SCL    | A27            |
| SDA    | A28            |

---

### Passive Buzzer

| Signal       | Breadboard Pin |
|--------------|----------------|
| Signal (+)   | A35            |
| Ground (-)   | A38            |

---

### MicroSD Adapter (SPI)

| Signal | Breadboard Pin | Notes                  |
|--------|----------------|------------------------|
| GND    | J25            |                        |
| VCC    | J26            | 5V (VBUS) - Requires onboard LDO |
| MISO   | J27            |                        |
| MOSI   | J28            |                        |
| SCK    | J29            |                        |
| CS     | J30            |                        |

---

## Jumper Connections

### OLED Display

| From | To  | Function      |
|------|-----|---------------|
| B25  | B3  | GND           |
| B26  | I5  | 3V3 OUT       |
| B27  | B5  | I2C1 SCL (GP3)|
| B28  | B4  | I2C1 SDA (GP2)|

---

### Passive Buzzer

| From | To   | Function         |
|------|------|------------------|
| E35  | B20  | PWM7 B (GP15)    |
| E38  | I18  | GND              |

---

### MicroSD Adapter

| From | To   | Function        |
|------|------|-----------------|
| I25  | I3   | GND             |
| I26  | I1   | VBUS (5V)       |
| I27  | I20  | SPI0 RX (GP16)  |
| I28  | I16  | SPI0 TX (GP19)  |
| I29  | I17  | SPI0 SCK (GP18) |
| I30  | I19  | SPI0 CSn (GP17) |

---

## Project
**Known**  
Local DNS Privacy Monitoring Device

Phase 1 Prototype:
- Raspberry Pi Pico 2W
- OLED Status Display
- Passive Alert Buzzer
- MicroSD Logging Storage

Design Goal:  
Real-time local privacy monitoring with zero cloud dependency.