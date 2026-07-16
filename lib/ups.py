# pico ups b driver: ina219 current/power monitor at i2c addr 0x43.
# the ups sits on i2c bus 0 (gp6 sda / gp7 scl), separate from the oled
# which is on i2c bus 1 (gp2 sda / gp3 scl).
#
# waveshare pico ups b uses an ina219 with a 0.1 ohm shunt resistor.
# the onboard eta6003 handles charging and power path management; we
# only read the ina219 for voltage, current, and estimated charge level.
#
# register layout from the ina219 datasheet and waveshare demo code.
# calibration: 32v bus range, gain 8 (320mv shunt), 12-bit 32-sample avg.

import time

try:
    from machine import I2C, Pin
except ImportError:
    # cpython test fallback: no real i2c
    I2C = None
    Pin = None

# i2c bus: 0 (gp6/gp7). oled is on bus 1 (gp2/gp3). they are independent.
UPS_I2C_BUS = 0
UPS_I2C_ADDR = 0x43

# ina219 registers
_REG_CONFIG = 0x00
_REG_SHUNTVOLTAGE = 0x01
_REG_BUSVOLTAGE = 0x02
_REG_POWER = 0x03
_REG_CURRENT = 0x04
_REG_CALIBRATION = 0x05

# calibration constants (32v, 2a range, 0.1 ohm shunt)
_CAL_VALUE = 4096
_CURRENT_LSB_MA = 100  # 100 uA per bit = 0.1 ma per bit
_POWER_LSB_MW = 2     # 2 mW per bit

# config word: 32v range | gain 8 (320mv) | 12-bit 32-sample bus+shunt | continuous
_CONFIG_WORD = (0x01 << 13) | (0x03 << 11) | (0x0D << 7) | (0x0D << 3) | 0x07

# li-po voltage range for percent estimate. the waveshare demo uses
# (bus_voltage - 3.0) / 1.2 * 100, clamped 0..100. that maps 3.0v=0%, 4.2v=100%
# which is the standard 1s li-po discharge curve. good enough for a status
# indicator -- not a fuel gauge.
_BATT_MIN_V = 3.0
_BATT_MAX_V = 4.2


class UPS:
    # reads the ina219 on the pico ups b. all reads are best-effort: if i2c
    # fails the last heron values are kept and available() returns false.

    def __init__(self, i2c=None):
        self.i2c = i2c
        self._available = False
        self._bus_v = 0.0
        self._current_ma = 0.0
        self._power_mw = 0.0
        self._shunt_mv = 0.0
        self._last_read_ms = 0

        if i2c is None and I2C is not None:
            try:
                self.i2c = I2C(UPS_I2C_BUS, scl=Pin(7), sda=Pin(6), freq=400000)
            except Exception as e:
                print("UPS I2C init failed:", e)
                self.i2c = None

        if self.i2c is not None:
            self._configure()

    def _configure(self):
        try:
            self._write_reg(_REG_CALIBRATION, _CAL_VALUE)
            self._write_reg(_REG_CONFIG, _CONFIG_WORD)
            # re-write cal after config: some ina219 clones reset cal when
            # config changes. belt and suspenders.
            self._write_reg(_REG_CALIBRATION, _CAL_VALUE)
            self._available = True
            print("UPS INA219 configured at 0x%02x" % UPS_I2C_ADDR)
        except Exception as e:
            print("UPS INA219 config failed:", e)
            self._available = False

    def _read_reg(self, reg):
        data = self.i2c.readfrom_mem(UPS_I2C_ADDR, reg, 2)
        return (data[0] << 8) | data[1]

    def _write_reg(self, reg, value):
        hi = (value >> 8) & 0xFF
        lo = value & 0xFF
        self.i2c.writeto_mem(UPS_I2C_ADDR, reg, bytes([hi, lo]))

    @staticmethod
    def _to_signed(raw):
        if raw > 32767:
            raw -= 65536
        return raw

    def read(self):
        # read all registers in one pass. returns true on success.
        if not self.i2c:
            return False
        try:
            # re-write cal before reading current/power: sharp loads can
            # reset the ina219 cal register, making those reads garbage.
            self._write_reg(_REG_CALIBRATION, _CAL_VALUE)

            raw_shunt = self._read_reg(_REG_SHUNTVOLTAGE)
            raw_bus = self._read_reg(_REG_BUSVOLTAGE)
            raw_current = self._read_reg(_REG_CURRENT)
            raw_power = self._read_reg(_REG_POWER)

            self._shunt_mv = self._to_signed(raw_shunt) * 0.01
            # bus voltage register: bits [15:3] are the value, then *4 mv
            self._bus_v = ((raw_bus >> 3) * 4) * 0.001
            self._current_ma = self._to_signed(raw_current) * (_CURRENT_LSB_MA / 1000.0)
            self._power_mw = self._to_signed(raw_power) * _POWER_LSB_MW

            self._last_read_ms = time.ticks_ms() if hasattr(time, 'ticks_ms') else 0
            self._available = True
            return True
        except Exception as e:
            print("UPS read failed:", e)
            self._available = False
            return False

    @property
    def available(self):
        return self._available

    @property
    def bus_voltage(self):
        return self._bus_v

    @property
    def current_ma(self):
        return self._current_ma

    @property
    def power_mw(self):
        return self._power_mw

    @property
    def shunt_mv(self):
        return self._shunt_mv

    @property
    def battery_percent(self):
        # linear map from li-po voltage range. not precise, but good
        # enough for "is the battery healthy" status. clamped 0..100.
        pct = (self._bus_v - _BATT_MIN_V) / (_BATT_MAX_V - _BATT_MIN_V) * 100
        if pct < 0:
            return 0
        if pct > 100:
            return 100
        return int(pct)

    @property
    def on_battery(self):
        # if bus voltage is below ~3.3v and current is near zero or
        # negative, we are likely running on battery with no usb input.
        # this is a heuristic: the eta6003 passes bus voltage through when
        # usb is connected. without usb, the battery drives vsys directly.
        return self._bus_v < 3.3 and self._available

    def get_status(self):
        # returns a dict for the http /power endpoint and oled display.
        return {
            "available": self._available,
            "bus_voltage": round(self._bus_v, 3),
            "current_ma": round(self._current_ma, 2),
            "power_mw": round(self._power_mw, 2),
            "battery_percent": self.battery_percent,
            "on_battery": self.on_battery,
        }