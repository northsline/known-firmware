# Known - Local DNS Privacy Monitor
# For the breadboard layout and build instructions, see the docs repo on our profile.

import machine
import time

OLED_SCL_PIN = 3
OLED_SDA_PIN = 2
BUZZER_PIN = 15

OLED_MAX_CHARS = 16
WIFI_TIMEOUT_S = 10
MDNS_HOSTNAME = "known"


def _show_provisioning_oled():
    """Quick setup screen so the user knows the device is alive."""
    try:
        from machine import Pin, I2C
        import ssd1306

        i2c = I2C(1, scl=Pin(OLED_SCL_PIN), sda=Pin(OLED_SDA_PIN), freq=400000)
        if 0x3C not in i2c.scan():
            print("OLED not detected on I2C bus")
            return
        oled = ssd1306.SSD1306_I2C(128, 64, i2c, addr=0x3C)
        oled.fill(0)
        oled.text("Known Setup", 0, 0)
        oled.text("Plug into PC", 0, 16)
        oled.text("Open the app", 0, 32)
        oled.show()
        print("OLED: setup screen shown")
    except Exception as e:
        print("OLED setup screen skipped:", e)


class KnownHardware:
    def __init__(self):
        import devices

        self.pico_id = machine.unique_id()
        print("Known Device ID:", self.pico_id.hex())

        self.oled = self._init_oled()
        self.buzzer = self._init_buzzer()

        self.wlan = None
        self.ip_address = None
        self.device_tracker = devices.DeviceTracker()
        self.dns_mon = None
        self.http = None

    def _init_oled(self):
        try:
            from machine import Pin, I2C
            import ssd1306

            print("Initializing I2C Bus 1...")
            i2c = I2C(1, scl=Pin(OLED_SCL_PIN), sda=Pin(OLED_SDA_PIN), freq=400000)
            found = i2c.scan()

            if 0x3C in found:
                print("OLED found at 0x3c. Initializing driver...")
                oled = ssd1306.SSD1306_I2C(128, 64, i2c, addr=0x3C)
                oled.fill(0)
                oled.text("Known Online", 0, 0)
                oled.show()
                return oled
            print("OLED not detected on I2C Bus 1")
            return None
        except Exception as e:
            print("OLED initialization failed:", e)
            return None

    def _init_buzzer(self):
        try:
            from machine import Pin

            buzzer = machine.PWM(Pin(BUZZER_PIN))
            buzzer.freq(1000)
            buzzer.duty_u16(0)
            print("Buzzer initialized")
            return buzzer
        except Exception as e:
            print("Buzzer init failed:", e)
            return None

    def beep(self, ms=50):
        if self.buzzer:
            self.buzzer.duty_u16(16384)
            time.sleep_ms(ms)
            self.buzzer.duty_u16(0)

    def connect_to_wifi(self, ssid, password):
        import network

        print("Attempting to connect to", ssid)
        self.wlan = network.WLAN(network.STA_IF)
        self.wlan.active(True)

        if not self.wlan.isconnected():
            self.wlan.connect(ssid, password)
            start = time.time()
            while not self.wlan.isconnected() and (time.time() - start) < WIFI_TIMEOUT_S:
                time.sleep(0.1)

        if self.wlan.isconnected():
            self.ip_address = self.wlan.ifconfig()[0]
            print("WiFi connected. IP:", self.ip_address)
            self._start_mdns()
            if self.oled:
                self.update_display("WiFi Connected", self.ip_address, "Ready")
            self._start_dns_monitor()
            return True

        print("WiFi connection failed")
        if self.oled:
            self.update_display("WiFi Failed", str(ssid)[:OLED_MAX_CHARS], "Retrying...")
        return False

    def _start_mdns(self):
        import network

        try:
            network.hostname(MDNS_HOSTNAME)
            print("mDNS hostname set:", MDNS_HOSTNAME + ".local")
        except Exception as e:
            print("mDNS setup skipped:", e)

    def _start_dns_monitor(self):
        import dns_monitor
        import http_server

        if self.dns_mon is None:
            self.dns_mon = dns_monitor.DNSMonitor(device_tracker=self.device_tracker)
        if self.dns_mon.start_server():
            print("DNS monitoring active")
        else:
            print("DNS monitor failed to start")
        self._start_http_server(http_server)

    def _start_http_server(self, http_server):
        if self.http is None:
            self.http = http_server.HTTPServer(
                self.dns_mon, self.device_tracker, port=8080
            )
        self.http.start()

    def update_display(self, line1="", line2="", line3=""):
        if self.oled:
            try:
                self.oled.fill(0)
                self.oled.text(line1[:OLED_MAX_CHARS], 0, 0)
                self.oled.text(line2[:OLED_MAX_CHARS], 0, 16)
                self.oled.text(line3[:OLED_MAX_CHARS], 0, 32)
                self.oled.show()
            except Exception as e:
                print("Display update error:", e)


hw = None


def run():
    global hw

    # Only provisioning is required for first-time USB setup. Import the rest
    # after Wi-Fi credentials exist so a partial lib/ copy cannot brick setup.
    import provisioning

    print("Starting Known firmware...")

    if not provisioning.is_provisioned():
        # Serial first — OLED/I2C init can delay USB command handling.
        provisioning.enter_provisioning_mode()
        print("Rebooting after provisioning...")
        time.sleep(1)
        machine.reset()
        return

    hw = KnownHardware()
    hw.beep(200)

    cfg = provisioning.load_config()
    hw.connect_to_wifi(cfg.get("ssid"), cfg.get("pass"))

    last_oled_update = 0
    last_wifi_check = 0
    while True:
        now = time.ticks_ms()

        if hw.dns_mon:
            dns_packet = hw.dns_mon.check_for_packets()
            if dns_packet:
                print("DNS Request:", dns_packet["domain"], "from", dns_packet["source"])
                hw.beep(50)

        if hw.http:
            hw.http.poll()

        if time.ticks_diff(now, last_oled_update) >= 1000:
            if hw.ip_address:
                hw.update_display(
                    "Known v0.1",
                    ("IP:" + hw.ip_address)[:OLED_MAX_CHARS],
                    "Monitoring...",
                )
            else:
                hw.update_display("Known v0.1", "No WiFi", "Retrying...")
            last_oled_update = now

        if time.ticks_diff(now, last_wifi_check) >= 30000:
            if not hw.wlan or not hw.wlan.isconnected():
                hw.connect_to_wifi(cfg.get("ssid"), cfg.get("pass"))
            last_wifi_check = now

        time.sleep_ms(100)


if __name__ == "__main__":
    run()
