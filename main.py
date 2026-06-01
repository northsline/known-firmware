# Known - Local DNS Privacy Monitor

import machine
import time
import network
from machine import Pin, I2C

import ssd1306
import provisioning
import dns_monitor

OLED_SCL_PIN = 3
OLED_SDA_PIN = 2
BUZZER_PIN = 15

OLED_MAX_CHARS = 16
WIFI_TIMEOUT_S = 10
MDNS_HOSTNAME = "known"


class KnownHardware:
    def __init__(self):
        self.pico_id = machine.unique_id()
        print(f"Known Device ID: {self.pico_id.hex()}\n")

        self.oled = self._init_oled()
        self.buzzer = self._init_buzzer()

        self.wlan = None
        self.ip_address = None
        self.dns_mon = None

    def _init_oled(self):
        try:
            print("Initializing I2C Bus 1...")
            i2c = I2C(1, scl=Pin(OLED_SCL_PIN), sda=Pin(OLED_SDA_PIN), freq=400000)
            devices = i2c.scan()

            if 0x3c in devices:
                print("OLED found at 0x3c. Initializing driver...")
                oled = ssd1306.SSD1306_I2C(128, 64, i2c, addr=0x3c)
                oled.fill(0)
                oled.text("Known Online", 0, 0)
                oled.show()
                return oled
            else:
                print("OLED not detected on I2C Bus 1")
                return None
        except Exception as e:
            print(f"OLED initialization failed: {e}")
            return None

    def _init_buzzer(self):
        try:
            buzzer = machine.PWM(Pin(BUZZER_PIN))
            buzzer.freq(1000)
            buzzer.duty_u16(0)
            print("Buzzer initialized")
            return buzzer
        except Exception as e:
            print(f"Buzzer init failed: {e}")
            return None

    def beep(self, ms=50):
        if self.buzzer:
            self.buzzer.duty_u16(16384)
            time.sleep_ms(ms)
            self.buzzer.duty_u16(0)

    def connect_to_wifi(self, ssid, password):
        print(f"Attempting to connect to {ssid}")
        self.wlan = network.WLAN(network.STA_IF)
        self.wlan.active(True)

        if not self.wlan.isconnected():
            self.wlan.connect(ssid, password)
            start = time.time()
            while not self.wlan.isconnected() and (time.time() - start) < WIFI_TIMEOUT_S:
                time.sleep(0.1)

        if self.wlan.isconnected():
            self.ip_address = self.wlan.ifconfig()[0]
            print(f"WiFi connected. IP: {self.ip_address}")
            self._start_mdns()
            if self.oled:
                self.update_display("WiFi Connected", self.ip_address, "Ready")
            self._start_dns_monitor()
            return True
        else:
            print("WiFi connection failed")
            if self.oled:
                self.update_display("WiFi Failed", str(ssid)[:OLED_MAX_CHARS], "Retrying...")
            return False

    def _start_mdns(self):
        try:
            network.hostname(MDNS_HOSTNAME)
            print(f"mDNS hostname set: {MDNS_HOSTNAME}.local")
        except Exception as e:
            print(f"mDNS setup skipped: {e}")

    def _start_dns_monitor(self):
        if self.dns_mon is None:
            self.dns_mon = dns_monitor.DNSMonitor()
        if self.dns_mon.start_server():
            print("DNS monitoring active")
        else:
            print("DNS monitor failed to start")

    def update_display(self, line1="", line2="", line3=""):
        if self.oled:
            try:
                self.oled.fill(0)
                self.oled.text(line1[:OLED_MAX_CHARS], 0, 0)
                self.oled.text(line2[:OLED_MAX_CHARS], 0, 16)
                self.oled.text(line3[:OLED_MAX_CHARS], 0, 32)
                self.oled.show()
            except Exception as e:
                print(f"Display update error: {e}")


def run():
    print("Starting Known firmware...")
    hw = KnownHardware()
    hw.beep(200)

    if not provisioning.is_provisioned():
        if hw.oled:
            hw.update_display("Known Setup", "Plug into PC", "Open the app")
        provisioning.enter_provisioning_mode()
        print("Rebooting after provisioning...")
        time.sleep(1)
        machine.reset()
        return

    cfg = provisioning.load_config()
    hw.connect_to_wifi(cfg.get("ssid"), cfg.get("pass"))

    counter = 0
    while True:
        if hw.oled:
            if hw.ip_address:
                hw.update_display(
                    "Known v0.1",
                    f"IP:{hw.ip_address}"[:OLED_MAX_CHARS],
                    "Monitoring...",
                )
            else:
                hw.update_display("Known v0.1", "No WiFi", "Retrying...")

        if not hw.wlan or not hw.wlan.isconnected():
            if counter % 30 == 0:
                hw.connect_to_wifi(cfg.get("ssid"), cfg.get("pass"))

        if hw.dns_mon:
            dns_packet = hw.dns_mon.check_for_packets()
            if dns_packet:
                print(f"DNS Request: {dns_packet['domain']} from {dns_packet['source']}")
                hw.beep(50)

        counter += 1
        time.sleep(1)


if __name__ == "__main__":
    run()
