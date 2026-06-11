# Known - Local DNS Privacy Monitor
# This runs on the Raspberry Pi Pico 2 W.
# It listens for DNS queries from your devices, logs them, and forwards them to a real DNS server.
# The dashboard shows you what's happening on your network.

import machine
import time

OLED_SCL_PIN = 3
OLED_SDA_PIN = 2
BUZZER_PIN = 15

OLED_MAX_CHARS = 16
WIFI_TIMEOUT_S = 30
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
        oled.text("Setup", 0, 0)
        oled.text("Plug into PC", 0, 16)
        oled.text("Open the app", 0, 32)
        oled.show()
        print("OLED: setup screen shown")
    except Exception as e:
        print("OLED setup screen skipped:", e)


class KnownHardware:
    """Hardware control for Known.

    Handles WiFi connection, OLED display, buzzer, and runs the main loop.
    """
    
    def __init__(self):
        import devices

        self.pico_id = machine.unique_id()
        print("Known Device ID:", self.pico_id.hex())

        self.oled = self._init_oled()
        self.buzzer = self._init_buzzer()

        self.wlan = None
        self.ip_address = None
        self.was_connected = False
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
        
        # First, scan for networks to see what's available
        print("Scanning for networks...")
        wlan_temp = network.WLAN(network.STA_IF)
        wlan_temp.active(True)
        networks = wlan_temp.scan()
        print("Networks found:", len(networks))
        for n in networks:
            print(" -", n[0].decode(), "RSSI:", n[3], "sec:", n[5])
        
        self.wlan = network.WLAN(network.STA_IF)
        self.wlan.active(True)

        if not self.wlan.isconnected():
            self.wlan.connect(ssid, password)
            # Wait for association first (this can take time on weak signals)
            print("Waiting for association...")
            start = time.time()
            while not self.wlan.isconnected():
                time.sleep(0.5)
                status = self.wlan.status()
                print("  status:", status, "-", self._wifi_status_name(status))
                if time.time() - start > WIFI_TIMEOUT_S:
                    break
                # Check if we're in a failed state
                if status == network.STAT_WRONG_PASSWORD:
                    print("WiFi: wrong password")
                    return False
                elif status == network.STAT_NO_AP_FOUND:
                    print("WiFi: no AP found")
                    return False
                elif status == network.STAT_CONNECT_FAIL:
                    print("WiFi: connect failed")
                    return False

            # Now wait for IP assignment
            if self.wlan.isconnected():
                print("Associated, waiting for IP...")
                start = time.time()
                while not self.ip_address and (time.time() - start) < 10:
                    time.sleep(0.2)
                    self.ip_address = self.wlan.ifconfig()[0]
                    if self.ip_address == '0.0.0.0':
                        self.ip_address = None

        if self.wlan.isconnected():
            if not self.ip_address:
                self.ip_address = self.wlan.ifconfig()[0]
            print("WiFi connected. IP:", self.ip_address)
            self.was_connected = True
            self._start_mdns()
            if self.oled:
                self.update_display("WiFi Connected", self.ip_address, "Ready")
            self._start_dns_monitor()
            return True

        print("WiFi connection failed")
        if self.oled:
            self.update_display("WiFi Failed", str(ssid)[:OLED_MAX_CHARS], "Retrying...")
        return False

    def _wifi_status_name(self, status):
        """Return human-readable WiFi status."""
        # Hardcoded status values (MicroPython STAT_* constants)
        statuses = {
            0: "IDLE",
            1: "CONNECTING", 
            2: "WRONG_PASSWORD",
            3: "NO_AP_FOUND",
            4: "CONNECT_FAIL",
            5: "GOT_IP",
        }
        return statuses.get(status, "UNKNOWN(" + str(status) + ")")

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
        # Show setup screen so user knows device is alive before serial
        _show_provisioning_oled()
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

        if time.ticks_diff(now, last_oled_update) >= 10000:
            if hw.ip_address:
                # Get DNS query count
                query_count = 0
                if hw.dns_mon and hw.dns_mon.dns_requests:
                    query_count = len(hw.dns_mon.dns_requests)
                hw.update_display(
                    "Known v0.1",
                    ("Queries: " + str(query_count))[:OLED_MAX_CHARS],
                    "Monitoring...",
                )
            elif hw.was_connected:
                hw.update_display("WiFi Lost", "Retrying...", "")
            else:
                hw.update_display("Known v0.1", "No WiFi", "Retrying...")
            last_oled_update = now

        if time.ticks_diff(now, last_wifi_check) >= 30000:
            if not hw.wlan or not hw.wlan.isconnected():
                hw.connect_to_wifi(cfg.get("ssid"), cfg.get("pass"))
            last_wifi_check = now

        # Immediate reconnect if we lost connection (debounced)
        if hw.was_connected and (not hw.wlan or not hw.wlan.isconnected()):
            if time.ticks_diff(now, last_wifi_check) >= 5000:
                hw.connect_to_wifi(cfg.get("ssid"), cfg.get("pass"))
                last_wifi_check = now

        time.sleep_ms(100)


if __name__ == "__main__":
    run()
