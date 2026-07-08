# Known firmware: pico 2 w dns monitor
# listens on udp/53, logs queries, forwards to upstream.
# oled shows query count, wifi status, uptime.
import machine
import time

OLED_SCL_PIN = 3
OLED_SDA_PIN = 2
BUZZER_PIN = 15

OLED_MAX_CHARS = 16
WIFI_TIMEOUT_S = 30
MDNS_HOSTNAME = "known"

# OLED timing. All in ms; use ticks_ms/ticks_diff everywhere.
OLED_CYCLE_MS = 3000            # how long each phase shows during normal operation
OLED_CYCLE_PROVISIONING_MS = 800  # fast cycle for the pre-serial intro
# The provisioning intro must finish inside the PWA's ~15 s ready-beacon
# window after a port-open reboot. Keep it short so enter_provisioning_mode()
# can send {"status": "ready"} in time.
HEARTBEAT_MS = 1000        # corner dot blink period
WIFI_LOST_PULSE_MS = 250   # half-period of WiFi-lost flash
RESTART_SPINNER_MS = 150   # spinner frame duration

# Spinner glyphs for the "Restarting..." screen. Module-level so the
# string objects are allocated once at import time, not per frame.
_SPINNER = ['|', '/', '-', '\\']

# Heartbeat dot pixel coords (top-right corner, just inside the bezel).
_HEARTBEAT_X = 122
_HEARTBEAT_Y = 2


def _show_provisioning_oled():
    # cycle onboarding hints so the user knows the device is alive.
    # runs one full rotation then returns: provisioning takes over after.
    try:
        from machine import Pin, I2C
        import ssd1306

        i2c = I2C(1, scl=Pin(OLED_SCL_PIN), sda=Pin(OLED_SDA_PIN), freq=400000)
        if 0x3C not in i2c.scan():
            print("OLED not detected on I2C bus")
            return
        oled = ssd1306.SSD1306_I2C(128, 64, i2c, addr=0x3C)

        # Four screens, one full rotation. Phases are tuples of
        # (line1, line2, line3): short strings, no allocation per frame.
        phases = [
            ("Known",  "Plug into PC",   "Open known.setup"),
            ("Known",  "Setting up...",  " "),
            ("Known",  "Ready",          " "),
            ("Known",  "Waiting for you", " "),
        ]
        # Pre-slice to the OLED width so we do not truncate on every call.
        for i in range(len(phases)):
            phases[i] = (phases[i][0][:OLED_MAX_CHARS],
                         phases[i][1][:OLED_MAX_CHARS],
                         phases[i][2][:OLED_MAX_CHARS])

        start = time.ticks_ms()
        idx = 0
        n = len(phases)
        # One full rotation = n * OLED_CYCLE_PROVISIONING_MS, then bail to provisioning.
        while time.ticks_diff(time.ticks_ms(), start) < n * OLED_CYCLE_PROVISIONING_MS:
            oled.fill(0)
            oled.text(phases[idx][0], 0, 0)
            oled.text(phases[idx][1], 0, 16)
            oled.text(phases[idx][2], 0, 32)
            # Heartbeat so the user can tell at a glance it is alive.
            now = time.ticks_ms()
            if (now // HEARTBEAT_MS) & 1:
                oled.pixel(_HEARTBEAT_X, _HEARTBEAT_Y, 1)
            oled.show()
            time.sleep_ms(OLED_CYCLE_PROVISIONING_MS)
            idx = (idx + 1) % n
        print("OLED: provisioning intro done")
    except Exception as e:
        print("OLED setup screen skipped:", e)


class OledView:
    # Drives the 128x64 OLED. Owns its own state; main loop just calls render().

    # States. Strings are interned by the compiler: no per-frame alloc.
    S_UNPROVISIONED = "unprovisioned"  # pre-WiFi, during onboarding
    S_CONNECTING = "connecting"        # first WiFi connect attempt
    S_ONLINE = "online"                # connected, monitoring
    S_WIFI_LOST = "wifi_lost"          # was connected, now isn't
    S_RESTARTING = "restarting"        # pre-reset spinner

    def __init__(self, oled):
        self.oled = oled
        self.state = self.S_UNPROVISIONED
        self.phase = 0                # current screen index
        self.last_phase_ms = 0        # when we last rotated
        self.last_heartbeat_ms = 0    # for the corner dot
        self.boot_ms = time.ticks_ms()

    def set_state(self, state):
        if state != self.state:
            self.state = state
            self.phase = 0
            self.last_phase_ms = time.ticks_ms()

    def _draw_heartbeat(self, now_ms):
        # Blink once per second. (now // period) is 0/1, gives a 50% duty.
        if (now_ms // HEARTBEAT_MS) & 1:
            self.oled.pixel(_HEARTBEAT_X, _HEARTBEAT_Y, 1)

    def _format_kb(self, n_bytes):
        # Inline so we do not allocate a helper string each call.
        # DNS packets cap at 512 bytes; we just want a human "X KB" feel.
        if n_bytes < 1024:
            return str(n_bytes) + " B"
        return str(n_bytes // 1024) + " KB"

    def render(self, info, now_ms):
        # Info is a dict built once per main-loop pass. Do not allocate inside here.
        if not self.oled:
            return

        # Rotate the screen on a fixed cadence, regardless of state.
        # (WiFi-lost has its own timing: see below.)
        if self.state != self.S_WIFI_LOST and \
                time.ticks_diff(now_ms, self.last_phase_ms) >= OLED_CYCLE_MS:
            self.phase = (self.phase + 1)
            self.last_phase_ms = now_ms

        self.oled.fill(0)

        if self.state == self.S_UNPROVISIONED:
            self._render_unprovisioned()
        elif self.state == self.S_CONNECTING:
            self._render_connecting(info, now_ms)
        elif self.state == self.S_ONLINE:
            self._render_online(info, now_ms)
        elif self.state == self.S_WIFI_LOST:
            self._render_wifi_lost(now_ms)
        elif self.state == self.S_RESTARTING:
            self._render_restarting(now_ms)
        else:
            # Unknown state: show nothing rather than crash.
            pass

        # Heartbeat goes on top of every screen.
        self._draw_heartbeat(now_ms)
        try:
            self.oled.show()
        except Exception as e:
            print("Display update error:", e)

    def _render_unprovisioned(self):
        # Mirrors _show_provisioning_oled phases, just in case the view
        # is used directly without the pre-roll.
        phases = [
            ("Known", "Plug into PC",  "Open known.setup"),
            ("Known", "Setting up...", " "),
            ("Known", "Ready",         " "),
            ("Known", "Waiting for you", " "),
        ]
        i = self.phase % 4
        l1, l2, l3 = phases[i]
        self.oled.text(l1[:OLED_MAX_CHARS], 0, 0)
        self.oled.text(l2[:OLED_MAX_CHARS], 0, 16)
        self.oled.text(l3[:OLED_MAX_CHARS], 0, 32)

    def _render_connecting(self, info, now_ms):
        # Two phases: "WiFi: <ssid>" then "Status: connecting".
        ssid = info.get("ssid", "")
        if (self.phase & 1) == 0:
            self.oled.text("Known", 0, 0)
            self.oled.text("WiFi:", 0, 16)
            self.oled.text(ssid[:OLED_MAX_CHARS], 0, 32)
        else:
            self.oled.text("Known", 0, 0)
            self.oled.text("WiFi...", 0, 16)
            self.oled.text("connecting", 0, 32)

    def _render_online(self, info, now_ms):
        # Two alternating screens.
        # Phase 0: "Known / N queries / X KB"
        # Phase 1: "Known / Wi-Fi: XX% / Uptime: Xh"
        queries = info.get("queries", 0)
        kb = info.get("kb", 0)
        rssi = info.get("rssi", 0)
        uptime_h = (time.ticks_diff(now_ms, self.boot_ms) // 3600000)
        if (self.phase & 1) == 0:
            self.oled.text("Known", 0, 0)
            self.oled.text(("Q: " + str(queries))[:OLED_MAX_CHARS], 0, 16)
            self.oled.text(self._format_kb(kb)[:OLED_MAX_CHARS], 0, 32)
        else:
            # Map RSSI to a rough % (0..100). Clamp at 0.
            pct = rssi + 100
            if pct < 0:
                pct = 0
            elif pct > 100:
                pct = 100
            self.oled.text("Known", 0, 0)
            self.oled.text(("Wi-Fi: " + str(pct) + "%")[:OLED_MAX_CHARS], 0, 16)
            self.oled.text(("Uptime: " + str(uptime_h) + "h")[:OLED_MAX_CHARS], 0, 32)

    def _render_wifi_lost(self, now_ms):
        # Pulse: hardware-invert the panel at 2 Hz. The SSD1306 driver
        # has invert(n) which flips the whole framebuffer in place :
        # we just redraw the same text in normal color and toggle.
        pulse_on = ((now_ms // WIFI_LOST_PULSE_MS) & 1) == 0
        self.oled.fill(0)
        self.oled.text("WiFi Lost", 0, 16)
        self.oled.text("Retrying...", 0, 32)
        self.oled.invert(1 if pulse_on else 0)

    def _render_restarting(self, now_ms):
        # Spinner frame from module-level tuple. No allocation.
        frame = _SPINNER[(now_ms // RESTART_SPINNER_MS) & 3]
        self.oled.text("Restarting...", 0, 16)
        self.oled.text(frame, 110, 16)


class KnownHardware:
    # WiFi, OLED, buzzer, main loop. One-stop shop for the hardware.
    def __init__(self):
        import devices

        self.pico_id = machine.unique_id()
        print("Known Device ID:", self.pico_id.hex())

        self.oled = self._init_oled()
        self.buzzer = self._init_buzzer()
        self.view = OledView(self.oled)

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

        # First, scan for networks to see what is available
        print("Scanning for networks...")
        wlan_temp = network.WLAN(network.STA_IF)
        wlan_temp.active(True)
        networks = wlan_temp.scan()
        print("Networks found:", len(networks))
        for n in networks:
            print(" -", n[0].decode(), "RSSI:", n[3], "sec:", n[5])

        self.wlan = network.WLAN(network.STA_IF)
        self.wlan.active(True)
        self.view.set_state(OledView.S_CONNECTING)
        # We do not render here: the main loop is what calls render. The
        # state change is enough; the next loop tick will pick it up.
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
                # Check if we are in a failed state
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
            self.view.set_state(OledView.S_ONLINE)
            self._start_dns_monitor()
            return True

        print("WiFi connection failed")
        # Do not drop to wifi_lost on a *first* connect failure: that
        # would flash the user with a scary screen on a normal config
        # mistake. Leave the connecting screen up; the main loop will
        # call us again on the slow retry timer. Return False

    def _wifi_status_name(self, status):
        # micropython STAT_* constants to human-readable
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
            # Pass the device token so the server can expose it for future auth.
            import provisioning
            token = provisioning.load_config().get("device_token")
            self.http = http_server.HTTPServer(
                self.dns_mon, self.device_tracker, port=8080, device_token=token
            )
        self.http.start()


hw = None


def _draw_restart_screen(view, n_frames=4):
    # show the spinner for a few frames before machine.reset() wipes the display
    view.set_state(OledView.S_RESTARTING)
    start = time.ticks_ms()
    # One full spinner rotation = 4 * RESTART_SPINNER_MS.
    duration = n_frames * RESTART_SPINNER_MS
    while time.ticks_diff(time.ticks_ms(), start) < duration:
        # Build a tiny info dict: the spinner screen ignores it, but
        # keeping the call shape uniform avoids branching in the view.
        view.render({}, time.ticks_ms())
        time.sleep_ms(RESTART_SPINNER_MS)


def run():
    global hw

    # Only provisioning is required for first-time USB setup. Import the rest
    # after Wi-Fi credentials exist so a partial lib/ copy cannot brick setup.
    import provisioning

    print("Starting Known firmware...")

    if not provisioning.is_provisioned():
        # Show setup screen so user knows device is alive before serial
        _show_provisioning_oled()
        # Serial first: OLED/I2C init can delay USB command handling.
        provisioning.enter_provisioning_mode()
        print("Rebooting after provisioning...")
        # Build a throwaway view just for the spinner: the device is
        # about to reset, no need to spin up the full hardware class.
        try:
            from machine import Pin, I2C
            import ssd1306
            i2c = I2C(1, scl=Pin(OLED_SCL_PIN), sda=Pin(OLED_SDA_PIN), freq=400000)
            if 0x3C in i2c.scan():
                oled = ssd1306.SSD1306_I2C(128, 64, i2c, addr=0x3C)
                view = OledView(oled)
                _draw_restart_screen(view)
        except Exception as e:
            print("Restart screen skipped:", e)
        machine.reset()
        return

    hw = KnownHardware()
    hw.beep(200)
    hw.view.set_state(OledView.S_ONLINE)

    cfg = provisioning.load_config()
    # Generate a device token on first boot if one does not exist yet.
    # Unused by the consumer dashboard now: the primitive is here so
    # auth can be added later without a firmware reflash on deployed devices.
    provisioning.ensure_device_token()
    hw.connect_to_wifi(cfg.get("ssid"), cfg.get("pass"))

    # load saved device names from flash so they survive reboots.
    hw.device_tracker.load_saved_names()

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

        # Build the small info dict the view needs. Done once per loop
        # pass; the view itself does not allocate on the hot path.
        info = {
            "queries": len(hw.dns_mon.dns_requests) if (hw.dns_mon and hw.dns_mon.dns_requests) else 0,
            "kb": 0,  # byte count not yet tracked; placeholder for the format
            "rssi": hw.wlan.status("rssi") if hw.wlan and hw.wlan.isconnected() else 0,
            "ssid": cfg.get("ssid", ""),
        }
        if hw.ip_address and hw.wlan and hw.wlan.isconnected():
            hw.view.set_state(OledView.S_ONLINE)
        elif hw.was_connected:
            hw.view.set_state(OledView.S_WIFI_LOST)
        # else: keep current state (CONNECTING or initial)

        hw.view.render(info, now)

        if time.ticks_diff(now, last_wifi_check) >= 30000:
            if not hw.wlan or not hw.wlan.isconnected():
                hw.connect_to_wifi(cfg.get("ssid"), cfg.get("pass"))
            last_wifi_check = now

        time.sleep_ms(100)


if __name__ == "__main__":
    run()
