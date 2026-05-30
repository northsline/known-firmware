"""
Known - Local DNS Privacy Monitor
Phase 1: Component Testing & Integration
"""

import machine
import time
from machine import Pin, I2C, SPI
import ssd1306
import wifi_config
import dns_monitor
import env

OLED_SCL_PIN = 3
OLED_SDA_PIN = 2
BUZZER_PIN = 15
SD_MISO_PIN = 16
SD_MOSI_PIN = 19
SD_SCK_PIN = 18
SD_CS_PIN = 17

class KnownHardware:
    def __init__(self):
        self.pico_id = machine.unique_id()
        print(f"Known Device ID: {self.pico_id.hex()}\n")
        
        self.oled = self._init_oled()
        self.buzzer = self._init_buzzer()
        self.sd_card = self._init_sd_card()
        
        self.wlan = None
        self.ip_address = None
        
        self._startup_sequence()
    
    def _init_oled(self):
        """Initialize OLED display using the driver"""
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
        """Initialize passive buzzer"""
        try:
            buzzer = machine.PWM(Pin(BUZZER_PIN))
            buzzer.freq(1000)
            buzzer.duty_u16(0)
            print("Buzzer initialized")
            return buzzer
        except Exception as e:
            print(f"Buzzer init failed: {e}")
            return None
    
    def _init_sd_card(self):
        """Initialize MicroSD card via SPI"""
        try:
            spi = SPI(0, baudrate=1000000, polarity=0, phase=0, bits=8, 
                      firstbit=SPI.MSB, sck=Pin(SD_SCK_PIN), 
                      mosi=Pin(SD_MOSI_PIN), miso=Pin(SD_MISO_PIN))
            cs = Pin(SD_CS_PIN, Pin.OUT)
            cs.value(1)
            print("SD Card SPI initialized")
            return {"spi": spi, "cs": cs}
        except Exception as e:
            print(f"SD Card init failed: {e}")
            return None
    
    def connect_to_wifi(self):
        """Connect to WiFi network"""
        print(f"Attempting to connect to {env.WIFI_SSID}")
        self.wlan, self.ip_address = wifi_config.connect_wifi(
            env.WIFI_SSID, 
            env.WIFI_PASSWORD
        )
        
        if self.wlan and self.ip_address:
            if self.oled:
                self.update_display("WiFi Connected", self.ip_address, "Ready")
            return True
        else:
            if self.oled:
                self.update_display("WiFi Failed", env.WIFI_SSID, "Retrying...")
            return False
    
    def _startup_sequence(self):
        """Test each component with feedback"""
        print("\n=== Known Hardware Test Sequence ===")
        
        if self.buzzer:
            print("Testing buzzer...")
            self.buzzer.duty_u16(16384)
            time.sleep(0.2)
            self.buzzer.duty_u16(0)
            time.sleep(0.1)
        
        if self.sd_card:
            print("Testing SD card...")
            try:
                self.sd_card["cs"].value(0)
                response = bytearray(5)
                self.sd_card["spi"].write_readinto(b'\xff\x00\x00\x00\xff', response)
                self.sd_card["cs"].value(1)
                print(f"SD raw stream response: {[hex(x) for x in response]}")
            except Exception as e:
                print(f"SD test error: {e}")
        
        print("Connecting to WiFi...")
        wifi_connected = self.connect_to_wifi()
        
        if wifi_connected:
            print("Starting DNS monitor...")
            self.dns_mon = dns_monitor.DNSMonitor()
            if self.dns_mon.start_server():
                print("DNS monitoring active")
            else:
                print("DNS monitor failed to start")
        else:
            print("Skipping DNS monitor - no WiFi")
        
        print("Hardware test complete!\n")

    def update_display(self, line1="", line2="", line3=""):
        """Update OLED with new text using driver syntax"""
        if self.oled:
            try:
                self.oled.fill(0)
                self.oled.text(line1, 0, 0)
                self.oled.text(line2, 0, 16)
                self.oled.text(line3, 0, 32)
                self.oled.show()
            except Exception as e:
                print(f"Display update error: {e}")

if __name__ == "__main__":
    print("Starting Known firmware...")
    known_hw = KnownHardware()
    
    counter = 0
    dns_check_interval = 0
    
    while True:
        if known_hw.oled:
            if known_hw.ip_address:
                known_hw.update_display(
                    "Known v0.1", 
                    f"IP: {known_hw.ip_address}", 
                    "Monitoring..."
                )
            else:
                known_hw.update_display("Known v0.1", "No WiFi", "Retrying...")
        
        if not known_hw.wlan or not known_hw.wlan.isconnected():
            if counter % 30 == 0:
                known_hw.connect_to_wifi()
        
        if hasattr(known_hw, 'dns_mon') and counter % 2 == 0:
            dns_packet = known_hw.dns_mon.check_for_packets()
            if dns_packet:
                print(f"DNS Request: {dns_packet['domain']} from {dns_packet['source']}")
                if known_hw.buzzer:
                    known_hw.buzzer.duty_u16(16384)
                    time.sleep_ms(50)
                    known_hw.buzzer.duty_u16(0)
        
        counter += 1
        time.sleep(1)