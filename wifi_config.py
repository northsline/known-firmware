import network
import time
from machine import reset

def connect_wifi(ssid, password, timeout=10):
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    
    if not wlan.isconnected():
        print(f'Connecting to {ssid}...')
        wlan.connect(ssid, password)
        
        start_time = time.time()
        while not wlan.isconnected() and (time.time() - start_time) < timeout:
            time.sleep(0.1)
    
    if wlan.isconnected():
        ip = wlan.ifconfig()[0]
        print(f'WiFi connected. IP: {ip}')
        return wlan, ip
    else:
        print('WiFi connection failed')
        return None, None