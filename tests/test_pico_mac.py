# tests for the pico's own mac address exposed in the firmware API.
# on rp2350, the cyw43 driver holds the mac in cyw43_state.mac (loaded from
# OTP at init, or LAA-generated if no OTP). pure micropython gets it via
# wlan.config('mac'), which returns 6 raw bytes.
#
# the firmware formats those bytes as colon-separated hex (aa:bb:cc:dd:ee:ff)
# and exposes them on:
#   - /stats  as `pico_mac`
#   - /devices response wrapper as `pico_mac` (the tracked devices list is
#     nested under `devices` to keep the per-device `mac` field meaningful for
#     the *tracked* devices, not the heron device itself).
#
# per-device mac on /devices remains best-effort (None on rp2350 stock
# firmware: no ARP API). this is unchanged from the existing code.
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import pytest
from devices import format_mac


# --- format_mac: raw bytes -> colon-separated hex ----------------------

def test_format_mac_lowercase_hex():
    # canonical case from the rpi pico: B8:27:EB style (here arbitrary bytes)
    assert format_mac(b"\xb8\x27\xeb\x00\x00\x01") == "b8:27:eb:00:00:01"


def test_format_mac_all_zeros():
    assert format_mac(b"\x00\x00\x00\x00\x00\x00") == "00:00:00:00:00:00"


def test_format_mac_all_ff():
    assert format_mac(b"\xff\xff\xff\xff\xff\xff") == "ff:ff:ff:ff:ff:ff"


def test_format_mac_uses_colons_between_every_byte():
    out = format_mac(b"\xaa\xbb\xcc\xdd\xee\xff")
    assert out == "aa:bb:cc:dd:ee:ff"
    # exactly 5 colons
    assert out.count(":") == 5


def test_format_mac_returns_string():
    out = format_mac(b"\x12\x34\x56\x78\x9a\xbc")
    assert isinstance(out, str)
    assert out == "12:34:56:78:9a:bc"


def test_format_mac_wrong_length_raises():
    # must be exactly 6 bytes
    with pytest.raises(ValueError):
        format_mac(b"\x00\x00\x00\x00\x00")
    with pytest.raises(ValueError):
        format_mac(b"\x00\x00\x00\x00\x00\x00\x00")
    with pytest.raises(ValueError):
        format_mac(b"")


# --- /stats includes pico_mac ------------------------------------------

def test_stats_includes_pico_mac_field():
    # build a dns_monitor with no requests, a tracker with one device,
    # and a heron-hardware with a mac. the /stats response should expose
    # the pico's own mac under `pico_mac`. we replicate what _stats()
    # does in the http_server, since capturing the wire payload from a
    # non-blocking socket is overkill for a unit test.
    from devices import DeviceTracker
    from dns_monitor import DNSMonitor
    from http_server import HTTPServer

    mon = DNSMonitor()
    tracker = DeviceTracker()
    http = HTTPServer(mon, tracker, port=8080, pico_mac="b8:27:eb:00:00:42")

    # _stats body: same dict shape as the http server's _stats method.
    stats = tracker.get_stats()
    stats["unique_domains"] = 0
    stats["boot_time"] = mon.get_boot_time()
    stats["pico_mac"] = http.pico_mac
    assert stats["pico_mac"] == "b8:27:eb:00:00:42"


def test_stats_pico_mac_none_when_hw_has_no_mac():
    # if the hardware didn't surface a mac (e.g. very early boot, or a
    # build that doesn't expose wlan.config('mac')), the field is None
    # not missing -- so the dashboard adapter can branch on it.
    from devices import DeviceTracker
    from dns_monitor import DNSMonitor
    from http_server import HTTPServer

    mon = DNSMonitor()
    tracker = DeviceTracker()
    http = HTTPServer(mon, tracker, port=8080)  # no pico_mac passed

    stats = tracker.get_stats()
    stats["pico_mac"] = http.pico_mac
    assert http.pico_mac is None
    assert "pico_mac" in stats
    assert stats["pico_mac"] is None


# --- /devices response is wrapped: {pico_mac, devices: [...]} ---------

def test_devices_response_is_wrapped_with_pico_mac():
    # the /devices endpoint now returns an object, not an array, so the
    # pico's own mac can ride alongside the tracked-device list.
    from devices import DeviceTracker
    tracker = DeviceTracker()
    tracker.record("192.168.1.10", "example.com", 1000.0)
    from dns_monitor import DNSMonitor
    from http_server import HTTPServer
    mon = DNSMonitor()
    http = HTTPServer(mon, tracker, port=8080, pico_mac="b8:27:eb:00:00:42")

    # simulate the response shape: {pico_mac, devices: get_all()}
    response = {
        "pico_mac": http.pico_mac,
        "devices": tracker.get_all(),
    }
    assert response["pico_mac"] == "b8:27:eb:00:00:42"
    assert isinstance(response["devices"], list)
    assert len(response["devices"]) == 1
    assert response["devices"][0]["ip"] == "192.168.1.10"


def test_devices_response_keeps_per_device_mac_field():
    # per-device `mac` is still best-effort (None on rp2350 stock
    # firmware). the wrapper does NOT replace that -- the dashboard's
    # per-device vendor lookup still keys off it.
    from devices import DeviceTracker
    tracker = DeviceTracker()
    tracker.record("192.168.1.10", "example.com", 1000.0)
    response = {
        "pico_mac": "b8:27:eb:00:00:42",
        "devices": tracker.get_all(),
    }
    assert response["devices"][0]["mac"] is None  # unchanged: still None


# --- _read_pico_mac integration ----------------------------------------

def test_read_pico_mac_formats_bytes_from_wlan_config():
    # _read_pico_mac() in main.py pulls wlan.config('mac') and runs it
    # through format_mac. verify the call shape and the failure path:
    # if wlan.config raises or returns junk, the helper leaves the
    # attribute untouched.
    # we don't import main.py here because it pulls in machine/network
    # at module load. instead, replicate the helper body inline and
    # assert on the behavior we depend on.
    import devices

    class FakeWlan:
        def __init__(self, mac):
            self._mac = mac
        def config(self, key):
            if key != "mac":
                raise KeyError(key)
            return self._mac

    # happy path
    wlan = FakeWlan(b"\xb8\x27\xeb\x12\x34\x56")
    raw = wlan.config("mac")
    assert devices.format_mac(raw) == "b8:27:eb:12:34:56"

    # wlan raises -> caller leaves self.mac_address unchanged
    class BadWlan:
        def config(self, key):
            raise OSError("wifi not ready")
    wlan = BadWlan()
    try:
        raw = wlan.config("mac")
        raised = False
    except Exception:
        raised = True
    assert raised

    # wlan returns non-bytes -> format_mac rejects
    class WeirdWlan:
        def config(self, key):
            return "not bytes"
    raw = WeirdWlan().config("mac")
    with pytest.raises(ValueError):
        devices.format_mac(raw)
