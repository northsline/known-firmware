# tests for device name persistence across reboots.
# rename -> /names.json -> load_saved_names -> applied on next record().
# runs under cpython with a tmp names.json so we don't touch the real root fs.
import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import pytest
import devices


# stub network-touching lookups so tests don't hit the local network
devices._try_reverse_dns = lambda ip: None
devices._nbns_query_name = lambda ip: None
devices._lookup_mac = lambda ip: None


# --- names_store: file-level read/write ---

def test_load_names_returns_empty_when_file_missing(tmp_path, monkeypatch):
    # the pico's first boot has no /names.json. load_names() must not crash.
    import names_store
    monkeypatch.setattr(names_store, "NAMES_PATH", str(tmp_path / "names.json"))
    assert names_store.load_names() == {}


def test_load_names_returns_empty_on_corrupt_json(tmp_path, monkeypatch):
    # a half-written file (power loss mid-rename) must not brick the device.
    import names_store
    p = tmp_path / "names.json"
    p.write_text("{not valid json")
    monkeypatch.setattr(names_store, "NAMES_PATH", str(p))
    assert names_store.load_names() == {}


def test_load_names_returns_empty_on_wrong_root_type(tmp_path, monkeypatch):
    # someone (or a future bug) wrote a list at the top level. don't crash.
    import names_store
    p = tmp_path / "names.json"
    p.write_text("[]")
    monkeypatch.setattr(names_store, "NAMES_PATH", str(p))
    assert names_store.load_names() == {}


def test_save_names_round_trip(tmp_path, monkeypatch):
    # the boot path reads what rename() wrote.
    import names_store
    monkeypatch.setattr(names_store, "NAMES_PATH", str(tmp_path / "names.json"))
    data = {"192.168.1.10": "Laptop", "192.168.1.11": "Phone"}
    assert names_store.save_names(data) is True
    assert names_store.load_names() == data


def test_save_names_overwrites_existing(tmp_path, monkeypatch):
    # a rename rewrites the whole file, not just the changed entry.
    import names_store
    p = tmp_path / "names.json"
    monkeypatch.setattr(names_store, "NAMES_PATH", str(p))
    names_store.save_names({"192.168.1.10": "Old"})
    names_store.save_names({"192.168.1.10": "New", "192.168.1.11": "Phone"})
    assert names_store.load_names() == {"192.168.1.10": "New", "192.168.1.11": "Phone"}


# --- DeviceTracker: rename persists, load_saved_names restores ---

def test_rename_persists_to_flash(tmp_path, monkeypatch):
    # the contract: after rename(), the in-memory dict and the on-flash file
    # both hold the new name, so a reboot can restore it.
    from devices import DeviceTracker
    import names_store
    monkeypatch.setattr(names_store, "NAMES_PATH", str(tmp_path / "names.json"))

    tracker = DeviceTracker()
    tracker.record("192.168.1.10", "example.com", 1000.0, flagged=False)
    assert tracker.rename("192.168.1.10", "Laptop")

    # in-memory
    assert tracker.devices["192.168.1.10"]["custom_name"] == "Laptop"
    assert tracker.devices["192.168.1.10"]["name"] == "Laptop"
    # on disk
    assert names_store.load_names() == {"192.168.1.10": "Laptop"}


def test_rename_second_device_does_not_clobber_first(tmp_path, monkeypatch):
    # the boot path depends on this: each rename preserves the prior names.
    from devices import DeviceTracker
    import names_store
    monkeypatch.setattr(names_store, "NAMES_PATH", str(tmp_path / "names.json"))

    tracker = DeviceTracker()
    tracker.record("192.168.1.10", "a.com", 1000.0, flagged=False)
    tracker.record("192.168.1.11", "b.com", 1001.0, flagged=False)
    tracker.rename("192.168.1.10", "Laptop")
    tracker.rename("192.168.1.11", "Phone")

    assert names_store.load_names() == {
        "192.168.1.10": "Laptop",
        "192.168.1.11": "Phone",
    }


def test_rename_unknown_device_returns_false(tmp_path, monkeypatch):
    # renaming an ip we never saw must fail without writing to flash.
    from devices import DeviceTracker
    import names_store
    monkeypatch.setattr(names_store, "NAMES_PATH", str(tmp_path / "names.json"))

    tracker = DeviceTracker()
    assert tracker.rename("192.168.1.99", "Ghost") is False
    assert names_store.load_names() == {}


def test_rename_rejects_name_longer_than_32_chars(tmp_path, monkeypatch):
    # constraint from the task: long names must be rejected, not truncated.
    # a 33-char name is one past the cap.
    from devices import DeviceTracker
    import names_store
    monkeypatch.setattr(names_store, "NAMES_PATH", str(tmp_path / "names.json"))

    tracker = DeviceTracker()
    tracker.record("192.168.1.10", "a.com", 1000.0, flagged=False)
    too_long = "x" * 33
    assert tracker.rename("192.168.1.10", too_long) is False
    # the name must not have changed and must not have been written
    assert "custom_name" not in tracker.devices["192.168.1.10"]
    assert names_store.load_names() == {}


def test_rename_accepts_name_exactly_32_chars(tmp_path, monkeypatch):
    # boundary: exactly 32 chars is the cap, must be allowed.
    from devices import DeviceTracker
    import names_store
    monkeypatch.setattr(names_store, "NAMES_PATH", str(tmp_path / "names.json"))

    tracker = DeviceTracker()
    tracker.record("192.168.1.10", "a.com", 1000.0, flagged=False)
    boundary = "x" * 32
    assert tracker.rename("192.168.1.10", boundary) is True
    assert tracker.devices["192.168.1.10"]["custom_name"] == boundary


# --- boot path: load_saved_names restores, record() applies to new devices ---

def test_load_saved_names_applies_to_existing_devices(tmp_path, monkeypatch):
    # simulate: names.json on flash from a prior session, devices in RAM from
    # dns traffic that already happened. load_saved_names() must wire them up.
    from devices import DeviceTracker
    import names_store
    p = tmp_path / "names.json"
    p.write_text(json.dumps({"192.168.1.10": "Laptop"}))
    monkeypatch.setattr(names_store, "NAMES_PATH", str(p))

    tracker = DeviceTracker()
    tracker.record("192.168.1.10", "a.com", 1000.0, flagged=False)
    # the first record() set a default name. the saved name should overwrite it.
    tracker.load_saved_names()

    assert tracker.devices["192.168.1.10"]["custom_name"] == "Laptop"
    assert tracker.devices["192.168.1.10"]["name"] == "Laptop"


def test_record_applies_saved_name_to_new_device(tmp_path, monkeypatch):
    # the device shows up for the first time AFTER load_saved_names. the
    # record() path must still apply the saved custom_name.
    from devices import DeviceTracker
    import names_store
    p = tmp_path / "names.json"
    p.write_text(json.dumps({"192.168.1.10": "Laptop"}))
    monkeypatch.setattr(names_store, "NAMES_PATH", str(p))

    tracker = DeviceTracker()
    tracker.load_saved_names()
    tracker.record("192.168.1.10", "a.com", 1000.0, flagged=False)

    assert tracker.devices["192.168.1.10"]["custom_name"] == "Laptop"
    assert tracker.devices["192.168.1.10"]["name"] == "Laptop"


def test_load_saved_names_handles_missing_file(tmp_path, monkeypatch):
    # first boot ever: no names.json. must not crash, must not error.
    from devices import DeviceTracker
    import names_store
    monkeypatch.setattr(names_store, "NAMES_PATH", str(tmp_path / "names.json"))

    tracker = DeviceTracker()
    tracker.record("192.168.1.10", "a.com", 1000.0, flagged=False)
    tracker.load_saved_names()  # must not raise

    # saved name was empty, so the default name is still in place
    assert tracker.devices["192.168.1.10"]["name"].startswith("Device #")


def test_load_saved_names_handles_corrupt_file(tmp_path, monkeypatch):
    # flash file is garbage. must not crash; device falls back to default naming.
    from devices import DeviceTracker
    import names_store
    p = tmp_path / "names.json"
    p.write_text("not json at all")
    monkeypatch.setattr(names_store, "NAMES_PATH", str(p))

    tracker = DeviceTracker()
    tracker.record("192.168.1.10", "a.com", 1000.0, flagged=False)
    tracker.load_saved_names()  # must not raise

    # corrupt file -> empty saved names -> default naming still applies
    assert tracker.devices["192.168.1.10"]["name"].startswith("Device #")
