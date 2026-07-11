# tests for otp_keys. run with: pytest tests/ -q
#
# these run under cpython (micropython modules have try/except fallbacks).
# we do NOT burn real OTP from a test. the in-memory backend is used
# instead; the real OTP backend runs on-device only via flash_known.py.
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import pytest
import otp_keys


# --- backend selection ---

def test_module_exposes_backend_constant():
    # _BACKEND is set on import: "otp", "flash", or "memory" (test stub)
    assert hasattr(otp_keys, "_BACKEND")
    assert otp_keys._BACKEND in ("otp", "flash", "memory")


# --- key layout constants ---

def test_layout_constants_match_design():
    # layout is part of the contract. if these move, every burned device is bricked.
    assert otp_keys._PRIVATE_KEY_OFFSET == 0
    assert otp_keys._PRIVATE_KEY_LEN == 32
    assert otp_keys._PUBLIC_KEY_OFFSET == 32
    assert otp_keys._PUBLIC_KEY_LEN == 65
    assert otp_keys._SERIAL_OFFSET == 97
    assert otp_keys._SERIAL_LEN == 8
    assert otp_keys._CERT_OFFSET == 105
    assert otp_keys._CERT_LEN == 148
    assert otp_keys._MAGIC_OFFSET == 253
    assert otp_keys._MAGIC_VALUE == 0x01
    # total must be 254 bytes (253 data + 1 magic)
    assert otp_keys._MAGIC_OFFSET + 1 == 254


# --- has_keys ---

def test_has_keys_false_on_empty_storage(monkeypatch):
    # arrange: storage returns no magic byte
    monkeypatch.setattr(otp_keys, "_read_bytes",
                        lambda off, n: b'\x00' if off == otp_keys._MAGIC_OFFSET else None)
    assert otp_keys.has_keys() is False


def test_has_keys_true_when_magic_is_set(monkeypatch):
    monkeypatch.setattr(otp_keys, "_read_bytes",
                        lambda off, n: bytes([otp_keys._MAGIC_VALUE])
                        if off == otp_keys._MAGIC_OFFSET else None)
    assert otp_keys.has_keys() is True


def test_has_keys_false_when_magic_read_fails(monkeypatch):
    def fail(off, n):
        if off == otp_keys._MAGIC_OFFSET:
            return None  # no storage at all
        return None
    monkeypatch.setattr(otp_keys, "_read_bytes", fail)
    assert otp_keys.has_keys() is False


# --- get_private_key / get_public_key / get_serial / get_certificate ---

def test_get_private_key_returns_32_bytes_after_burn():
    priv = bytes(range(32))
    pub = b'\x04' + b'\x01' * 32 + b'\x02' * 32  # 65 bytes
    serial = b'\xaa' * 8
    cert = b'\x30\x46' + b'\x42' * 70  # ~72 bytes

    assert otp_keys.burn_keys(priv, pub, serial, cert) is True
    out = otp_keys.get_private_key()
    assert out == priv
    assert len(out) == 32


def test_get_public_key_returns_65_bytes_after_burn():
    priv = bytes(range(32))
    pub = b'\x04' + b'\x01' * 32 + b'\x02' * 32
    serial = b'\xaa' * 8
    cert = b'\x30\x46' + b'\x42' * 70

    otp_keys.burn_keys(priv, pub, serial, cert)
    out = otp_keys.get_public_key()
    assert out == pub
    assert len(out) == 65
    assert out[0] == 0x04  # uncompressed point indicator


def test_get_serial_returns_hex_after_burn():
    priv = bytes(range(32))
    pub = b'\x04' + b'\x01' * 32 + b'\x02' * 32
    serial = b'\xde\xad\xbe\xef\xca\xfe\xba\xbe'
    cert = b'\x30\x46' + b'\x42' * 70

    otp_keys.burn_keys(priv, pub, serial, cert)
    out = otp_keys.get_serial()
    assert out == "deadbeefcafebabe"  # 16 hex chars
    assert len(out) == 16


def test_get_serial_returns_none_when_empty(monkeypatch):
    monkeypatch.setattr(otp_keys, "_read_bytes", lambda off, n: None)
    assert otp_keys.get_serial() is None


def test_get_certificate_trims_trailing_nulls():
    priv = bytes(range(32))
    pub = b'\x04' + b'\x01' * 32 + b'\x02' * 32
    serial = b'\xaa' * 8
    # cert shorter than 148 bytes: must be padded on write, trimmed on read
    cert = b'\x30\x46\x02\x21' + b'\xab' * 60  # 64 bytes

    otp_keys.burn_keys(priv, pub, serial, cert)
    out = otp_keys.get_certificate()
    assert out == cert
    assert len(out) == 64


def test_get_certificate_returns_none_when_empty(monkeypatch):
    monkeypatch.setattr(otp_keys, "_read_bytes", lambda off, n: None)
    assert otp_keys.get_certificate() is None


def test_get_certificate_returns_none_when_only_nulls(monkeypatch):
    # storage present but cert field is all zeros (no cert burned)
    def fake(off, n):
        if off == otp_keys._CERT_OFFSET:
            return b'\x00' * otp_keys._CERT_LEN
        return b'\x00' * n
    monkeypatch.setattr(otp_keys, "_read_bytes", fake)
    assert otp_keys.get_certificate() is None


# --- get_private_key_int ---

def test_get_private_key_int_returns_int_after_burn():
    priv = bytes(range(32))
    pub = b'\x04' + b'\x01' * 32 + b'\x02' * 32
    serial = b'\xaa' * 8
    cert = b'\x30\x46' + b'\x42' * 70

    otp_keys.burn_keys(priv, pub, serial, cert)
    out = otp_keys.get_private_key_int()
    assert isinstance(out, int)
    assert out == int.from_bytes(priv, 'big')


def test_get_private_key_int_returns_none_when_empty(monkeypatch):
    monkeypatch.setattr(otp_keys, "_read_bytes", lambda off, n: None)
    assert otp_keys.get_private_key_int() is None


# --- burn_keys atomicity: read-back must match ---

def test_burn_keys_atomicity_readback_matches():
    # the critical safety property: what we wrote, we can read back.
    # if this fails on hardware, the device is bricked for key storage.
    priv = bytes(range(32))
    pub = b'\x04' + b'\x01' * 32 + b'\x02' * 32
    serial = b'\xaa\xbb\xcc\xdd\xee\xff\x11\x22'
    cert = b'\x30\x46\x02\x21' + b'\xcd' * 70  # 74 bytes (under 146 cap)

    assert otp_keys.burn_keys(priv, pub, serial, cert) is True

    # read back every field
    assert otp_keys.get_private_key() == priv
    assert otp_keys.get_public_key() == pub
    assert otp_keys.get_serial() == serial.hex()
    assert otp_keys.get_certificate() == cert
    assert otp_keys.has_keys() is True


def test_burn_keys_validation_rejects_wrong_lengths():
    # private key wrong length: must fail before any write
    priv_short = b'\x01' * 31
    pub = b'\x04' + b'\x01' * 32 + b'\x02' * 32
    serial = b'\xaa' * 8
    cert = b'\x30\x46' + b'\x42' * 70

    assert otp_keys.burn_keys(priv_short, pub, serial, cert) is False


def test_burn_keys_validation_rejects_wrong_pubkey_length():
    priv = bytes(range(32))
    pub_short = b'\x04' + b'\x01' * 32  # only 33 bytes, not 65
    serial = b'\xaa' * 8
    cert = b'\x30\x46' + b'\x42' * 70

    assert otp_keys.burn_keys(priv, pub_short, serial, cert) is False


def test_burn_keys_validation_rejects_wrong_serial_length():
    priv = bytes(range(32))
    pub = b'\x04' + b'\x01' * 32 + b'\x02' * 32
    serial_short = b'\xaa' * 4  # too short
    cert = b'\x30\x46' + b'\x42' * 70

    assert otp_keys.burn_keys(priv, pub, serial_short, cert) is False


def test_burn_keys_validation_rejects_oversized_cert():
    priv = bytes(range(32))
    pub = b'\x04' + b'\x01' * 32 + b'\x02' * 32
    serial = b'\xaa' * 8
    cert_huge = b'\x30' * 200  # over the 148-byte cap

    assert otp_keys.burn_keys(priv, pub, serial, cert_huge) is False


# --- burn_keys verify_back ---

def test_burn_keys_calls_verify_back(monkeypatch):
    # verify the internal verify-back path is exercised
    priv = bytes(range(32))
    pub = b'\x04' + b'\x01' * 32 + b'\x02' * 32
    serial = b'\xaa' * 8
    cert = b'\x30\x46' + b'\x42' * 70

    calls = {"verify": 0, "write": []}

    def fake_write(off, data):
        calls["write"].append((off, data))

    def fake_read(off, n):
        # after writes return what was written for that region
        if off == otp_keys._PRIVATE_KEY_OFFSET and n == otp_keys._PRIVATE_KEY_LEN:
            return priv
        if off == otp_keys._PUBLIC_KEY_OFFSET and n == otp_keys._PUBLIC_KEY_LEN:
            return pub
        if off == otp_keys._SERIAL_OFFSET and n == otp_keys._SERIAL_LEN:
            return serial
        if off == otp_keys._CERT_OFFSET and n == otp_keys._CERT_LEN:
            return cert.ljust(otp_keys._CERT_LEN, b'\x00')[:otp_keys._CERT_LEN]
        if off == otp_keys._MAGIC_OFFSET and n == 1:
            return bytes([otp_keys._MAGIC_VALUE])
        return None

    monkeypatch.setattr(otp_keys, "_write_bytes", fake_write)
    monkeypatch.setattr(otp_keys, "_read_bytes", fake_read)

    result = otp_keys.burn_keys(priv, pub, serial, cert)
    assert result is True
    # all 5 fields were written
    assert len(calls["write"]) == 5
    # and the final magic byte was the last write
    last_off, last_data = calls["write"][-1]
    assert last_off == otp_keys._MAGIC_OFFSET
    assert last_data == bytes([otp_keys._MAGIC_VALUE])


def test_burn_keys_aborts_on_readback_mismatch(monkeypatch):
    # if the read-back after a partial write doesn't match, the burn
    # MUST fail and not mark keys as present.
    priv = bytes(range(32))
    pub = b'\x04' + b'\x01' * 32 + b'\x02' * 32
    serial = b'\xaa' * 8
    cert = b'\x30\x46' + b'\x42' * 70

    def bad_read(off, n):
        # simulate a write that didn't stick: return zeros
        return b'\x00' * n

    monkeypatch.setattr(otp_keys, "_write_bytes", lambda off, data: None)
    monkeypatch.setattr(otp_keys, "_read_bytes", bad_read)

    # should fail because read-back doesn't match what we wrote
    result = otp_keys.burn_keys(priv, pub, serial, cert)
    assert result is False
    # and has_keys() must be false (we never wrote the magic byte)
    assert otp_keys.has_keys() is False


# --- error handling for runtime issues ---

def test_get_private_key_returns_none_on_storage_error(monkeypatch):
    def raise_oserror(off, n):
        raise OSError("storage failure")
    monkeypatch.setattr(otp_keys, "_read_bytes", raise_oserror)
    assert otp_keys.get_private_key() is None


def test_burn_keys_returns_false_on_storage_error(monkeypatch):
    def raise_oserror(off, data):
        raise OSError("OTP write failed")
    monkeypatch.setattr(otp_keys, "_write_bytes", raise_oserror)
    assert otp_keys.burn_keys(
        bytes(range(32)),
        b'\x04' + b'\x01' * 32 + b'\x02' * 32,
        b'\xaa' * 8,
        b'\x30\x46' + b'\x42' * 70,
    ) is False
