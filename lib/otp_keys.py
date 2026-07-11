# lib/otp_keys.py: device key storage for the RP2350
#
# key layout in storage (OTP or flash file):
#   offset 0    32 bytes  ECDSA P-256 private key (raw, big-endian)
#   offset 32   65 bytes  ECDSA P-256 public key (uncompressed, 0x04 || X || Y)
#   offset 97    8 bytes  device serial number
#   offset 105 148 bytes  device certificate (DER, null-padded)
#   offset 253   1 byte   magic (0x01 = keys present)
#   total: 254 bytes
#
# backend selection: at import time, try machine.OTP. if the RP2350 OTP
# API is not available in the running MicroPython build, fall back to a
# flash file at /keys.bin. the file is written once during manufacturing
# and read-only during normal operation.
#
# burn_keys is atomic-by-construction: data fields are written first,
# the magic byte is written LAST. read-back verification happens between
# the data and magic writes -- if any byte does not match what we wrote,
# the magic byte is never set and burn_keys returns False. the device
# can be re-attempted (OTP bits only go 0->1, so retrying a partial
# write is safe).
import sys

# --- layout constants. the on-device byte positions of every field.
# these are part of the contract -- if they move, every burned device
# is bricked. the test suite locks them.
_PRIVATE_KEY_OFFSET = 0
_PRIVATE_KEY_LEN = 32
_PUBLIC_KEY_OFFSET = 32
_PUBLIC_KEY_LEN = 65
_SERIAL_OFFSET = 97
_SERIAL_LEN = 8
_CERT_OFFSET = 105
_CERT_LEN = 148
_MAGIC_OFFSET = 253
_MAGIC_VALUE = 0x01

# flash fallback path
_KEY_FILE = "/keys.bin"


# --- backend selection. runs once at import. ---

def _init_backend():
    # three backends, in priority order:
    #   1. RP2350 OTP via machine.OTP (production, on-device)
    #   2. flash file at /keys.bin (on-device fallback if OTP unavailable)
    #   3. in-memory dict (cpython test environment, host-only)
    try:
        import machine
        otp_cls = getattr(machine, "OTP", None)
        if otp_cls is not None:
            return "otp", otp_cls()
    except Exception:
        pass
    # on cpython we cannot write to /keys.bin (root-owned path, no
    # MicroPython FS). the in-memory backend keeps tests runnable.
    is_micropython = "MicroPython" in sys.version or hasattr(sys, "implementation") and getattr(sys.implementation, "name", "") == "micropython"
    if is_micropython:
        return "flash", None
    return "memory", {}


_BACKEND, _OTP = _init_backend()


# --- low-level read/write. swappable per backend. ---

def _read_bytes(offset, length):
    if _BACKEND == "otp":
        try:
            return bytes(_OTP.read(offset, length))
        except Exception as e:
            print("[otp_keys] OTP read failed at", offset, ":", e)
            return None
    if _BACKEND == "flash":
        try:
            with open(_KEY_FILE, "rb") as f:
                f.seek(offset)
                return f.read(length)
        except (OSError, ValueError):
            return None
    # in-memory backend. dict keyed by (offset, length) tuples.
    return _OTP.get((offset, length))


def _write_bytes(offset, data):
    if _BACKEND == "otp":
        # OTP is one-time-write. bits go 0->1 only. writes to already-1
        # bits are no-ops on the hardware -- the verify-back step will
        # catch any bit that failed to set.
        try:
            _OTP.write(offset, data)
        except Exception as e:
            raise OSError("OTP write failed at {}: {}".format(offset, e))
        return
    if _BACKEND == "flash":
        # read-modify-write across the whole file. during manufacturing
        # the file is built up across multiple _write_bytes calls.
        try:
            with open(_KEY_FILE, "rb") as f:
                existing = bytearray(f.read())
        except OSError:
            existing = bytearray()
        needed = offset + len(data)
        if len(existing) < needed:
            existing.extend(b'\x00' * (needed - len(existing)))
        existing[offset:offset + len(data)] = data
        with open(_KEY_FILE, "wb") as f:
            f.write(bytes(existing))
        return
    # in-memory backend
    _OTP[(offset, len(data))] = bytes(data)


def _verify_region(offset, length, expected):
    # read back a region and compare. returns True if every byte matches.
    actual = _read_bytes(offset, length)
    if actual is None or len(actual) != length:
        return False
    return actual == expected


# --- public read API ---

def has_keys():
    magic = _read_bytes(_MAGIC_OFFSET, 1)
    if magic is None or len(magic) != 1:
        return False
    return magic[0] == _MAGIC_VALUE


def get_private_key():
    try:
        return _read_bytes(_PRIVATE_KEY_OFFSET, _PRIVATE_KEY_LEN)
    except Exception as e:
        print("[otp_keys] get_private_key failed:", e)
        return None


def get_public_key():
    try:
        return _read_bytes(_PUBLIC_KEY_OFFSET, _PUBLIC_KEY_LEN)
    except Exception as e:
        print("[otp_keys] get_public_key failed:", e)
        return None


def get_serial():
    try:
        raw = _read_bytes(_SERIAL_OFFSET, _SERIAL_LEN)
    except Exception as e:
        print("[otp_keys] get_serial failed:", e)
        return None
    if raw and len(raw) == _SERIAL_LEN:
        return raw.hex()
    return None


def get_certificate():
    try:
        cert = _read_bytes(_CERT_OFFSET, _CERT_LEN)
    except Exception as e:
        print("[otp_keys] get_certificate failed:", e)
        return None
    if cert and len(cert) == _CERT_LEN:
        cert = cert.rstrip(b'\x00')
        if len(cert) > 0:
            return cert
    return None


def get_private_key_int():
    raw = get_private_key()
    if raw and len(raw) == _PRIVATE_KEY_LEN:
        return int.from_bytes(raw, 'big')
    return None


# --- public write API: burn_keys ---

def burn_keys(private_key, public_key, serial, certificate):
    # 1. validate input lengths. wrong sizes cannot be tolerated --
    #    writing 31 bytes where 32 were expected leaves an OTP cell
    #    that will be read as something else.
    if not isinstance(private_key, (bytes, bytearray)) or len(private_key) != _PRIVATE_KEY_LEN:
        print("[otp_keys] burn: private key must be {} bytes, got {}".format(
            _PRIVATE_KEY_LEN, len(private_key) if hasattr(private_key, '__len__') else '?'))
        return False
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != _PUBLIC_KEY_LEN:
        print("[otp_keys] burn: public key must be {} bytes".format(_PUBLIC_KEY_LEN))
        return False
    if not isinstance(serial, (bytes, bytearray)) or len(serial) != _SERIAL_LEN:
        print("[otp_keys] burn: serial must be {} bytes".format(_SERIAL_LEN))
        return False
    if not isinstance(certificate, (bytes, bytearray)) or len(certificate) > _CERT_LEN:
        print("[otp_keys] burn: cert must be <= {} bytes".format(_CERT_LEN))
        return False

    # 2. write each data field. the magic byte is intentionally LAST --
    #    a set magic byte is the commit signal. before that, the device
    #    appears unprovisioned.
    try:
        _write_bytes(_PRIVATE_KEY_OFFSET, bytes(private_key))
        _write_bytes(_PUBLIC_KEY_OFFSET, bytes(public_key))
        _write_bytes(_SERIAL_OFFSET, bytes(serial))
        # pad cert to fixed length. the actual DER cert is variable
        # (sig + serial + pubKey, ~146 bytes max). nulls are trimmed on read.
        cert_padded = bytes(certificate) + b'\x00' * (_CERT_LEN - len(certificate))
        _write_bytes(_CERT_OFFSET, cert_padded)
    except OSError as e:
        print("[otp_keys] burn: write failed:", e)
        return False

    # 3. read-back verify. every data field must match exactly. if any
    #    byte mismatches, the device is partially burned but the magic
    #    byte has not been set, so the device is still recoverable: it
    #    will be read as "no keys" by has_keys(), and the burn can be
    #    retried (OTP bits only go 0->1, so retrying a partial write is
    #    safe -- it just sets the same bits again).
    if not _verify_region(_PRIVATE_KEY_OFFSET, _PRIVATE_KEY_LEN, bytes(private_key)):
        print("[otp_keys] burn: verify failed (private key)")
        return False
    if not _verify_region(_PUBLIC_KEY_OFFSET, _PUBLIC_KEY_LEN, bytes(public_key)):
        print("[otp_keys] burn: verify failed (public key)")
        return False
    if not _verify_region(_SERIAL_OFFSET, _SERIAL_LEN, bytes(serial)):
        print("[otp_keys] burn: verify failed (serial)")
        return False
    if not _verify_region(_CERT_OFFSET, _CERT_LEN, cert_padded):
        print("[otp_keys] burn: verify failed (certificate)")
        return False

    # 4. commit: write the magic byte. this is the point of no return.
    try:
        _write_bytes(_MAGIC_OFFSET, bytes([_MAGIC_VALUE]))
    except OSError as e:
        print("[otp_keys] burn: magic write failed:", e)
        return False

    return True
