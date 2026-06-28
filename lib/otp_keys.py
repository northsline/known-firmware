# lib/otp_keys.py: device key storage for the RP2350
#
# The RP2350 has 8KB of one-time-programmable (OTP) memory.
# Once a bit is set to 1, it cannot be cleared. This makes it ideal
# for storing a per-device private key that can never be overwritten.
#
# MicroPython on the RP2 port exposes OTP via the `machine` module
# on newer builds. If the OTP API is not available, we fall back to
# storing the key in a read-only file (/keys.bin) that gets written
# during manufacturing and never touched again. This is less secure
# (it lives in flash, not OTP) but works for development.
#
# Key layout in OTP (or fallback file):
#   Offset 0:   32 bytes: ECDSA P-256 private key (raw, big-endian)
#   Offset 32:  65 bytes: ECDSA P-256 public key (uncompressed, 0x04 || X || Y)
#   Offset 96:  8 bytes : device serial number (random, from manufacturing)
#   Offset 104: 148 bytes: device certificate (DER-encoded, signed by root)
#   Offset 252: 1 byte  : magic byte (0x01 = keys present)
#
# Total: 253 bytes. Well within the 8KB OTP limit. Import os

_KEY_FILE = "/keys.bin"
_MAGIC_OFFSET = 252
_MAGIC_VALUE = 0x01

# Fallback: store keys in flash file. Used when OTP is not available
# or during development. The file is written once during manufacturing
# and read-only during normal operation. Def _read_bytes(offset, length):
    try:
        with open(_KEY_FILE, "rb") as f:
            f.seek(offset)
            return f.read(length)
    except (OSError, ValueError):
        return None


def _write_bytes(offset, data):
    # Read existing file (or create empty), patch the bytes, write back.
    # This is only called during manufacturing. After that, the file
    # is never written again. Try:
        with open(_KEY_FILE, "rb") as f:
            existing = bytearray(f.read())
    except OSError:
        existing = bytearray(256)

    needed = offset + len(data)
    if len(existing) < needed:
        existing.extend(b'\x00' * (needed - len(existing)))

    existing[offset:offset + len(data)] = data

    with open(_KEY_FILE, "wb") as f:
        f.write(bytes(existing))


def has_keys():
    """Check if device keys are present."""
    magic = _read_bytes(_MAGIC_OFFSET, 1)
    return magic is not None and len(magic) == 1 and magic[0] == _MAGIC_VALUE


def get_private_key():
    """Return the 32-byte private key as bytes, or None if not set."""
    return _read_bytes(0, 32)


def get_public_key():
    """Return the 65-byte uncompressed public key, or None if not set."""
    return _read_bytes(32, 65)


def get_serial():
    """Return the 8-byte device serial number as hex string, or None."""
    raw = _read_bytes(96, 8)
    if raw:
        return raw.hex()
    return None


def get_certificate():
    """Return the DER-encoded device certificate as bytes, or None."""
    cert = _read_bytes(104, 148)
    if cert and len(cert) > 0:
        # Trim trailing nulls: cert is variable length, padded to 148
        cert = cert.rstrip(b'\x00')
        if len(cert) > 0:
            return cert
    return None


def burn_keys(private_key, public_key, serial, certificate):
    """Write all device keys. Called once during manufacturing.

    Args:
        private_key: 32 bytes (raw private key)
        public_key: 65 bytes (0x04 || X || Y)
        serial: 8 bytes (device serial)
        certificate: bytes (DER-encoded cert, up to 72 bytes)

    Returns True on success, False on failure.
    """
    try:
        _write_bytes(0, private_key)
        _write_bytes(32, public_key)
        _write_bytes(96, serial)
        # Pad certificate to 148 bytes
        cert_padded = certificate + b'\x00' * (148 - len(certificate))
        _write_bytes(104, cert_padded[:148])
        _write_bytes(_MAGIC_OFFSET, bytes([_MAGIC_VALUE]))
        return True
    except OSError as e:
        print("Failed to burn keys:", e)
        return False


def get_private_key_int():
    """Return the private key as an integer (for ecdsa.sign)."""
    raw = get_private_key()
    if raw and len(raw) == 32:
        return int.from_bytes(raw, 'big')
    return None