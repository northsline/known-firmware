# lib/ecdsa.py: minimal ECDSA P-256 sign + verify for MicroPython (RP2350)
#
# Pure Python. No C extension. No mbedTLS.
# Designed for one-time use during provisioning: takes 2-5 seconds
# on the RP2350, which is fine because the user is watching a spinner.
#
# Implements sign() and verify() for ECDSA P-256 SHA-256.
# Uses the Pico's TRNG (machine.rng) for the per-signature k.
# Outputs DER-encoded signatures that Web Crypto's SubtleCrypto.verify accepts.
#
# Curve: NIST P-256 (secp256r1)
# Hash: SHA-256 (hardware-accelerated on RP2350 via hashlib)

import hashlib
import struct

# --- P-256 curve parameters ---

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G = (GX, GY)


# --- Modular arithmetic ---

def _inv_mod(a, m):
    # Extended Euclidean GCD
    if a < 0 or a >= m:
        a = a % m
    lm, hm = 1, 0
    low, high = a, m
    while low > 1:
        r = high // low
        nm = hm - lm * r
        new = high - low * r
        hm, high = lm, low
        lm, low = nm, new
    return lm % m


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        # point doubling
        s = (3 * x1 * x1 + A) * _inv_mod(2 * y1, P) % P
    else:
        s = (y2 - y1) * _inv_mod(x2 - x1, P) % P
    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    return (x3, y3)


def _scalar_mult(k, point):
    # Double-and-add
    result = None
    addend = point
    while k > 0:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


# --- DER encoding ---

def _int_to_der_bytes(n):
    # Encode integer as DER INTEGER content (big-endian, minimal, leading
    # zero if high bit set to keep it positive)
    if n == 0:
        return b'\x00'
    b = b''
    while n > 0:
        b = bytes([n & 0xff]) + b
        n >>= 8
    if b[0] & 0x80:
        b = b'\x00' + b
    return b


def _der_encode_sig(r, s):
    # ASN.1 DER SEQUENCE { INTEGER r, INTEGER s }
    r_bytes = _int_to_der_bytes(r)
    s_bytes = _int_to_der_bytes(s)
    r_tlv = bytes([0x02, len(r_bytes)]) + r_bytes
    s_tlv = bytes([0x02, len(s_bytes)]) + s_bytes
    seq_content = r_tlv + s_tlv
    return bytes([0x30, len(seq_content)]) + seq_content


# --- DER decoding ---

def _der_decode_sig(sig_der):
    # Parse ASN.1 DER SEQUENCE { INTEGER r, INTEGER s }
    # Returns (r, s) as integers, or raises ValueError on malformed input.
    if len(sig_der) < 8:
        raise ValueError("DER signature too short")
    if sig_der[0] != 0x30:
        raise ValueError("Expected SEQUENCE tag")
    seq_len = sig_der[1]
    if seq_len + 2 != len(sig_der):
        raise ValueError("SEQUENCE length mismatch")
    pos = 2
    if sig_der[pos] != 0x02:
        raise ValueError("Expected INTEGER tag for r")
    pos += 1
    r_len = sig_der[pos]
    pos += 1
    if pos + r_len > len(sig_der):
        raise ValueError("r overflows signature")
    r_bytes = sig_der[pos:pos + r_len]
    pos += r_len
    if sig_der[pos] != 0x02:
        raise ValueError("Expected INTEGER tag for s")
    pos += 1
    s_len = sig_der[pos]
    pos += 1
    if pos + s_len != len(sig_der):
        raise ValueError("s length mismatch")
    s_bytes = sig_der[pos:pos + s_len]
    r = int.from_bytes(r_bytes, 'big')
    s = int.from_bytes(s_bytes, 'big')
    if r < 1 or r >= N or s < 1 or s >= N:
        raise ValueError("r or s out of range")
    return r, s


# --- Random k from TRNG ---

def _rand_int(bits):
    # Generate a random integer from the Pico's TRNG.
    # machine.rng() returns a 32-bit random number on the RP2 port.
    try:
        from machine import rng
    except ImportError:
        import os
        # Fallback: os.urandom should work on RP2 as well
        return int.from_bytes(os.urandom(bits // 8), 'big')
    n_bytes = bits // 8
    chunks = []
    for _ in range(0, n_bytes, 4):
        chunks.append(rng() & 0xffffffff)
    raw = b''
    for c in chunks:
        raw += struct.pack('>I', c)
    return int.from_bytes(raw[:n_bytes], 'big')


# --- Public API ---

def sign(private_key_int, message_bytes):
    """Sign a message with ECDSA P-256.

    Args:
        private_key_int: 32-byte private key as an integer (0 < k < N)
        message_bytes: the raw message to sign (will be SHA-256 hashed internally)

    Returns:
        DER-encoded signature bytes (typically 70-72 bytes)
    """
    # Hash the message
    h = hashlib.sha256(message_bytes).digest()
    z = int.from_bytes(h, 'big')

    # Generate per-signature k from TRNG
    while True:
        k = _rand_int(256)
        if 1 <= k < N:
            break

    # R = k * G
    point = _scalar_mult(k, G)
    r = point[0] % N
    if r == 0:
        # Astronomically unlikely, but handle it
        return sign(private_key_int, message_bytes)

    # s = k^(-1) * (z + r * private_key) mod N
    k_inv = _inv_mod(k, N)
    s = (k_inv * (z + r * private_key_int)) % N
    if s == 0:
        return sign(private_key_int, message_bytes)

    # Low-S normalization (BIP-62 / RFC 6979 convention)
    # Web Crypto accepts both high-S and low-S, but low-S is standard
    if s > N // 2:
        s = N - s

    return _der_encode_sig(r, s)


def public_key_bytes(private_key_int):
    """Derive the public key (uncompressed point) from the private key.

    Returns 65 bytes: 0x04 || X(32) || Y(32)
    Used by the browser to verify the nonce signature.
    """
    point = _scalar_mult(private_key_int, G)
    x = point[0].to_bytes(32, 'big')
    y = point[1].to_bytes(32, 'big')
    return b'\x04' + x + y


def verify(public_key_bytes, signature_der, message_bytes):
    """Verify an ECDSA P-256 SHA-256 signature.

    Args:
        public_key_bytes: 65-byte uncompressed public key (0x04 || X || Y)
        signature_der: DER-encoded signature (typically 70-72 bytes)
        message_bytes: the raw message that was signed (will be SHA-256
                       hashed internally)

    Returns:
        True if the signature is valid, False otherwise.
    """
    if len(public_key_bytes) != 65 or public_key_bytes[0] != 0x04:
        return False

    try:
        r, s = _der_decode_sig(signature_der)
    except (ValueError, IndexError):
        return False

    h = hashlib.sha256(message_bytes).digest()
    z = int.from_bytes(h, 'big')

    w = _inv_mod(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N

    qx = int.from_bytes(public_key_bytes[1:33], 'big')
    qy = int.from_bytes(public_key_bytes[33:65], 'big')
    Q = (qx, qy)

    p1 = _scalar_mult(u1, G)
    p2 = _scalar_mult(u2, Q)
    point = _point_add(p1, p2)

    if point is None:
        return False

    v = point[0] % N
    return v == r