# lib/ecdsa.py: minimal ECDSA P-256 sign for MicroPython (RP2350)
#
# Pure Python. No C extension. No mbedTLS. ~150 lines.
# Designed for one-time use during provisioning: takes 2-5 seconds
# on the RP2350, which is fine because the user is watching a spinner.
#
# Only implements sign(): verify happens in the browser via Web Crypto.
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


# --- Random k from TRNG ---

def _rand_int(bits):
    # Generate a random integer from the Pico's TRNG.
    # machine.rng() returns a 32-bit random number on the RP2 port. Try:
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