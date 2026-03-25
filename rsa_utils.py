"""
rsa_utils.py
============
Shared RSA primitives, string encoding, and nonce/timestamp utilities.
Used by both pkda.py and client.py.

Implements from scratch (no crypto libraries):
  - Miller-Rabin primality test
  - Random prime generation
  - Extended Euclidean Algorithm
  - Modular inverse
  - RSA key-pair generation  →  (p, q, n, φ(n), e, d)
  - RSA encrypt / decrypt    →  c = m^key mod n
  - String ↔ chunked-integer encoding for arbitrary-length messages
  - Nonce generation (128-bit random integer)
  - Timestamp utilities
"""

import random
import math
import secrets
import time


# ──────────────────────────────────────────────────────────────────────────────
# 1.  PRIMALITY & PRIME GENERATION
# ──────────────────────────────────────────────────────────────────────────────

def is_prime(n: int, k: int = 10) -> bool:
    """
    Miller-Rabin probabilistic primality test.
    k rounds → probability of false positive ≤ 4^(-k).
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d  (d odd)
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int = 64) -> int:
    """
    Generate a random prime of exactly `bits` bits.
    Forces MSB=1 (so result is exactly `bits` bits wide) and LSB=1 (odd).
    """
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate


# ──────────────────────────────────────────────────────────────────────────────
# 2.  NUMBER THEORY
# ──────────────────────────────────────────────────────────────────────────────

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that  a*x + b*y = gcd(a, b).
    """
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


def mod_inverse(e: int, phi: int) -> int:
    """
    Modular multiplicative inverse: returns d such that e*d ≡ 1 (mod phi).
    Uses the Extended Euclidean Algorithm.
    Raises ValueError if the inverse does not exist (gcd(e, phi) ≠ 1).
    """
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({e}, {phi}) = {g}")
    return x % phi


# ──────────────────────────────────────────────────────────────────────────────
# 3.  RSA KEY-PAIR GENERATION
# ──────────────────────────────────────────────────────────────────────────────

def generate_rsa_keypair(bits: int = 64) -> tuple[int, int, int, int, int, int]:
    """
    Generate an RSA key pair entirely from scratch.

    Steps:
      1. Choose two distinct random primes p, q  (each `bits` bits wide)
      2. Compute n = p * q                        (modulus)
      3. Compute φ(n) = (p-1)(q-1)               (Euler's totient)
      4. Choose public exponent e = 65537         (standard Fermat prime)
         Fall back to smallest odd e > 1 if gcd(e, φ(n)) ≠ 1
      5. Compute private exponent d = e⁻¹ mod φ(n)

    Returns: (p, q, n, phi_n, e, d)
      Public key  = (e, n)
      Private key = (d, n)
    """
    # Step 1 – primes
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)

    # Step 2 – modulus
    n = p * q

    # Step 3 – totient
    phi_n = (p - 1) * (q - 1)

    # Step 4 – public exponent
    e = 65537
    if math.gcd(e, phi_n) != 1:
        e = 3
        while math.gcd(e, phi_n) != 1:
            e += 2

    # Step 5 – private exponent
    d = mod_inverse(e, phi_n)

    return p, q, n, phi_n, e, d


# ──────────────────────────────────────────────────────────────────────────────
# 4.  RSA ENCRYPT / DECRYPT
# ──────────────────────────────────────────────────────────────────────────────

def rsa_encrypt(message: int, key: int, n: int) -> int:
    """c = m^key mod n   (works for both encryption and decryption)."""
    return pow(message, key, n)


def rsa_decrypt(ciphertext: int, key: int, n: int) -> int:
    """m = c^key mod n   (alias of rsa_encrypt for clarity at call sites)."""
    return pow(ciphertext, key, n)


# ──────────────────────────────────────────────────────────────────────────────
# 5.  STRING ↔ CHUNKED-INTEGER ENCODING
# ──────────────────────────────────────────────────────────────────────────────

def encrypt_string(plaintext: str, key: int, n: int) -> list[int]:
    """
    Encrypt an arbitrary-length string with RSA key (key, n).

    Because RSA requires  m < n, we split the UTF-8 encoded message into
    byte-chunks of size  (n.bit_length() // 8 - 1)  bytes — each chunk is
    guaranteed to be numerically smaller than n.  Each chunk is encrypted
    independently:  c_i = chunk_i ^ key  mod n.

    Returns a list of ciphertext integers (one per chunk).
    """
    chunk_size = (n.bit_length() // 8) - 1
    if chunk_size < 1:
        chunk_size = 1

    encoded = plaintext.encode("utf-8")
    chunks = [encoded[i : i + chunk_size]
              for i in range(0, len(encoded), chunk_size)]

    return [rsa_encrypt(int(chunk.hex(), 16), key, n) for chunk in chunks]


def decrypt_chunks(ciphertext_chunks: list[int], key: int, n: int) -> str:
    """
    Decrypt a list of RSA ciphertext integers back to the original string.
    Reverses encrypt_string: m_i = c_i ^ key mod n, then hex-decode each
    integer back to bytes and concatenate.
    """
    parts = []
    for c in ciphertext_chunks:
        m = rsa_decrypt(c, key, n)
        h = hex(m)[2:]
        if len(h) % 2:
            h = "0" + h
        parts.append(bytes.fromhex(h))
    return b"".join(parts).decode("utf-8")


# ──────────────────────────────────────────────────────────────────────────────
# 6.  NONCE & TIMESTAMP UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

def generate_nonce() -> int:
    """Return a 128-bit cryptographically random nonce (as a Python int)."""
    return secrets.randbits(128)


def current_timestamp() -> int:
    """Return the current Unix epoch time in seconds."""
    return int(time.time())


def timestamp_to_str(ts: int) -> str:
    """Format a Unix timestamp as a human-readable UTC string."""
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))
