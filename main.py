"""
main.py
=======
Demo driver for the RSA-based PKDA system.

Wires together one PKDA server and two clients (Alice and Bob),
runs the full key-exchange and messaging protocol, and prints
every step in detail.

Run with:
    python main.py

File structure
--------------
    rsa_utils.py  –  RSA primitives, encoding, nonce/timestamp helpers
    pkda.py       –  PKDA server class
    client.py     –  Client class
    main.py       –  this file; demo / entry-point

Protocol steps demonstrated
----------------------------
  1. PKDA generates its RSA key pair.
  2. Alice generates her RSA key pair and registers with PKDA.
  3. Bob   generates his RSA key pair and registers with PKDA.
  4. Alice requests Bob's public key from PKDA (encrypted response).
  5. Bob   requests Alice's public key from PKDA (encrypted response).
  6. Alice sends Hi1, Hi2, Hi3 to Bob (encrypted with Bob's public key).
  7. Bob   sends Got-it1, Got-it2, Got-it3 to Alice (encrypted with Alice's key).
"""

from pkda   import PKDA
from client import Client


def separator(title: str = "") -> None:
    width = 62
    if title:
        pad = (width - len(title) - 2) // 2
        print("\n" + "─" * pad + f" {title} " + "─" * pad)
    else:
        print("\n" + "─" * width)


def main() -> None:
    print("\n" + "═" * 62)
    print("   RSA-BASED PUBLIC KEY DISTRIBUTION AUTHORITY (PKDA)")
    print("   Full Demo: Key Generation → Exchange → Encrypted Messaging")
    print("═" * 62)

    # ── STEP 1: PKDA starts up and generates its key pair ────────────────────
    separator("STEP 1 — PKDA Initialization")
    pkda = PKDA(bits=64)

    # ── STEP 2 & 3: Clients start up, generate keys, register with PKDA ─────
    separator("STEP 2 — Alice Initialization & Registration")
    alice = Client("Alice", pkda, bits=64)

    separator("STEP 3 — Bob Initialization & Registration")
    bob = Client("Bob", pkda, bits=64)

    # ── STEP 4: Alice requests Bob's public key via PKDA ─────────────────────
    separator("STEP 4 — Alice requests Bob's public key from PKDA")
    alice.request_public_key("Bob")

    # ── STEP 5: Bob requests Alice's public key via PKDA ─────────────────────
    separator("STEP 5 — Bob requests Alice's public key from PKDA")
    bob.request_public_key("Alice")

    # ── STEP 5b: Self-key lookup demo (client requesting own public key) ─────
    separator("STEP 5b — Alice requests her own public key from PKDA")
    alice.request_public_key("Alice")

    # ── STEP 6: Alice → Bob, three messages ──────────────────────────────────
    separator("STEP 6 — Alice sends 3 messages to Bob")
    for msg in ["Hi1", "Hi2", "Hi3"]:
        packet = alice.send_message("Bob", msg)
        bob.receive_message(packet)

    # ── STEP 7: Bob → Alice, three acknowledgements ───────────────────────────
    separator("STEP 7 — Bob responds to Alice")
    for msg in ["Got-it1", "Got-it2", "Got-it3"]:
        packet = bob.send_message("Alice", msg)
        alice.receive_message(packet)

    # ── Summary ───────────────────────────────────────────────────────────────
    separator("DEMO COMPLETE")
    print()
    print("✓  RSA key generation (p, q, n, φ, e, d) — implemented from scratch")
    print("✓  PKDA response encrypted with PKDA's private key d")
    print("✓  Clients decrypt PKDA response with PKDA's public key e")
    print("✓  Nonce echoed & verified in every PKDA response")
    print("✓  Timestamp included in every PKDA response and message")
    print("✓  Client-to-client messages encrypted with recipient's public key")
    print("✓  Alice → Bob:   Hi1, Hi2, Hi3")
    print("✓  Bob   → Alice: Got-it1, Got-it2, Got-it3")
    print()


if __name__ == "__main__":
    main()
