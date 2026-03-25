"""
client.py
=========
RSA Client for the PKDA-based secure messaging system.

Each client:
  - Generates its own RSA key pair locally (private key never leaves this file).
  - Is pre-loaded with PKDA's public key (e_PKDA, n_PKDA) at creation time,
    simulating out-of-band distribution (e.g. embedded in the client binary).
  - Registers its own public key with the PKDA.
  - Can request any other client's public key from the PKDA and verify the
    response by decrypting it with PKDA's public key.
  - Exchanges confidential messages with other clients using RSA encryption
    under the recipient's public key.

Security properties of client-to-client messages
-------------------------------------------------
  Confidentiality  : ciphertext encrypted with recipient's public key;
                     only the holder of the matching private key can decrypt.
  Replay protection: every message envelope contains a fresh 128-bit nonce
                     and a Unix timestamp.
  Integrity        : any bit-flip in transit makes decryption yield garbage
                     (the JSON parse will fail).
"""

import json
from rsa_utils import (
    generate_rsa_keypair,
    encrypt_string,
    decrypt_chunks,
    generate_nonce,
    current_timestamp,
    timestamp_to_str,
)


class SecurityError(Exception):
    """Raised when a security check (nonce, field, or decryption) fails."""
    pass


class Client:
    """
    Represents one participant in the PKDA-based PKI system.

    Parameters
    ----------
    client_id : str
        Human-readable identifier (e.g. "Alice", "Bob").
    pkda : PKDA
        Reference to the running PKDA server object.  In a real deployment
        this would be replaced by a network socket; here it is a direct
        Python reference to simulate the network call.
    bits : int
        Bit-width of each RSA prime p and q (default 64).
    """

    def __init__(self, client_id: str, pkda, bits: int = 64):
        self.client_id = client_id
        self._pkda     = pkda

        # PKDA's public key is pre-loaded (out-of-band distribution).
        # The client never sees PKDA's private key.
        self.pkda_pub: tuple[int, int] = pkda.public_key

        # Registry of other clients' public keys, filled via PKDA requests.
        self._known_keys: dict[str, tuple[int, int]] = {}
        # Track seen (sender, nonce) pairs to reject replayed ciphertext packets.
        self._seen_message_nonces: set[tuple[str, int]] = set()
        # Accept small clock skew while validating message freshness.
        self._max_clock_skew_seconds = 120

        # ── Generate own RSA key pair ────────────────────────────────────────
        print(f"\n[{client_id}] Generating RSA key pair …")
        p, q, n, phi_n, e, d = generate_rsa_keypair(bits)

        self.p     = p
        self.q     = q
        self.n     = n
        self.phi_n = phi_n
        self.e     = e          # public exponent
        self.d     = d          # private exponent  (never shared)

        self.public_key  = (e, n)
        self.private_key = (d, n)   # kept strictly local

        print(f"[{client_id}]  p          = {p}")
        print(f"[{client_id}]  q          = {q}")
        print(f"[{client_id}]  n          = {n}")
        print(f"[{client_id}]  φ(n)       = {phi_n}")
        print(f"[{client_id}]  e (pub)    = {e}")
        print(f"[{client_id}]  d (priv)   = {d}")

        # ── Register public key with PKDA ────────────────────────────────────
        pkda.register_client(client_id, self.public_key)

    # ── Public-key retrieval via PKDA ─────────────────────────────────────────

    def request_public_key(self, target_id: str) -> tuple[int, int]:
        """
        Ask the PKDA for `target_id`'s public key.

        Protocol (client side)
        ----------------------
        1. Generate a fresh 128-bit nonce_A.
        2. Send {requester=self, target=target_id, nonce_A} to PKDA.
        3. Receive a list of ciphertext integers (the full PKDA response
           encrypted with PKDA's private key d_PKDA).
        4. Decrypt each chunk using PKDA's PUBLIC key e_PKDA.
           → If decryption produces valid JSON, the response is authentic:
             only PKDA (the sole holder of d_PKDA) could have created it.
        5. Verify nonce_A echoed in response equals the one we sent
           (replay-attack protection).
        6. Verify requester and target fields match (substitution protection).
        7. Store and return target's public key.
        """
        nonce_a = generate_nonce()

        print(f"\n[{self.client_id}] → Requesting public key of '{target_id}' from PKDA")
        print(f"[{self.client_id}]   nonce_A = {nonce_a}")

        # ── Step 2: send request to PKDA (network call simulated here) ───────
        encrypted_chunks = self._pkda.handle_public_key_request(
            self.client_id, target_id, nonce_a
        )

        # ── Steps 3-4: decrypt with PKDA's PUBLIC key ─────────────────────────
        e_pkda, n_pkda = self.pkda_pub
        try:
            payload_str = decrypt_chunks(encrypted_chunks, e_pkda, n_pkda)
            payload     = json.loads(payload_str)
        except Exception as exc:
            raise SecurityError(
                f"[{self.client_id}] Failed to decrypt/parse PKDA response — "
                f"possible tampering or wrong PKDA key.  Detail: {exc}"
            )

        # ── Step 5: nonce check ────────────────────────────────────────────────
        if payload["nonce_a"] != nonce_a:
            raise SecurityError(
                f"[{self.client_id}] Nonce mismatch "
                f"(expected {nonce_a}, got {payload['nonce_a']}) — "
                "possible replay attack!"
            )

        # ── Step 6: field integrity check ─────────────────────────────────────
        if payload["requester"] != self.client_id or payload["target"] != target_id:
            raise SecurityError(
                f"[{self.client_id}] Response fields mismatch — "
                "possible substitution attack!"
            )

        # ── Step 6b: freshness check on PKDA timestamp ───────────────────────
        now = current_timestamp()
        if abs(now - int(payload["timestamp"])) > self._max_clock_skew_seconds:
            raise SecurityError(
                f"[{self.client_id}] PKDA response timestamp is stale/out-of-window "
                f"(response={payload['timestamp']}, now={now})."
            )

        # ── Step 7: store and return ───────────────────────────────────────────
        target_pub = (payload["target_pub_e"], payload["target_pub_n"])
        self._known_keys[target_id] = target_pub

        print(f"[{self.client_id}] ✓ PKDA response decrypted successfully (authentic).")
        print(f"[{self.client_id}]   response timestamp = {timestamp_to_str(payload['timestamp'])}")
        print(f"[{self.client_id}]   nonce verified     = {nonce_a}")
        print(f"[{self.client_id}]   stored public key of '{target_id}': "
              f"(e={target_pub[0]}, n={target_pub[1]})")
        return target_pub

    # ── Confidential messaging ─────────────────────────────────────────────────

    def send_message(self, recipient_id: str, plaintext: str) -> dict:
        """
        Encrypt `plaintext` with `recipient_id`'s public key and return the
        packet (simulates putting the message on the network).

        Envelope (JSON, encrypted before sending):
          {
            "from"      : <sender_id>,
            "to"        : <recipient_id>,
            "timestamp" : <unix epoch>,
            "nonce"     : <128-bit random int>,
            "body"      : <plaintext message>,
          }

        The entire envelope is chunk-encrypted with recipient's public key
        so only the recipient (holder of the matching private key) can read it.
        """
        if recipient_id not in self._known_keys:
            raise RuntimeError(
                f"[{self.client_id}] Public key of '{recipient_id}' not known. "
                "Request it from PKDA first."
            )

        e_r, n_r = self._known_keys[recipient_id]
        nonce     = generate_nonce()
        ts        = current_timestamp()

        envelope = json.dumps({
            "from"      : self.client_id,
            "to"        : recipient_id,
            "timestamp" : ts,
            "nonce"     : nonce,
            "body"      : plaintext,
        })

        ciphertext_chunks = encrypt_string(envelope, e_r, n_r)

        print(f"\n[{self.client_id}] → Sending to '{recipient_id}'")
        print(f"[{self.client_id}]   plaintext  : {plaintext}")
        print(f"[{self.client_id}]   timestamp  : {timestamp_to_str(ts)}")
        print(f"[{self.client_id}]   nonce      : {nonce}")
        print(f"[{self.client_id}]   ciphertext : "
              f"{ciphertext_chunks[:2]}{'...' if len(ciphertext_chunks) > 2 else ''}")

        # The packet that travels over the "network" — ciphertext only
        return {
            "from"      : self.client_id,   # unencrypted header (routing info)
            "to"        : recipient_id,
            "ciphertext": ciphertext_chunks,
        }

    def receive_message(self, packet: dict) -> str:
        """
        Decrypt an incoming packet using this client's own private key.
        Returns the plaintext message body.

        Raises ValueError if the packet is not addressed to this client.
        """
        if packet["to"] != self.client_id:
            raise ValueError(
                f"[{self.client_id}] Packet addressed to '{packet['to']}', not me!"
            )

        plaintext_json = decrypt_chunks(packet["ciphertext"], self.d, self.n)
        msg = json.loads(plaintext_json)

        # Reject header/body mismatches to prevent routing/substitution tricks.
        if msg["to"] != self.client_id or msg["from"] != packet["from"]:
            raise SecurityError(
                f"[{self.client_id}] Message header/body mismatch detected."
            )

        # Enforce message freshness using timestamp.
        now = current_timestamp()
        if abs(now - int(msg["timestamp"])) > self._max_clock_skew_seconds:
            raise SecurityError(
                f"[{self.client_id}] Stale message rejected "
                f"(message_ts={msg['timestamp']}, now={now})."
            )

        # Replay protection: reject if same sender nonce appears again.
        replay_key = (msg["from"], int(msg["nonce"]))
        if replay_key in self._seen_message_nonces:
            raise SecurityError(
                f"[{self.client_id}] Replay detected for sender '{msg['from']}' "
                f"with nonce {msg['nonce']}."
            )
        self._seen_message_nonces.add(replay_key)

        print(f"\n[{self.client_id}] ← Received from '{packet['from']}'")
        print(f"[{self.client_id}]   body       : {msg['body']}")
        print(f"[{self.client_id}]   timestamp  : {timestamp_to_str(msg['timestamp'])}")
        print(f"[{self.client_id}]   nonce      : {msg['nonce']}")

        return msg["body"]
