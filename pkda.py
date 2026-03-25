"""
pkda.py
=======
Public Key Distribution Authority (PKDA) server.

Responsibilities:
  - Generates and holds its own RSA key pair (p, q, n, φ, e, d).
  - Maintains a registry of client public keys  { client_id: (e, n) }.
  - Handles client registrations.
  - Responds to public-key requests by encrypting the ENTIRE response
    payload with its PRIVATE key d_PKDA, so that any holder of the
    corresponding PUBLIC key e_PKDA can:
      (a) decrypt the response   →  confidentiality to authorised parties
      (b) trust its authenticity →  only PKDA owns d_PKDA

Pre-condition (security assumption):
  PKDA's public key (e_PKDA, n_PKDA) is distributed to all clients via a
  secure out-of-band channel before the protocol begins (analogous to root
  CA certificates pre-installed in browsers/OS).
"""

import json
from rsa_utils import (
    generate_rsa_keypair,
    encrypt_string,
    current_timestamp,
    timestamp_to_str,
)


class PKDA:
    """
    Public Key Distribution Authority.

    Public interface
    ----------------
    pkda.public_key              → (e, n)   share this with all clients
    pkda.register_client(id, pk) → store a client's public key
    pkda.handle_public_key_request(requester, target, nonce)
                                 → list[int]  (ciphertext chunks)
    """

    def __init__(self, bits: int = 64):
        print("=" * 60)
        print("[PKDA] Generating RSA key pair …")

        p, q, n, phi_n, e, d = generate_rsa_keypair(bits)

        self.p     = p
        self.q     = q
        self.n     = n
        self.phi_n = phi_n
        self.e     = e          # public exponent
        self.d     = d          # private exponent  (kept secret)

        self.public_key  = (e, n)
        self.private_key = (d, n)   # never shared with anyone

        self._registry: dict[str, tuple[int, int]] = {}

        print(f"[PKDA]  p          = {p}")
        print(f"[PKDA]  q          = {q}")
        print(f"[PKDA]  n          = {n}")
        print(f"[PKDA]  φ(n)       = {phi_n}")
        print(f"[PKDA]  e (pub)    = {e}")
        print(f"[PKDA]  d (priv)   = {d}")
        print(f"[PKDA] Public key  : (e={e}, n={n})")
        print("=" * 60)

    # ── Registration ─────────────────────────────────────────────────────────

    def register_client(self, client_id: str, public_key: tuple[int, int]) -> None:
        """
        Store a client's public key in the registry.
        Called once per client during the bootstrap/registration phase.
        The registration channel is assumed to be secure (out-of-band).
        """
        self._registry[client_id] = public_key
        e_c, n_c = public_key
        print(f"[PKDA] Registered '{client_id}'  →  public key (e={e_c}, n={n_c})")

    # ── Key-distribution request ──────────────────────────────────────────────

    def handle_public_key_request(
        self,
        requester_id: str,
        target_id: str,
        nonce_a: int,
    ) -> list[int]:
        """
        Respond to a request from `requester_id` for the public key of `target_id`.

        Protocol
        --------
        Plaintext payload (JSON, sorted keys):
          {
            "timestamp"    : <unix epoch>,
            "requester"    : <requester_id>,
            "target"       : <target_id>,
            "nonce_a"      : <nonce sent by requester>,   ← echoed for replay protection
            "target_pub_e" : <e of target>,
            "target_pub_n" : <n of target>,
          }

        The ENTIRE payload is RSA-encrypted chunk-by-chunk with PKDA's
        PRIVATE key d.  Wire format: list[int]  (no plaintext travels).

        Security guarantee
        ------------------
        Only PKDA holds d_PKDA, so only PKDA could have produced ciphertext
        that decrypts correctly under e_PKDA.  A client that successfully
        decrypts and parses the JSON knows the response is authentic.
        """
        if target_id not in self._registry:
            raise ValueError(f"[PKDA] Unknown client: '{target_id}'")

        e_b, n_b = self._registry[target_id]
        ts = current_timestamp()

        # Build plaintext payload
        payload = {
            "timestamp"    : ts,
            "requester"    : requester_id,
            "target"       : target_id,
            "nonce_a"      : nonce_a,
            "target_pub_e" : e_b,
            "target_pub_n" : n_b,
        }
        payload_str = json.dumps(payload, sort_keys=True)

        # Encrypt the ENTIRE payload with PKDA's PRIVATE key d
        encrypted_chunks = encrypt_string(payload_str, self.d, self.n)

        print(f"\n[PKDA] → Key request: '{requester_id}' asks for '{target_id}' public key")
        print(f"[PKDA]   timestamp        = {timestamp_to_str(ts)}")
        print(f"[PKDA]   nonce_A          = {nonce_a}")
        print(f"[PKDA]   target e_B       = {e_b}")
        print(f"[PKDA]   target n_B       = {n_b}")
        print(f"[PKDA]   plaintext payload: {payload_str}")
        print(f"[PKDA]   encrypted chunks : "
              f"{encrypted_chunks[:2]}{'...' if len(encrypted_chunks) > 2 else ''}")
        print(f"[PKDA]   (encrypted with PKDA private key d)")

        return encrypted_chunks
