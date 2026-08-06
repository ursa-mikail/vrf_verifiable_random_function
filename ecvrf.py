"""
ECVRF-P256-SHA256-TAI

A from-scratch, educational implementation of a *real* Elliptic Curve
Verifiable Random Function, modeled on RFC 9381 (the IETF VRF spec),
using the "Try And Increment" hash-to-curve method on NIST P-256.

Why this replaces the earlier HMAC-based "VRF":
    A real VRF must satisfy: the proof can only be PRODUCED by whoever
    holds the secret key, but it can be VERIFIED by anyone who only has
    the public key. HMAC-based schemes fail this because HMAC needs the
    same secret on both ends -- verification would require the secret
    key too, which defeats the purpose. This version uses elliptic-curve
    point arithmetic so verification only ever touches the public key.

Public API:
    keygen()                              -> (secret_key:int, public_key:Point)
    prove(secret_key, public_key, alpha)  -> proof_bytes (81 bytes)
    proof_to_hash(proof_bytes)            -> beta_bytes (32 bytes, the VRF output)
    verify(public_key, alpha, proof_bytes)-> (valid: bool, beta_bytes_or_None)
"""

import hashlib
import hmac
import os

import p256

SUITE_STRING = b"\xfe"  # arbitrary 1-byte domain separator for this toy suite


def _hash(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


# ---------------------------------------------------------------------------
# 1. Key generation
# ---------------------------------------------------------------------------

def keygen():
    secret_key = int.from_bytes(os.urandom(32), "big") % (p256.N - 1) + 1
    public_key = p256.scalar_mult(secret_key, p256.G)
    return secret_key, public_key


# ---------------------------------------------------------------------------
# 2. Hash-to-curve: deterministically map (public_key, alpha) -> a curve point H
#    "Try And Increment" (RFC 9381 4.4.1): keep hashing with an incrementing
#    counter until the hash decodes as a valid compressed point.
# ---------------------------------------------------------------------------

def _hash_to_curve(public_key, alpha: bytes):
    pk_string = p256.point_to_bytes(public_key)
    ctr = 0
    while ctr < 256:
        candidate = _hash(SUITE_STRING, b"\x01", pk_string, alpha, bytes([ctr]))
        compressed = b"\x02" + candidate  # try the even-y encoding
        H = p256.bytes_to_point(compressed)
        if H is not None:
            return p256.scalar_mult(p256.COFACTOR, H)
        ctr += 1
    raise RuntimeError("hash_to_curve failed to find a valid point (should not happen)")


# ---------------------------------------------------------------------------
# 3. Deterministic nonce generation (RFC 6979 style): derive k from the
#    secret key and message so no external randomness is needed and the
#    same (secret_key, alpha) always yields the same proof.
# ---------------------------------------------------------------------------

def _nonce(secret_key: int, h_string: bytes) -> int:
    sk_bytes = secret_key.to_bytes(32, "big")
    k_material = hmac.new(sk_bytes, h_string, hashlib.sha256).digest()
    k = int.from_bytes(k_material, "big") % p256.N
    if k == 0:
        # astronomically unlikely; re-derive with a domain-separated tweak
        k = int.from_bytes(hmac.new(sk_bytes, h_string + b"\x00", hashlib.sha256).digest(), "big") % p256.N
    return k


# ---------------------------------------------------------------------------
# 4. Fiat-Shamir challenge: binds H, Gamma, and the two commitment points
#    together into a single scalar c.
# ---------------------------------------------------------------------------

def _challenge(H, Gamma, U, V) -> int:
    digest = _hash(
        SUITE_STRING, b"\x02",
        p256.point_to_bytes(H),
        p256.point_to_bytes(Gamma),
        p256.point_to_bytes(U),
        p256.point_to_bytes(V),
    )
    # truncate to 16 bytes, per RFC 9381's cLen convention for this curve size
    return int.from_bytes(digest[:16], "big")


# ---------------------------------------------------------------------------
# 5. Prove: only possible with the secret key
# ---------------------------------------------------------------------------

def prove(secret_key: int, public_key, alpha: bytes) -> bytes:
    H = _hash_to_curve(public_key, alpha)
    Gamma = p256.scalar_mult(secret_key, H)

    h_string = p256.point_to_bytes(H)
    k = _nonce(secret_key, h_string)

    U = p256.scalar_mult(k, p256.G)   # k*G
    V = p256.scalar_mult(k, H)        # k*H
    c = _challenge(H, Gamma, U, V)
    s = (k + c * secret_key) % p256.N

    pi = (
        p256.point_to_bytes(Gamma)      # 33 bytes
        + c.to_bytes(16, "big")         # 16 bytes
        + s.to_bytes(32, "big")         # 32 bytes
    )                                    # = 81 bytes total
    return pi


# ---------------------------------------------------------------------------
# 6. proof_to_hash: turn a valid proof into the actual pseudorandom output.
#    Deliberately separate from prove()/verify() -- you should only ever
#    trust a beta value that came from a proof you verified.
# ---------------------------------------------------------------------------

def proof_to_hash(pi: bytes) -> bytes:
    Gamma, _c, _s = _decode_proof(pi)
    cofactor_gamma = p256.scalar_mult(p256.COFACTOR, Gamma)
    return _hash(SUITE_STRING, b"\x03", p256.point_to_bytes(cofactor_gamma))


def _decode_proof(pi: bytes):
    if len(pi) != 81:
        raise ValueError(f"malformed proof: expected 81 bytes, got {len(pi)}")
    gamma_bytes, c_bytes, s_bytes = pi[:33], pi[33:49], pi[49:81]
    Gamma = p256.bytes_to_point(gamma_bytes)
    if Gamma is None:
        raise ValueError("malformed proof: Gamma is not a valid curve point")
    c = int.from_bytes(c_bytes, "big")
    s = int.from_bytes(s_bytes, "big")
    return Gamma, c, s


# ---------------------------------------------------------------------------
# 7. Verify: only the public key is needed. This is the whole point.
# ---------------------------------------------------------------------------

def verify(public_key, alpha: bytes, pi: bytes):
    """
    Returns (True, beta) if the proof is valid for (public_key, alpha),
    otherwise (False, None). No secret material is used anywhere here.
    """
    try:
        Gamma, c, s = _decode_proof(pi)
    except ValueError:
        return False, None

    if not p256.is_on_curve(Gamma) or Gamma is None:
        return False, None
    if not (0 <= s < p256.N):
        return False, None

    H = _hash_to_curve(public_key, alpha)

    # U = s*G - c*public_key   (reconstructs k*G if the proof is genuine)
    U = p256.point_add(
        p256.scalar_mult(s, p256.G),
        p256.scalar_mult((-c) % p256.N, public_key),
    )
    # V = s*H - c*Gamma        (reconstructs k*H if the proof is genuine)
    V = p256.point_add(
        p256.scalar_mult(s, H),
        p256.scalar_mult((-c) % p256.N, Gamma),
    )

    c_prime = _challenge(H, Gamma, U, V)
    if c_prime != c:
        return False, None

    return True, proof_to_hash(pi)
