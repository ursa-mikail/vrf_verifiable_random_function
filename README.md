# Verifiable Random Function (VRF) — from scratch, step by step

**ECVRF-P256-SHA256-TAI**, modeled on [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381), implemented
in pure Python on the NIST P-256 elliptic curve.

## Files

| File | What it does |
|---|---|
| `p256.py` | Elliptic curve arithmetic (point add, scalar multiply, compress/decompress) on NIST P-256. No external crypto dependency. |
| `ecvrf.py` | The actual VRF: `keygen`, `prove`, `proof_to_hash`, `verify`. |
| `demo.py` | Runnable demonstration, same shape as your original script. |
| `test_ecvrf.py` | Tests that prove the security properties actually hold (not just "it runs"). |

Run it:
```bash
python3 demo.py

"""
VRF DEMONSTRATION (ECVRF-P256-SHA256-TAI)

Public Key: 0234b0350d4aea4103ac200bf56fc18a...

Seed: Blockchain_Height_12345

Random Number (1st): de8c316df1298a47d5bc4fb11ecca6d8749bd1994037ea02aa106026e644cc5c
Proof (1st):         03fdc2083d57c307864e3a453f42ff4f5dcd72faa3d064541908890460259f1d9bd61ecc711446abfc0c23ca991ebae210b4a545a56e2e417bf3496d00e129f60705466ab6bafeac02350f7b69a25ce4da

Random Number (2nd): de8c316df1298a47d5bc4fb11ecca6d8749bd1994037ea02aa106026e644cc5c
Proof (2nd):         03fdc2083d57c307864e3a453f42ff4f5dcd72faa3d064541908890460259f1d9bd61ecc711446abfc0c23ca991ebae210b4a545a56e2e417bf3496d00e129f60705466ab6bafeac02350f7b69a25ce4da

--- Determinism Check ---
Same seed -> same random number: True
Same seed -> same proof:         True

--- Different Seed Test ---
Different seed -> different random number: True
Different seed -> different proof:          True

--- Verification Tests (public key ONLY -- no secret key used below) ---
Correct data verifies:            True (recovered beta matches: True)
Tampered proof rejected:          True

--- Different Key Test ---
Same seed, different key -> different number: True
Other party's proof rejected under our public key: True

============================================================
This is a real VRF: verify() above used ONLY the public key,
seed, and proof -- never the secret key -- yet it correctly
accepts genuine proofs and rejects tampered/forged ones.

"""

python3 test_ecvrf.py
"""
PASS: roundtrip + determinism
PASS: different alpha -> different proof/output
PASS: different key -> different proof
PASS: verification succeeds using only the public key
PASS: tampered proof rejected
PASS: proof does not validate against a different seed
PASS: random forgery attempt correctly rejected
PASS: attacker's own valid proof does not verify under victim's public key

ALL TESTS PASSED

"""
```

---

## Notes

`hmac.new(secret_key, seed, sha256)` generated a proof, but ...
The problem: **HMAC verification requires the same secret key that created it.**
So `verify()` couldn't check anything cryptographically — it just
recomputed `sha256(proof + seed)` and compared. Anyone could invent a fake
`(proof, random_number)` pair for any seed and it would "verify" fine, because
nothing tied the proof to the secret key in a way the public key could check.

That defeats the entire point of a VRF, which is:

> **Only the secret-key holder can produce a valid proof.**
> **Anyone with just the public key can check it's valid.**

To get that property you need public-key math (elliptic curve points), not
a symmetric primitive like HMAC. 

---

## The concept, step by step

```
VRF(secret_key, seed) = (random_number, proof)
verify(public_key, seed, proof) = true / false
```

### 1. Key generation
```
secret_key  = random integer in [1, n-1]
public_key  = secret_key * G          (G = curve generator point)
```
Same idea as any elliptic-curve keypair (ECDSA, EdDSA, etc). `secret_key`
never leaves the prover.

### 2. Hash-to-curve
 
Before signing anything, the seed (`alpha`) is deterministically mapped onto
a *point on the curve*, `H`:
```
H = hash_to_curve(public_key, alpha)
```
alpha isn't used directly as x. It's hashed (along with the public key and a counter) to produce the candidate x. Given that x, look for a valid y.

```
candidate_x = SHA256(suite || 0x01 || public_key || alpha || ctr)   # alpha goes IN here
                              ↓
                    is there a y such that y² = x³ + ax + b (mod p) ?
                              ↓
                    yes → H = (x, y), done
                    no  → bump ctr, hash again, try a new x
```
Why not just use alpha itself as x? A few reasons:

- `alpha` can be any length (a string, a block hash, whatever) — x needs to be exactly 32 bytes and < curve prime p. Hashing normalizes that. alpha has to be known to the verifier. It is not a secret and need not be randomly generated. If it were secret, nobody could check the proof. It's meant to be public and agreed-upon by everyone involved.
- You need retries. Since only ~half of all possible x values have a matching y, you need a way to try a different x if the first one fails — that's what ctr is for. If you used alpha directly as x with no counter, you'd have no way to "try again" when it happens to land on an invalid x — you'd just be stuck.
- Binding to the public key. Mixing public_key into the hash means the same alpha produces a different x (and thus a different H) for every different key — which is what stops one party's proof from being replayed under someone else's key.

So the actual sequence is: alpha → (hashed with pk, ctr) → candidate x → search for y. alpha is an ingredient in deriving x, not x itself.

**The problem it solves.** A curve point is a pair `(x, y)` satisfying
`y² = x³ + ax + b (mod p)`. If you just hash `alpha` straight into a 256-bit
number and use it as `x`, it only corresponds to a valid point *about half
the time* — for the other half, `x³ + ax + b` isn't a perfect square mod `p`,
so no `y` exists. You need an algorithm that always eventually lands on a
valid point, without ever needing external randomness (the whole VRF has to
stay deterministic).
 
**The algorithm ("Try And Increment", RFC 9381 §4.4.1):**
```
hash_to_curve(public_key, alpha):
    pk_string = compress(public_key)              # 33-byte encoding
    ctr = 0
    loop:
        candidate = SHA256(suite || 0x01 || pk_string || alpha || ctr)
        H = decompress(0x02 || candidate)          # try candidate as an x-coordinate
        if H is a valid point:
            return H
        ctr += 1                                    # otherwise bump ctr and rehash
```
 
Step by step:
1. **Build a hash input** mixing the public key, the seed, and a counter — this is what makes `H` unique to `(public_key, alpha)`.
2. **Hash it with SHA-256** → 32 bytes, treated as a candidate `x`-coordinate.
3. **Try to decompress it as a point.** Prepend `0x02` (the "even y" SEC1 prefix) and attempt `y = sqrt(x³ + ax + b) mod p`. Since P-256's prime satisfies `p ≡ 3 (mod 4)`, the square root — *if it exists* — is simply `y = rhs^((p+1)/4) mod p`; square `y` back and check it matches to confirm.
4. **If valid → done.** That point is `H`.
5. **If invalid → increment `ctr`, go back to step 2.** Roughly half of candidates fail, so this almost always finishes in 1–3 tries.
**A real trace** (against an actual keypair, seed `b"seed-1"`):
```
ctr=0: candidate_x = d749fa88...  INVALID (not a quadratic residue mod p)
ctr=1: candidate_x = 14137c7a...  INVALID (not a quadratic residue mod p)
ctr=2: candidate_x = b39a7a01...  INVALID (not a quadratic residue mod p)
ctr=3: candidate_x = 6862bdf4...  VALID -> use this H, stop
```
Three misses, then a hit — completely normal.
 
**Why each ingredient is in the hash:**
 
| Ingredient | Why it's there |
|---|---|
| `public_key` | Ties `H` to a specific prover — two different keys get different `H` for the same seed, so a proof can't be replayed under another key. |
| `alpha` | Ties `H` to the specific seed — different seeds get unrelated, unpredictable points. |
| `ctr` | Lets the algorithm retry with a *different* hash output when a candidate `x` has no square root, with no coin flips or external randomness needed — still 100% deterministic. |
| Fixed `0x02` prefix | RFC 9381 always tries the even-`y` branch first, so there's no ambiguity about which of the two possible `y` values to use — `H` is just defined as whichever compressed point decodes validly under `0x02`. |
 
Given the same `(public_key, alpha)`, this **always** lands on the same `H`
— which is exactly what the prover and every independent verifier need to
agree on without communicating.
 
#### What is `alpha`, and who decides it?
 
`alpha` is just the VRF's input message — any byte string. The VRF itself
doesn't care what it means; that's entirely up to the system using it. What
matters is **who gets to pick `alpha`**, because that determines what the
VRF's output can be trusted to do.
 
In this code it's simply whatever bytes you pass to `prove()` /
`verify()` — e.g. `b"Blockchain_Height_12345"` in the demo. In a real
deployment, `alpha` is typically constructed from data that's:
 
- **Public** — the verifier needs to be able to reconstruct the exact same
  `alpha` independently, or verification is meaningless.
- **Not chosen by the prover after the fact** — otherwise the prover could
  try many `alpha` values, see which output they like best, and submit that
  one. This is why `alpha` is usually built from things outside the
  prover's control, like:
  - a block hash or block height (blockchain randomness beacons, leader election)
  - a round number or epoch counter (lottery draws, committee selection)
  - a previous VRF output chained together with a counter (continuous randomness beacons)
  - a combination of the above plus a fixed context string, so the same
    prover can't reuse a proof for a different purpose
For example, a blockchain doing per-block leader election might set:
```
alpha = block_hash(N-1) || round_number
```
so every validator, using only public chain data, arrives at the identical
`alpha` — and hence the identical `H` and the identical expected VRF output
— without needing to trust or coordinate with the prover at all.
 
**The property this protects:** because `hash_to_curve` maps `alpha` to an
unpredictable point `H`, and the final output is `Hash(Gamma) = Hash(secret_key * H)`,
nobody — including the prover — can predict the VRF's output for a given
`alpha` in advance, and the prover can't retroactively pick a different
`alpha` once one has been fixed by the protocol (e.g. once a block is
mined). If `alpha` were instead something the prover could freely choose or
change after seeing intermediate results, they could grind through options
looking for a favorable "random" outcome, which breaks the whole point of
using a VRF over a plain RNG.
 
### 3. Prove (needs the secret key)
```
Gamma = secret_key * H                     # the core VRF proof point
k     = deterministic_nonce(secret_key, H) # like RFC 6979: no randomness needed
U     = k * G
V     = k * H
c     = Hash(H, Gamma, U, V)               # Fiat-Shamir challenge
s     = k + c * secret_key   (mod n)
 
proof = (Gamma, c, s)
```
`Gamma` is the piece that only the secret-key holder could have computed,
since it's `secret_key * H`. `c` and `s` are a zero-knowledge-style proof
that `Gamma` was built correctly, *without revealing `secret_key`.*
 
### 4. Turn the proof into the random output
```
random_number = Hash(Gamma)
```
Deliberately a separate step from `prove`/`verify` — you should only ever
trust a `random_number` that came out of a proof you already verified.
 
### 5. Verify (needs only the public key)
```
H  = hash_to_curve(public_key, alpha)          # recompute, same as prover did
U' = s*G - c*public_key                        # should reconstruct k*G
V' = s*H - c*Gamma                              # should reconstruct k*H
c' = Hash(H, Gamma, U', V')
 
valid = (c' == c)
```
This is the piece the HMAC version was missing. Because
`public_key = secret_key * G`, the algebra works out so that `U'` and `V'`
land back on `k*G` and `k*H` **only if** `Gamma` really was `secret_key * H`
for the matching secret key. A forger who doesn't know `secret_key` cannot
make this equation balance except by guessing — probability effectively zero.
 
If `valid == true`, the verifier can now trust:
```
random_number = Hash(Gamma)
```
without ever having seen `secret_key`.
 
---
 
## Diagram
 
```
PRNG(seed) --secret_key--> random_number, proof
 
VRF(secret_key, seed)              = random_number, proof
verify(public_key, seed, proof)    = true | false
 
# loosely:
sign(secret_key, seed)  ~= (Gamma, c, s)     <- this is "proof"
Hash(Gamma)              = random_number
```
 
One correction to keep in mind: `random_number` is **not** an input to
`verify` in the strict sense — it's *derived* from the proof only after
`verify` succeeds. That ordering is what makes it safe: you never trust a
random number whose proof you haven't already checked.
 
---
 
## What each guarantee buys you in practice
 
| Property | Why it matters |
|---|---|
| **Deterministic** | Same `(secret_key, seed)` always gives the same output — no way to quietly pick a "better" random number after the fact. |
| **Pseudorandom** | Output is indistinguishable from random to anyone without the secret key. |
| **Publicly verifiable** | Anyone with the public key can confirm the output is legitimate, without trusting the prover or needing the secret key. |
| **Unforgeable** | Without the secret key, you cannot produce a proof that passes `verify()` (short of guessing, with negligible probability). |
 
This combination is why VRFs are used for things like leader election in
blockchains, lottery/randomness beacons, and any system where you need
"random, but provably fair and not manipulable after the fact."
 
---
 
## Honest caveats about this implementation
 
This is written for clarity, not for production:
- No constant-time arithmetic → vulnerable to timing side-channels; a real
  deployment should use a vetted library (e.g. libsodium's `crypto_vrf_*`,
  or a maintained RFC 9381 implementation) rather than hand-rolled curve math.
- The "Try and Increment" hash-to-curve is simple but not the most efficient
  method in the RFC; production suites usually use a constant-time
  hash-to-curve (e.g. SWU/Elligator variants).
- Encoding lengths (`c` truncated to 16 bytes) are a simplification for
  P-256 and not byte-for-byte identical to any specific published test
  vector — treat this as a teaching implementation, not an interoperable one.

---

## What each guarantee buys you in practice

| Property | Why it matters |
|---|---|
| **Deterministic** | Same `(secret_key, seed)` always gives the same output — no way to quietly pick a "better" random number after the fact. |
| **Pseudorandom** | Output is indistinguishable from random to anyone without the secret key. |
| **Publicly verifiable** | Anyone with the public key can confirm the output is legitimate, without trusting the prover or needing the secret key. |
| **Unforgeable** | Without the secret key, you cannot produce a proof that passes `verify()` (short of guessing, with negligible probability). |

This combination is why VRFs are used for things like leader election in
blockchains, lottery/randomness beacons, and any system where you need
"random, but provably fair and not manipulable after the fact."

---

## Honest caveats about this implementation

This is written for clarity, not for production:
- No constant-time arithmetic → vulnerable to timing side-channels; a real
  deployment should use a vetted library (e.g. libsodium's `crypto_vrf_*`,
  or a maintained RFC 9381 implementation) rather than hand-rolled curve math.
- The "Try and Increment" hash-to-curve is simple but not the most efficient
  method in the RFC; production suites usually use a constant-time
  hash-to-curve (e.g. SWU/Elligator variants).
- Encoding lengths (`c` truncated to 16 bytes) are a simplification for
  P-256 and not byte-for-byte identical to any specific published test
  vector — treat this as a teaching implementation, not an interoperable one.
