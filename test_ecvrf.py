import ecvrf
import p256


def test_roundtrip_and_determinism():
    sk, pk = ecvrf.keygen()
    alpha = b"Blockchain_Height_12345"

    pi1 = ecvrf.prove(sk, pk, alpha)
    pi2 = ecvrf.prove(sk, pk, alpha)
    assert pi1 == pi2, "same (secret_key, alpha) must give the same proof"

    beta1 = ecvrf.proof_to_hash(pi1)
    beta2 = ecvrf.proof_to_hash(pi2)
    assert beta1 == beta2

    ok, beta_v = ecvrf.verify(pk, alpha, pi1)
    assert ok is True
    assert beta_v == beta1
    print("PASS: roundtrip + determinism")


def test_different_alpha_gives_different_output():
    sk, pk = ecvrf.keygen()
    pi_a = ecvrf.prove(sk, pk, b"seed-A")
    pi_b = ecvrf.prove(sk, pk, b"seed-B")
    assert pi_a != pi_b
    assert ecvrf.proof_to_hash(pi_a) != ecvrf.proof_to_hash(pi_b)
    print("PASS: different alpha -> different proof/output")


def test_different_key_gives_different_output():
    sk1, pk1 = ecvrf.keygen()
    sk2, pk2 = ecvrf.keygen()
    alpha = b"same-seed-for-both"
    pi1 = ecvrf.prove(sk1, pk1, alpha)
    pi2 = ecvrf.prove(sk2, pk2, alpha)
    assert pi1 != pi2
    print("PASS: different key -> different proof")


def test_verification_needs_only_public_key():
    sk, pk = ecvrf.keygen()
    alpha = b"public-key-only-check"
    pi = ecvrf.prove(sk, pk, alpha)
    # Simulate "the verifier": call verify with ONLY pk, alpha, pi -- no sk in scope.
    ok, beta = ecvrf.verify(pk, alpha, pi)
    assert ok and beta == ecvrf.proof_to_hash(pi)
    print("PASS: verification succeeds using only the public key")


def test_tampered_proof_is_rejected():
    sk, pk = ecvrf.keygen()
    alpha = b"tamper-test"
    pi = bytearray(ecvrf.prove(sk, pk, alpha))
    pi[-1] ^= 0x01  # flip a bit in s
    ok, beta = ecvrf.verify(pk, alpha, bytes(pi))
    assert ok is False and beta is None
    print("PASS: tampered proof rejected")


def test_wrong_alpha_is_rejected():
    sk, pk = ecvrf.keygen()
    pi = ecvrf.prove(sk, pk, b"original-seed")
    ok, beta = ecvrf.verify(pk, b"different-seed", pi)
    assert ok is False and beta is None
    print("PASS: proof does not validate against a different seed")


def test_cannot_forge_without_secret_key():
    """
    The core security property: someone who does NOT know the secret key,
    but who DOES know the public key and can pick alpha, cannot produce a
    proof that verify() accepts -- other than by guessing (probability
    ~ 1/2^128, i.e. never, for this challenge size).
    """
    sk, pk = ecvrf.keygen()
    alpha = b"attacker-controlled-seed"

    # Attacker tries to forge by picking a random Gamma/c/s without sk.
    import os
    forged_gamma = p256.scalar_mult(
        int.from_bytes(os.urandom(32), "big") % p256.N, p256.G
    )
    forged = (
        p256.point_to_bytes(forged_gamma)
        + os.urandom(16)
        + os.urandom(32)
    )
    ok, beta = ecvrf.verify(pk, alpha, forged)
    assert ok is False, "forged proof must NOT verify"
    print("PASS: random forgery attempt correctly rejected")


def test_proof_from_wrong_key_does_not_verify_under_victim_pk():
    sk_attacker, pk_attacker = ecvrf.keygen()
    sk_victim, pk_victim = ecvrf.keygen()
    alpha = b"shared-seed"

    attacker_proof = ecvrf.prove(sk_attacker, pk_attacker, alpha)
    ok, beta = ecvrf.verify(pk_victim, alpha, attacker_proof)
    assert ok is False
    print("PASS: attacker's own valid proof does not verify under victim's public key")


if __name__ == "__main__":
    test_roundtrip_and_determinism()
    test_different_alpha_gives_different_output()
    test_different_key_gives_different_output()
    test_verification_needs_only_public_key()
    test_tampered_proof_is_rejected()
    test_wrong_alpha_is_rejected()
    test_cannot_forge_without_secret_key()
    test_proof_from_wrong_key_does_not_verify_under_victim_pk()
    print("\nALL TESTS PASSED")
