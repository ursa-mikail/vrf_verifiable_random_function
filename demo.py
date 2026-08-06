import p256
import ecvrf


def hx(b):
    return b.hex()


if __name__ == "__main__":
    print("VRF DEMONSTRATION (ECVRF-P256-SHA256-TAI)\n")

    secret_key, public_key = ecvrf.keygen()
    seed = b"Blockchain_Height_12345"

    print(f"Public Key: {hx(p256.point_to_bytes(public_key))[:32]}...\n")
    print(f"Seed: {seed.decode()}\n")

    proof1 = ecvrf.prove(secret_key, public_key, seed)
    random_num1 = ecvrf.proof_to_hash(proof1)
    print(f"Random Number (1st): {hx(random_num1)}")
    print(f"Proof (1st):         {hx(proof1)}\n")

    proof2 = ecvrf.prove(secret_key, public_key, seed)
    random_num2 = ecvrf.proof_to_hash(proof2)
    print(f"Random Number (2nd): {hx(random_num2)}")
    print(f"Proof (2nd):         {hx(proof2)}\n")

    print("--- Determinism Check ---")
    print(f"Same seed -> same random number: {random_num1 == random_num2}")
    print(f"Same seed -> same proof:         {proof1 == proof2}")

    new_seed = b"Different_Seed"
    proof3 = ecvrf.prove(secret_key, public_key, new_seed)
    random_num3 = ecvrf.proof_to_hash(proof3)
    print("\n--- Different Seed Test ---")
    print(f"Different seed -> different random number: {random_num1 != random_num3}")
    print(f"Different seed -> different proof:          {proof1 != proof3}")

    print("\n--- Verification Tests (public key ONLY -- no secret key used below) ---")
    ok, beta = ecvrf.verify(public_key, seed, proof1)
    print(f"Correct data verifies:            {ok} (recovered beta matches: {beta == random_num1})")

    tampered = bytearray(proof1)
    tampered[-1] ^= 0x01
    ok_tampered, _ = ecvrf.verify(public_key, seed, bytes(tampered))
    print(f"Tampered proof rejected:          {ok_tampered is False}")

    sk2, pk2 = ecvrf.keygen()
    proof4 = ecvrf.prove(sk2, pk2, seed)
    random_num4 = ecvrf.proof_to_hash(proof4)
    print("\n--- Different Key Test ---")
    print(f"Same seed, different key -> different number: {random_num1 != random_num4}")

    ok_wrong_key, _ = ecvrf.verify(public_key, seed, proof4)
    print(f"Other party's proof rejected under our public key: {ok_wrong_key is False}")

    print("\n" + "=" * 60)
    print("This is a real VRF: verify() above used ONLY the public key,")
    print("seed, and proof -- never the secret key -- yet it correctly")
    print("accepts genuine proofs and rejects tampered/forged ones.")
