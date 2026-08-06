"""
Minimal pure-Python implementation of NIST P-256 (secp256r1) elliptic curve
arithmetic. No external crypto dependency for the point operations, so we
have full control over every step of the ECVRF construction that uses them.

All constants below are the standard NIST P-256 domain parameters.
"""

# ---- Curve parameters (NIST P-256 / secp256r1), each a 64-hex-digit (32 byte) integer ----
P = int("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
A = int("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16)  # = P - 3
B = int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
N = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)  # group order
GX = int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
GY = int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
G = (GX, GY)
COFACTOR = 1  # P-256 has cofactor 1


def inv_mod(a, m):
    return pow(a, m - 2, m)


def is_on_curve(pt):
    if pt is None:
        return True
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None  # point at infinity
    if p1 == p2:
        if y1 == 0:
            return None
        m = (3 * x1 * x1 + A) * inv_mod(2 * y1, P) % P
    else:
        m = (y2 - y1) * inv_mod((x2 - x1) % P, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k, pt):
    k = k % N
    result = None
    addend = pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def point_to_bytes(pt):
    """Compressed SEC1 encoding: 0x02/0x03 prefix + 32-byte X coordinate."""
    if pt is None:
        return b"\x00" * 33
    x, y = pt
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big")


def bytes_to_point(data):
    """Decompress a SEC1 compressed point. Returns None if invalid."""
    if len(data) != 33 or data[0] not in (2, 3):
        return None
    x = int.from_bytes(data[1:], "big")
    if x >= P:
        return None
    rhs = (x * x * x + A * x + B) % P
    # P % 4 == 3 for P-256, so modular sqrt is a direct exponentiation.
    y = pow(rhs, (P + 1) // 4, P)
    if (y * y) % P != rhs:
        return None  # x is not a valid curve coordinate (not a quadratic residue)
    if (y % 2 == 0) != (data[0] == 2):
        y = P - y
    pt = (x, y)
    if not is_on_curve(pt):
        return None
    return pt


assert is_on_curve(G), "generator must lie on the curve"
