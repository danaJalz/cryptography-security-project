#prepared by "Dana Alzahrani 2310370"  and  "sara Jad 2311212"

# ---------------------------------------------------------------
# Enhanced EC-Schnorr Signature Protocol (with Security Improvements)
# Prepared by: "Dana Alzahrani 2310370" and "Sara Jad 2311212"
#
# Features:
#  - Deterministic nonce (RFC6979-style)
#  - Public key validation
#  - Scalar blinding for side-channel protection
#  - Proof-of-Possession (PoP)
#  - Full demo tests
# ---------------------------------------------------------------

from ecdsa import SigningKey, SECP256k1             # ECC key generation & curve operations
from ecdsa.ellipticcurve import INFINITY           # Point-at-infinity constant
import hashlib, hmac, secrets                      # Hashing + HMAC + secure randomness
from dataclasses import dataclass                  # For clean signature struct



# Global curve parameters
curve = SECP256k1                                  # Use secp256k1 elliptic curve
G = curve.generator                                # Base point G
n = curve.order                                    # Curve subgroup order



# Signature structure
@dataclass
class Signature:
    s: int                                         # Signature component s
    e: int                                         # Challenge e



# Deterministic Nonce (RFC6979-style)
# Ensures the nonce k is generated securely and repeatably,
# preventing nonce reuse attacks that leak private keys.
def deterministic_nonce_rfc6979(x: int, message: bytes, q: int) -> int:
    bx = x.to_bytes((q.bit_length() + 7) // 8, 'big')   # Convert private scalar to bytes

    hlen = 32                                           # SHA-256 output size
    V = b'\x01' * hlen                                  # Internal RFC6979 state
    K = b'\x00' * hlen                                  # Internal RFC6979 key

    # Step 1: Update K and V (per RFC6979)
    K = hmac.new(K, V + b'\x00' + bx + message, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()

    K = hmac.new(K, V + b'\x01' + bx + message, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()

    # Step 2: Generate candidate nonce
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = int.from_bytes(V, 'big') % q               # Convert output to int mod q
        if 1 <= k < q:                                 # Valid nonce
            return k



# Hash function H(R || message)
# Produces challenge e used in signature
def hash_point_message(R, message: bytes) -> int:
    rx = R.x().to_bytes((n.bit_length() + 7) // 8, 'big')
    ry = R.y().to_bytes((n.bit_length() + 7) // 8, 'big')
    digest = hashlib.sha256(rx + ry + message).digest()
    return int.from_bytes(digest, 'big') % n



# Public Key Validation
# Ensures Y is a valid elliptic-curve point
def validate_public_key(pubkey) -> bool:
    try:
        P = pubkey.pubkey.point                        # Extract EC point

        if P is None or P == INFINITY:                 # Must not be infinity
            return False

        curve_obj = curve.curve                        # Equation parameters
        p = curve_obj.p()                              # Prime field modulus

        # Verify P satisfies the curve equation: y² = x³ + ax + b mod p
        if (P.y()**2 - (P.x()**3 + curve_obj.a()*P.x() + curve_obj.b())) % p != 0:
            return False

        # Verify correct subgroup: n*P must equal infinity
        if (P * n) != INFINITY:
            return False

        return True                                    # All checks passed
    except:
        return False



# Scalar Blinding (Protection from Side-Channel Attacks)
def scalar_blinded_s(k: int, e: int, x: int) -> int:
    r = secrets.randbelow(n)                           # Blinding factor
    x_blind = x + r * n                                # A blinded private scalar
    return (k + e * x_blind) % n                       # Compute signature s securely


# Schnorr Signing (Improved)
def schnorr_sign(message: bytes, sk: SigningKey) -> Signature:
    x = sk.privkey.secret_multiplier                  # Private key scalar
    k = deterministic_nonce_rfc6979(x, message, n)    # Deterministic nonce
    R = k * G                                         # Commitment point
    e = hash_point_message(R, message)                # Challenge
    s = scalar_blinded_s(k, e, x)                     # Signature value
    return Signature(s=s, e=e)



# Schnorr Verification
def schnorr_verify(message: bytes, sig: Signature, pubkey) -> bool:
    if not validate_public_key(pubkey):               # Validate public key first
        return False

    s, e = sig.s, sig.e
    Y = pubkey.pubkey.point                           # Public key point
    R_prime = s * G + (-e * Y)                        # Recompute R'

    if R_prime == INFINITY:                           # Invalid signature
        return False

    e_check = hash_point_message(R_prime, message)    # Recompute challenge
    return e_check == e                               # Signature valid if equal


# Proof-of-Possession (PoP)
# Prevents rogue-key attacks
POP_DOMAIN = b"POP-SCHNORR-V1"

def produce_pop(sk: SigningKey) -> Signature:
    return schnorr_sign(POP_DOMAIN, sk)               # Sign fixed value

def verify_pop(pubkey, sig: Signature) -> bool:
    return schnorr_verify(POP_DOMAIN, sig, pubkey)    # Verify PoP signature


# Demo (Runs all tests)
def demo():
    print("=== Secure EC-Schnorr Demo ===")

    sk = SigningKey.generate(curve=curve)             # Generate private key
    vk = sk.verifying_key                             # Derive public key

    print("\nPrivate key (hex):", hex(sk.privkey.secret_multiplier))
    print("Public key valid?:", validate_public_key(vk))

    # Proof-of-Possession
    pop = produce_pop(sk)
    print("\nPoP Verified:", verify_pop(vk, pop))

    # Signing
    msg = b"Enhanced Schnorr Signature Test"
    sig = schnorr_sign(msg, sk)
    print("\nSignature (s, e):", sig.s, sig.e)

    # Verification
    print("Signature valid?:", schnorr_verify(msg, sig, vk))

    # Tampering tests
    tampered = b"Modified message!"
    print("Tampered verification:", schnorr_verify(tampered, sig, vk))

    # Modify s
    bad_sig = Signature(s=(sig.s + 1) % n, e=sig.e)
    print("Modified signature verification:", schnorr_verify(msg, bad_sig, vk))



# Run demo
if __name__ == "__main__":
    demo()
