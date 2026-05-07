# ------------------------------
# Import libraries
# ------------------------------
from ecdsa import SigningKey, SECP256k1        # For elliptic curve key generation and signing
from ecdsa.ellipticcurve import Point          # For EC point operations
import hashlib                                 # For SHA-256 hashing
import secrets                                 # For secure random numbers

# ------------------------------
# Helper function: Hash R || message
# ------------------------------
def hash_point_message(R_bytes, message):
    """
    Compute SHA-256 hash of R concatenated with message, return as integer.
    R_bytes: bytes of point R (x||y)
    message: bytes of the message
    """
    h = hashlib.sha256()               # Initialize SHA-256 hash
    h.update(R_bytes + message)        # Update hash with R || message
    return int(h.hexdigest(), 16)      # Return as integer

# ------------------------------
# Schnorr Signing Function
# ------------------------------
def schnorr_sign(message, priv_key):
    """
    Sign a message using Schnorr signature scheme.
    Returns signature tuple (s, e)
    """
    curve = SECP256k1                  # Use SECP256k1 curve
    q = curve.order                     # Curve order
    G = curve.generator                 # Generator point

    k = secrets.randbelow(q)            # Generate random nonce 0 <= k < q

    R = k * G                           # Compute R = k*G
    R_bytes = R.x().to_bytes(32, 'big') + R.y().to_bytes(32, 'big')  # Convert R coordinates to bytes

    e = hash_point_message(R_bytes, message) % q  # Compute challenge e = H(R || m) mod q

    x = int.from_bytes(priv_key.to_string(), 'big')  # Convert private key to integer
    s = (k + e * x) % q                             # Compute s = k + e*x mod q

    return s, e                                     # Return signature

# ------------------------------
# Schnorr Verification Function
# ------------------------------
def schnorr_verify(message, signature, pub_key):
    """
    Verify Schnorr signature (s, e) for a given message and public key.
    Returns True if valid, False otherwise.
    """
    s, e = signature
    curve = SECP256k1
    q = curve.order
    G = curve.generator

    Y = pub_key.pubkey.point                        # Public key point

    # Compute R' = s*G - e*Y
    R_prime = s * G + (-e * Y)
    R_bytes = R_prime.x().to_bytes(32, 'big') + R_prime.y().to_bytes(32, 'big')

    e_check = hash_point_message(R_bytes, message) % q  # Compute e' = H(R' || m)
    return e_check == e                                  # Valid if e' == e

# ------------------------------
# Schnorr Verification with Incorrect R (for Test 4)
# ------------------------------
def schnorr_verify_incorrect_R(message, signature, pub_key):
    """
    Deliberately miscompute R' to show verification failure.
    """
    s, e = signature
    curve = SECP256k1
    G = curve.generator
    Y = pub_key.pubkey.point

    R_prime_wrong = s * G  # Incorrect: missing - e*Y
    R_bytes = R_prime_wrong.x().to_bytes(32, 'big') + R_prime_wrong.y().to_bytes(32, 'big')

    e_check = hash_point_message(R_bytes, message) % curve.order
    return e_check == e

# ------------------------------
# Generate Key Pair
# ------------------------------
private_key = SigningKey.generate(curve=SECP256k1)  # Generate private key
public_key = private_key.verifying_key              # Derive public key

print("Private Key (hex):", private_key.to_string().hex())
print("Public Key (hex):", public_key.to_string().hex())

# ------------------------------
# User Input
# ------------------------------
user_input = input("Enter the message to sign: ")  # Get message from user
message = user_input.encode()                      # Convert to bytes

# ------------------------------
# Sign the message
# ------------------------------
signature = schnorr_sign(message, private_key)
print("\nSignature:")
print("s =", signature[0])
print("e =", signature[1])

# ------------------------------
# Verify the signature
# ------------------------------
valid = schnorr_verify(message, signature, public_key)
print("\nVerification Result (should be True):", valid)

# ------------------------------
# Validation Tests
# ------------------------------
print("\n--- Running Validation Tests ---")

# Test 1 — Sign + Verify (Expected: Pass)
test1 = schnorr_verify(message, signature, public_key)
print("Test 1 — Sign + Verify:", test1)  # Expected: True

# Test 2 — Modify the Message (Expected: Fail)
modified_message = message + b"."         # Slightly modified message
test2 = schnorr_verify(modified_message, signature, public_key)
print("Test 2 — Modified Message:", test2)  # Expected: False

# Test 3a — Modify s (Expected: Fail)
s_modified = (signature[0] + 1) % SECP256k1.order
signature_modified_s = (s_modified, signature[1])
test3a = schnorr_verify(message, signature_modified_s, public_key)
print("Test 3a — Modified s:", test3a)  # Expected: False

# Test 3b — Modify e (Expected: Fail)
e_modified = (signature[1] + 1) % SECP256k1.order
signature_modified_e = (signature[0], e_modified)
test3b = schnorr_verify(message, signature_modified_e, public_key)
print("Test 3b — Modified e:", test3b)  # Expected: False

# Test 4 — Incorrect R' (Expected: Fail)
test4 = schnorr_verify_incorrect_R(message, signature, public_key)
print("Test 4 — Incorrect R':", test4)  # Expected: False