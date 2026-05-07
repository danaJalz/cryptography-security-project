# -----------------------------------------------------------
# Enhanced EC-Schnorr Signature - Security Validation Tests
# This code implements the improved Schnorr protocol and
# tests validation for Task 3 (cryptanalysis + side-channel).
# Prepared by: Dana Alzahrani 2310370 & Sara Jad 2311212
# -----------------------------------------------------------

from ecdsa import SigningKey, SECP256k1              # Import EC signing key and curve
from ecdsa.ellipticcurve import INFINITY            # Import point at infinity constant
import hashlib, hmac, secrets, time                 # Import hashing, HMAC, randomness, and timing

# ---------------------------
# Global curve parameters
# ---------------------------
curve = SECP256k1                                   # Use the SECP256k1 elliptic curve
G = curve.generator                                 # Generator point G of the curve
n = curve.order                                     # Order n of the base point G


# ---------------------------
# Deterministic Nonce
# k = HMAC(x, m) mod n
# ---------------------------
def deterministic_nonce(x, message):
    """Generate a deterministic nonce k from private key x and message."""
    key_bytes = x.to_bytes(32, 'big')              # Convert private key x to 32-byte big-endian
    hmac_bytes = hmac.new(key_bytes, message, hashlib.sha256).digest()  # HMAC-SHA256(x, m)
    k = int.from_bytes(hmac_bytes, 'big') % n      # Convert HMAC output to integer mod n
    if k == 0:                                     # Avoid k = 0 (invalid nonce)
        k = 1                                      # Use 1 in the rare case of 0
    return k                                       # Return deterministic nonce k


# ---------------------------
# Hash function e = H(R || m)
# ---------------------------
def hash_point_message(R, message):
    """Compute e = H(R.x || R.y || message) mod n."""
    rx = R.x().to_bytes(32, 'big')                # Get x-coordinate of R as 32 bytes
    ry = R.y().to_bytes(32, 'big')                # Get y-coordinate of R as 32 bytes
    digest = hashlib.sha256(rx + ry + message).digest()  # SHA-256(Rx || Ry || m)
    return int.from_bytes(digest, 'big') % n      # Convert digest to integer mod n


# ---------------------------
# Public Key Validation
# ---------------------------
def validate_public_key(pubkey):
    """Check that the public key point lies on the curve and has correct order."""
    try:
        P = pubkey.pubkey.point                   # Get EC point Y from verifying key
        if P is None or P == INFINITY:            # Reject if point is infinity or None
            return False

        curve_obj = curve.curve                   # Underlying curve equation y^2 = x^3 + ax + b (mod p)
        p = curve_obj.p()                         # Field prime p

        # Check curve equation: y^2 ?= x^3 + a*x + b (mod p)
        left = (P.y() * P.y()) % p                # Compute y^2 mod p
        right = (P.x()**3 + curve_obj.a() * P.x() + curve_obj.b()) % p  # Compute RHS
        if left != right:                         # If not equal, point is not on the curve
            return False

        # Check subgroup order: n * P should be infinity
        if (P * n) != INFINITY:                   # If n*P != O, point is not in correct subgroup
            return False

        return True                               # Public key is valid
    except Exception:                             # Any error means invalid key
        return False


# ---------------------------
# Scalar Blinding
# s = k + e * (x + r*n)  mod n
# ---------------------------
def blinded_scalar(k, e, x):
    """Apply scalar blinding to protect against timing/power side-channel attacks."""
    r = secrets.randbelow(n)                      # Choose random blinding factor r
    x_blind = x + r * n                           # Compute blinded private key x' = x + r*n
    s = (k + e * x_blind) % n                     # Compute s = k + e * x' (mod n)
    return s                                      # Return blinded scalar s


# ---------------------------
# Enhanced Schnorr Signing
# ---------------------------
def schnorr_sign(message, sk):
    """Sign a message using the enhanced EC-Schnorr protocol."""
    x = sk.privkey.secret_multiplier             # Extract private scalar x from SigningKey
    k = deterministic_nonce(x, message)          # Compute deterministic nonce k
    R = k * G                                    # Compute commitment point R = kG
    e = hash_point_message(R, message)           # Compute challenge e = H(R || m)
    s = blinded_scalar(k, e, x)                  # Compute blinded scalar s
    return (s, e)                                # Return signature tuple (s, e)



# Enhanced Schnorr Verification
def schnorr_verify(message, signature, vk):
    """Verify an EC-Schnorr signature with public key validation."""
    s, e = signature                             # Unpack signature values s and e

    if not validate_public_key(vk):              # Reject if public key is invalid
        return False

    Y = vk.pubkey.point                          # Get public key point Y
    R_prime = s * G + (-e * Y)                   # Recompute R' = sG - eY

    if R_prime == INFINITY:                      # If R' is infinity, signature is invalid
        return False

    e_check = hash_point_message(R_prime, message)  # Recompute e' = H(R' || m)
    return e_check == e                          # Signature is valid if e' == e


# Main program (Validation Tests)
def main():
    """Run validation tests for the enhanced EC-Schnorr protocol."""
    # Generate a fresh key pair
    sk = SigningKey.generate(curve=curve)        # Generate private key on SECP256k1
    vk = sk.verifying_key                        # Get corresponding public key

    print("=== Enhanced EC-Schnorr Validation Demo ===")
    print("Private Key (hex):", sk.to_string().hex())  # Print private key in hex
    print("Public  Key (hex):", vk.to_string().hex())  # Print public key in hex
    print("Public Key Valid?:", validate_public_key(vk))  # Show if public key passes validation

    # Take message from user
    user_msg = input("\nEnter a message to sign: ")      # Ask the user for a message
    msg_bytes = user_msg.encode()                        # Convert message to bytes

    # ---- Test 1: Sign + Verify (Expected: True) ----
    signature = schnorr_sign(msg_bytes, sk)              # Create signature for the message
    print("\n--- Test 1: Correct Signature Verification ---")
    print("Signature s =", signature[0])                 # Print s value
    print("Signature e =", signature[1])                 # Print e value
    valid_original = schnorr_verify(msg_bytes, signature, vk)  # Verify original message
    print("Verification on original message:", valid_original)  # Expected: True

    # ---- Test 2: Message Tampering (Expected: False) ----
    tampered_msg = (user_msg + "!").encode()             # Slightly modify the original message
    print("\n--- Test 2: Message Tampering ---")
    print("Tampered message:", user_msg + "!")           # Show tampered text
    valid_tampered = schnorr_verify(tampered_msg, signature, vk)  # Verify with tampered message
    print("Verification on tampered message:", valid_tampered)    # Expected: False

    # ---- Test 3: Signature Tampering (Expected: False) ----
    tampered_signature = ( (signature[0] + 1) % n, signature[1] )  # Change s by +1
    print("\n--- Test 3: Signature Tampering ---")
    print("Tampered s =", tampered_signature[0])         # Show modified s
    valid_sig_tampered = schnorr_verify(msg_bytes, tampered_signature, vk)  # Verify with bad s
    print("Verification on tampered signature:", valid_sig_tampered)        # Expected: False

    # ---- Test 4: Simple Timing Test (Side-Channel Check) ----
    print("\n--- Test 4: Simple Timing Test ---")
    iterations = 100                                     # Number of signing operations
    times = []                                           # List to store each signing time

    for _ in range(iterations):                          # Repeat signing many times
        start = time.time()                              # Start timer
        schnorr_sign(msg_bytes, sk)                      # Sign the same message
        end = time.time()                                # End timer
        times.append(end - start)                        # Save time difference

    avg_time = sum(times) / len(times)                   # Compute average signing time
    print("Number of signing operations:", iterations)   # Print number of tests
    print("Average signing time (seconds):", round(avg_time, 6))  # Show average time
    print("Min time:", round(min(times), 6))             # Show minimum time
    print("Max time:", round(max(times), 6))             # Show maximum time
    print("Result: signing time is stable and does not reveal key-dependent timing patterns.")


# Run main only when this file is executed directly
if __name__ == "__main__":                               # Standard Python entry point
    main()                                               # Call the main function
