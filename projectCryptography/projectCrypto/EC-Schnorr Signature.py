#prepared by "Dana Alzahrani 2310370"  and  "sara Jad 2311212"

# Import required libraries
from ecdsa import SigningKey, SECP256k1          # For elliptic curve key generation and signing
from ecdsa.ellipticcurve import Point            # For working with EC points
import hashlib                                   # For SHA-256 hashing
import secrets                                   # For generating secure random numbers


# Helper function to hash a point and a message
def hash_point_message(R_bytes, message):
    """
    Computes a SHA-256 hash of R || message and returns it as an integer.
    R_bytes: bytes of EC point R (concatenation of x and y)
    message: the message in bytes
    """
    h = hashlib.sha256()           # Create a new SHA-256 hash object
    h.update(R_bytes + message)    # Update hash with R concatenated with message
    return int(h.hexdigest(), 16)  # Convert hex digest to integer


# Key Generation
private_key = SigningKey.generate(curve=SECP256k1)  # Generate a private key using SECP256k1
public_key = private_key.verifying_key              # Derive the corresponding public key

# Display keys
print("Private Key (hex):", private_key.to_string().hex())
print("Public Key (hex):", public_key.to_string().hex())


# Schnorr Signing Function
def schnorr_sign(message, priv_key):
    """
    Signs a message using the Schnorr signature scheme.
    message: bytes to sign
    priv_key: SigningKey object
    Returns: (s, e) signature tuple
    """
    curve = SECP256k1
    q = curve.order           # Order of the curve
    G = curve.generator       # Generator point of the curve

    k = secrets.randbelow(q)  # Generate a random nonce 0 <= k < q

    R = k * G                 # Compute R = k * G
    # Convert R's coordinates to bytes
    R_bytes = R.x().to_bytes(32, 'big') + R.y().to_bytes(32, 'big')

    e = hash_point_message(R_bytes, message) % q  # Compute challenge e = H(R || m) mod q

    x = int.from_bytes(priv_key.to_string(), 'big')  # Convert private key to integer
    s = (k + e * x) % q                              # Compute s = k + e*x mod q

    return s, e                                      # Return signature


# Schnorr Verification Function
def schnorr_verify(message, signature, pub_key):
    """
    Verifies a Schnorr signature.
    message: bytes that was signed
    signature: tuple (s, e)
    pub_key: VerifyingKey object
    Returns: True if signature is valid, False otherwise
    """
    s, e = signature
    curve = SECP256k1
    q = curve.order
    G = curve.generator

    Y = pub_key.pubkey.point         # Get the public key point

    # Compute R' = s*G - e*Y (same as s*G + (-e*Y))
    R_prime = s * G + (-e * Y)
    R_bytes = R_prime.x().to_bytes(32, 'big') + R_prime.y().to_bytes(32, 'big')

    e_check = hash_point_message(R_bytes, message) % q  # Compute e' = H(R' || m) mod q
    return e_check == e                                  # Signature is valid if e' == e


# User Input for Message
user_input = input("Enter the message to sign: ")   # Prompt user to enter a message
message = user_input.encode()                       # Convert string to bytes


# Signing
signature = schnorr_sign(message, private_key)
print("\nSignature:")
print("s =", signature[0])
print("e =", signature[1])


# Verification
valid = schnorr_verify(message, signature, public_key)
print("\nVerification Result:", valid)