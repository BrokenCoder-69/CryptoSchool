# ============================================================
# crypto.py — All cryptographic operations for Crypto School
# RSA implemented from scratch. No external crypto libraries.
# ============================================================

import random  # used for prime generation and padding
import math    # used for gcd
import hashlib # only used for hashing (not RSA) — allowed as it's not a crypto framework
import os      # used to generate random salt bytes


# ============================================================
# SECTION 1: MATH HELPERS FOR RSA
# ============================================================

def gcd(a, b):
    # Euclidean algorithm — finds greatest common divisor
    # RSA needs gcd(e, phi) == 1 to ensure e is valid
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    # Extended Euclidean Algorithm
    # Finds d such that (e * d) % phi == 1
    # This d becomes the RSA private key exponent
    old_r, r = e, phi
    old_s, s = 1, 0

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s

    # old_s is our modular inverse — make it positive
    return old_s % phi


def is_prime(n, k=10):
    # Miller-Rabin primality test
    # Much faster than trial division for large numbers
    # k = number of rounds (more rounds = more accurate)

    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop — test k random witnesses
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)  # Python's built-in modular exponentiation (math, not crypto lib)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # composite

    return True  # probably prime


def generate_prime(bits=512):
    # Generate a random prime number of given bit length
    # RSA uses two such primes (p and q)
    while True:
        # Generate a random odd number of the desired bit length
        candidate = random.getrandbits(bits) | (1 << bits - 1) | 1
        if is_prime(candidate):
            return candidate


# ============================================================
# SECTION 2: RSA KEY GENERATION
# ============================================================

def generate_rsa_keys(bits=512):
    # Generate RSA public and private key pair
    # bits=512 for speed in dev — use 1024+ in production
    #
    # RSA Key Generation Steps:
    # 1. Pick two large primes p and q
    # 2. n = p * q  (modulus)
    # 3. phi = (p-1)(q-1)  (Euler's totient)
    # 4. Choose e: 1 < e < phi, gcd(e, phi) = 1
    # 5. Compute d = modular inverse of e mod phi
    # 6. Public key = (e, n), Private key = (d, n)

    p = generate_prime(bits)
    q = generate_prime(bits)

    # Make sure p and q are different
    while q == p:
        q = generate_prime(bits)

    n = p * q                        # modulus (shared in both keys)
    phi = (p - 1) * (q - 1)         # Euler's totient

    # Common choice for e — 65537 is standard, fast, and secure
    e = 65537

    # Make sure e and phi are coprime
    # If not (rare), adjust e
    while gcd(e, phi) != 1:
        e = random.randrange(3, phi, 2)

    d = mod_inverse(e, phi)          # private exponent

    # Return as dictionaries for easy storage
    public_key = {'e': e, 'n': n}
    private_key = {'d': d, 'n': n}

    return public_key, private_key


# ============================================================
# SECTION 3: RSA ENCRYPTION / DECRYPTION
# ============================================================

def rsa_encrypt(message: str, public_key: dict) -> list:
    # Encrypt a string message using RSA public key
    # Returns a list of encrypted integers (one per character)
    #
    # RSA Encryption: ciphertext = (plaintext^e) mod n
    # We encrypt character by character (simple approach for now)

    e = public_key['e']
    n = public_key['n']

    encrypted = []
    for char in message:
        # Convert character to its ASCII/Unicode integer value
        m = ord(char)
        # Apply RSA encryption formula
        c = pow(m, e, n)   # Python's pow with 3 args = fast modular exponentiation
        encrypted.append(c)

    return encrypted  # list of integers


def rsa_decrypt(encrypted: list, private_key: dict) -> str:
    # Decrypt a list of RSA-encrypted integers back to string
    #
    # RSA Decryption: plaintext = (ciphertext^d) mod n

    d = private_key['d']
    n = private_key['n']

    decrypted = []
    for c in encrypted:
        # Apply RSA decryption formula
        m = pow(c, d, n)
        # Convert integer back to character
        decrypted.append(chr(m))

    return ''.join(decrypted)


def encrypt_to_string(message: str, public_key: dict) -> str:
    # Wrapper: encrypts message and returns a storable string
    # Format: "num1,num2,num3,..." — easy to store in DB as text
    encrypted_list = rsa_encrypt(message, public_key)
    return ','.join(map(str, encrypted_list))


def decrypt_from_string(encrypted_str: str, private_key: dict) -> str:
    # Wrapper: takes stored string and decrypts back to original
    encrypted_list = list(map(int, encrypted_str.split(',')))
    return rsa_decrypt(encrypted_list, private_key)


# ============================================================
# SECTION 4: KEY SERIALIZATION (convert keys to/from strings)
# ============================================================

def serialize_key(key: dict) -> str:
    # Convert a key dict to a string for DB storage
    # Format: "e:value,n:value" or "d:value,n:value"
    return ','.join(f"{k}:{v}" for k, v in key.items())


def deserialize_key(key_str: str) -> dict:
    # Convert stored string back to key dict
    # Reconstruct the original dictionary
    result = {}
    for part in key_str.split(','):
        k, v = part.split(':')
        result[k] = int(v)
    return result


# ============================================================
# SECTION 5: PASSWORD HASHING (custom, no libraries)
# ============================================================

def generate_salt(length=32) -> str:
    # Generate a random salt using OS randomness
    # Salt prevents rainbow table attacks
    # os.urandom gives us cryptographically random bytes
    raw = os.urandom(length)
    # Convert bytes to hex string for easy storage
    return raw.hex()


def hash_password(password: str, salt: str) -> str:
    # Custom password hashing using SHA-256
    # Process:
    # 1. Combine password + salt
    # 2. Hash multiple times (stretching) to slow down brute force
    # 3. Return hex digest

    ITERATIONS = 100000  # number of times we re-hash (key stretching)

    # Combine password and salt
    combined = (password + salt).encode('utf-8')

    # First hash
    result = hashlib.sha256(combined).digest()

    # Re-hash many times — makes brute force expensive
    for _ in range(ITERATIONS - 1):
        result = hashlib.sha256(result + combined).digest()

    return result.hex()  # return as hex string


def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    # Verify a password attempt against stored hash
    # Simply re-hash the attempt and compare
    attempt_hash = hash_password(password, salt)
    return attempt_hash == stored_hash  # True if password is correct



# ============================================================
# SECTION 6: ECC (Elliptic Curve Cryptography) FROM SCRATCH
# ============================================================
# We use a small custom curve for educational purposes
# Curve equation: y² ≡ x³ + ax + b (mod p)
#
# For real ECC we'd use standard curves like secp256k1
# but we implement the math from scratch here
# ============================================================

import secrets  # for cryptographically secure random numbers in ECC


# ── Curve Parameters ─────────────────────────────────────────
# These define our elliptic curve
# p must be a large prime — this is the field we work in
# G is the generator point — base point everyone uses
# n is the order of G — how many points are on the curve

ECC_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# ^ This is secp256k1's prime — large enough to be secure

ECC_A  = 0   # curve parameter a (secp256k1 uses 0)
ECC_B  = 7   # curve parameter b (secp256k1 uses 7)

# Generator point G (base point) from secp256k1
ECC_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
ECC_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

ECC_G  = (ECC_GX, ECC_GY)  # generator point as (x, y) tuple
ECC_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# ^ order of the curve (number of valid points)


# ── Point Arithmetic ─────────────────────────────────────────

def ecc_point_add(P, Q):
    # Add two points on the elliptic curve
    # This is the core operation of ECC
    # Returns a new point R = P + Q

    # Identity element: adding point at infinity returns the other point
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2:
        if y1 != y2:
            # Points are inverses of each other → result is point at infinity
            return None
        # Point doubling: P == Q
        # Formula: m = (3x₁² + a) / (2y₁) mod p
        m = (3 * x1 * x1 + ECC_A) * mod_inverse(2 * y1, ECC_P) % ECC_P
    else:
        # Regular addition: P != Q
        # Formula: m = (y₂ - y₁) / (x₂ - x₁) mod p
        m = (y2 - y1) * mod_inverse(x2 - x1, ECC_P) % ECC_P

    # Compute new point
    x3 = (m * m - x1 - x2) % ECC_P
    y3 = (m * (x1 - x3) - y1) % ECC_P

    return (x3, y3)


def ecc_scalar_multiply(k, P):
    # Multiply point P by scalar k using double-and-add algorithm
    # This is how we compute public keys: PublicKey = k * G
    # k = private key (integer)
    # P = starting point (usually generator G)
    #
    # Double-and-add is like binary exponentiation but for points

    result = None   # start with point at infinity (identity)
    addend = P      # current power of 2 point

    while k:
        if k & 1:
            # If current bit is 1, add current point to result
            result = ecc_point_add(result, addend)
        # Double the point for next bit
        addend = ecc_point_add(addend, addend)
        k >>= 1  # shift to next bit

    return result


# ── Key Generation ───────────────────────────────────────────

def generate_ecc_keys():
    # Generate ECC key pair
    # Private key: random integer in range [1, n-1]
    # Public key:  point on curve = private_key * G

    # Generate secure random private key
    private_key = secrets.randbelow(ECC_N - 1) + 1
    # +1 ensures it's never 0

    # Public key = scalar multiplication of private key with generator
    public_key = ecc_scalar_multiply(private_key, ECC_G)
    # public_key is a point (x, y) on the curve

    return private_key, public_key
    # private_key → integer
    # public_key  → (x, y) tuple


# ── ECC Serialization ────────────────────────────────────────

def serialize_ecc_public_key(public_key: tuple) -> str:
    # Convert ECC public key (x, y) point to storable string
    x, y = public_key
    return f"{x}:{y}"


def deserialize_ecc_public_key(key_str: str) -> tuple:
    # Convert stored string back to (x, y) point
    x, y = key_str.split(':')
    return (int(x), int(y))


def serialize_ecc_private_key(private_key: int) -> str:
    # ECC private key is just an integer — convert to string
    return str(private_key)


def deserialize_ecc_private_key(key_str: str) -> int:
    # Convert stored string back to integer
    return int(key_str)


# ── ECC Encryption (ElGamal on curve) ───────────────────────

def ecc_encrypt_otp(otp: str, public_key: tuple) -> dict:
    # Encrypt OTP using ECC ElGamal encryption
    #
    # How ElGamal ECC encryption works:
    # 1. Convert OTP to integer m
    # 2. Pick random k
    # 3. C1 = k * G  (ephemeral public key)
    # 4. C2 = m * G + k * PublicKey  (encrypted message point)
    # Sender sends (C1, C2)
    #
    # We encode OTP as a number and embed it on the curve
    # For simplicity: we encrypt the integer value directly

    # Random ephemeral key (used only once per encryption)
    k = secrets.randbelow(ECC_N - 1) + 1

    # C1 = k * G
    C1 = ecc_scalar_multiply(k, ECC_G)

    # shared secret = k * PublicKey
    shared_secret = ecc_scalar_multiply(k, public_key)

    # Convert OTP string to integer
    otp_int = int(otp)

    # XOR the OTP with x-coordinate of shared secret
    # This is the encryption step
    encrypted_otp = otp_int ^ (shared_secret[0] % 1000000)
    # mod 1000000 brings the huge number to 6-digit range for XOR

    return {
        'C1_x': C1[0],       # ephemeral key point x
        'C1_y': C1[1],       # ephemeral key point y
        'enc':  encrypted_otp  # XOR-encrypted OTP
    }


def ecc_decrypt_otp(cipher: dict, private_key: int) -> str:
    # Decrypt OTP using ECC private key
    #
    # Decryption:
    # 1. Recompute shared secret = PrivateKey * C1
    # 2. XOR encrypted value with shared secret to recover OTP

    C1 = (cipher['C1_x'], cipher['C1_y'])

    # Recompute shared secret using private key
    shared_secret = ecc_scalar_multiply(private_key, C1)

    # XOR back to recover original OTP
    otp_int = cipher['enc'] ^ (shared_secret[0] % 1000000)

    # Return as zero-padded 6-digit string
    return str(otp_int).zfill(6)


def serialize_ecc_cipher(cipher: dict) -> str:
    # Convert cipher dict to storable string
    # Format: "C1x|C1y|enc"
    return f"{cipher['C1_x']}|{cipher['C1_y']}|{cipher['enc']}"


def deserialize_ecc_cipher(cipher_str: str) -> dict:
    # Convert stored string back to cipher dict
    parts = cipher_str.split('|')
    return {
        'C1_x': int(parts[0]),
        'C1_y': int(parts[1]),
        'enc':  int(parts[2])
    }


# ── OTP Generation ───────────────────────────────────────────

def generate_otp() -> str:
    # Generate a cryptographically secure 6-digit OTP
    # secrets module is safe for this — it's not a crypto framework,
    # just a secure random number source
    otp = secrets.randbelow(900000) + 100000  # range: 100000–999999
    return str(otp)



# ============================================================
# SECTION 7: KEY MANAGEMENT
# ============================================================
# Problem: Private keys stored as plain text = security risk
# Solution: Encrypt private keys using a key derived from
#           the user's password before storing in DB
#
# Flow:
# Registration → derive master key from password
#             → encrypt private key with master key
#             → store encrypted private key in DB
#
# Login       → derive master key from password again
#             → decrypt private key for use in session
#             → NEVER store decrypted key in DB again
# ============================================================


# ============================================================
# KEY DERIVATION FUNCTION (KDF)
# Derives a symmetric encryption key from a password + salt
# This is similar to PBKDF2 but implemented from scratch
# ============================================================

def derive_master_key(password: str, salt: str, iterations: int = 100000) -> bytes:
    # Derives a 256-bit master key from a password using
    # iterative hashing (custom PBKDF2-like implementation)
    #
    # Why: We need a symmetric key to encrypt/decrypt private keys
    # We derive it from the user's password so:
    # - Only the user (who knows their password) can decrypt their private key
    # - Even if DB is breached, private keys can't be decrypted without password

    # Combine password and salt
    combined = (password + salt).encode('utf-8')

    # Initial hash
    key = hashlib.sha256(combined).digest()

    # Stretch the key through many iterations
    # Makes brute force attacks very expensive
    for i in range(iterations - 1):
        # Mix in iteration counter to make each round unique
        key = hashlib.sha256(key + combined + str(i).encode()).digest()

    return key   # 32 bytes = 256 bits


def derive_key_as_int(password: str, salt: str) -> int:
    # Derives master key and converts to integer
    # We need an integer because our XOR encryption works on integers
    key_bytes = derive_master_key(password, salt)
    return int.from_bytes(key_bytes, byteorder='big')


# ============================================================
# SYMMETRIC ENCRYPTION FOR PRIVATE KEYS
# We use XOR stream cipher with the derived master key
# Simple but effective when the key is truly random (derived)
# ============================================================

def xor_encrypt_key(data: str, key_int: int) -> str:
    # Encrypt a string using XOR with a derived integer key
    # Used to encrypt RSA/ECC private keys before DB storage
    #
    # XOR properties:
    # encrypt: data XOR key = ciphertext
    # decrypt: ciphertext XOR key = data  (XOR is its own inverse)

    # Convert string to bytes
    data_bytes = data.encode('utf-8')
    data_int   = int.from_bytes(data_bytes, byteorder='big')

    # XOR with key
    # We need key to be same size as data
    # Generate enough key material by extending the key
    key_stream = _extend_key(key_int, len(data_bytes))

    encrypted_int = data_int ^ key_stream

    # Convert back to hex string for storage
    # Use enough hex digits to represent the encrypted integer
    hex_length = len(data_bytes) * 2
    return format(encrypted_int, f'0{hex_length}x')


def xor_decrypt_key(encrypted_hex: str, key_int: int) -> str:
    # Decrypt a hex string back to original using XOR
    # Same key must be used (derived from same password+salt)

    encrypted_int = int(encrypted_hex, 16)
    byte_length   = len(encrypted_hex) // 2

    # Regenerate same key stream
    key_stream = _extend_key(key_int, byte_length)

    # XOR to decrypt
    decrypted_int = encrypted_int ^ key_stream

    # Convert back to string
    decrypted_bytes = decrypted_int.to_bytes(byte_length, byteorder='big')
    return decrypted_bytes.decode('utf-8')


def _extend_key(key_int: int, target_bytes: int) -> int:
    # Extends key material to match data length
    # Uses repeated hashing to generate more key bytes
    key_bytes    = key_int.to_bytes(32, byteorder='big')
    result_bytes = b''

    # Generate enough blocks of 32 bytes
    block = 0
    while len(result_bytes) < target_bytes:
        block_bytes = hashlib.sha256(
            key_bytes + block.to_bytes(4, byteorder='big')
        ).digest()
        result_bytes += block_bytes
        block += 1

    # Trim to exact size and convert to int
    result_bytes = result_bytes[:target_bytes]
    return int.from_bytes(result_bytes, byteorder='big')


# ============================================================
# HIGH LEVEL: ENCRYPT / DECRYPT PRIVATE KEY FOR STORAGE
# ============================================================

def encrypt_private_key(private_key_str: str, password: str, salt: str) -> str:
    # Encrypt a serialized private key string using password
    # This is what gets stored in the database
    #
    # Steps:
    # 1. Derive master key from password + salt
    # 2. XOR encrypt the private key string
    # 3. Return encrypted hex string

    master_key = derive_key_as_int(password, salt)
    encrypted  = xor_encrypt_key(private_key_str, master_key)
    return encrypted


def decrypt_private_key(encrypted_str: str, password: str, salt: str) -> str:
    # Decrypt a stored private key using the user's password
    # Called during login after password is verified
    #
    # Steps:
    # 1. Derive same master key from password + salt
    # 2. XOR decrypt to recover original private key string
    # 3. Return the serialized private key string

    master_key = derive_key_as_int(password, salt)
    decrypted  = xor_decrypt_key(encrypted_str, master_key)
    return decrypted


# ============================================================
# KEY ROTATION HELPERS
# ============================================================

def rotate_rsa_keys(old_private_key: dict, old_public_key: dict,
                    encrypted_fields: list, bits: int = 512):
    # Generate new RSA key pair and re-encrypt all data fields
    #
    # Steps:
    # 1. Decrypt all fields with OLD private key
    # 2. Generate NEW key pair
    # 3. Re-encrypt all fields with NEW public key
    # 4. Return new keys + re-encrypted data

    # Step 1: Decrypt all fields with old key
    decrypted_fields = []
    for field in encrypted_fields:
        if field:  # skip empty fields
            try:
                plain = decrypt_from_string(field, old_private_key)
                decrypted_fields.append(plain)
            except Exception:
                decrypted_fields.append('')
        else:
            decrypted_fields.append('')

    # Step 2: Generate new RSA key pair
    new_public_key, new_private_key = generate_rsa_keys(bits=bits)

    # Step 3: Re-encrypt all fields with new public key
    re_encrypted_fields = []
    for plain in decrypted_fields:
        if plain:
            re_encrypted_fields.append(
                encrypt_to_string(plain, new_public_key)
            )
        else:
            re_encrypted_fields.append('')

    return new_public_key, new_private_key, re_encrypted_fields





# ============================================================
# SECTION 8: HMAC — Data Integrity Verification
# ============================================================
# HMAC proves data has not been tampered with
# If even one byte changes, HMAC verification fails
#
# HMAC(key, message) = Hash(key XOR opad || Hash(key XOR ipad || message))
# We implement this from scratch using SHA-256
# ============================================================

def hmac_sha256(key: bytes, message: bytes) -> str:
    # Custom HMAC-SHA256 implementation from scratch
    # key     = secret key bytes
    # message = data to authenticate

    BLOCK_SIZE = 64   # SHA-256 block size in bytes

    # If key is longer than block size, hash it first
    if len(key) > BLOCK_SIZE:
        key = hashlib.sha256(key).digest()

    # Pad key to block size with zeros
    if len(key) < BLOCK_SIZE:
        key = key + b'\x00' * (BLOCK_SIZE - len(key))

    # Create inner and outer padding
    # ipad = 0x36 repeated, opad = 0x5c repeated
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5c for b in key)

    # HMAC = Hash(opad || Hash(ipad || message))
    inner = hashlib.sha256(ipad + message).digest()
    outer = hashlib.sha256(opad + inner).digest()

    return outer.hex()


def generate_hmac(data: str, secret_key: str) -> str:
    # Generate HMAC for a string using a secret key
    # Used to verify data integrity
    key_bytes  = secret_key.encode('utf-8')
    data_bytes = data.encode('utf-8')
    return hmac_sha256(key_bytes, data_bytes)


def verify_hmac(data: str, secret_key: str, expected_hmac: str) -> bool:
    # Verify HMAC — returns True if data is intact
    # Returns False if data was tampered with
    computed = generate_hmac(data, secret_key)

    # Constant time comparison to prevent timing attacks
    # We compare every byte even if mismatch found early
    if len(computed) != len(expected_hmac):
        return False

    result = 0
    for a, b in zip(computed, expected_hmac):
        result |= ord(a) ^ ord(b)

    return result == 0   # True only if all bytes matched


# ============================================================
# SECTION 9: ECC DIGITAL SIGNATURE
# ============================================================
# Digital signature proves:
# 1. Data came from the claimed sender (authenticity)
# 2. Data was not modified (integrity)
#
# ECDSA (Elliptic Curve Digital Signature Algorithm):
# Sign:   (r, s) = sign(private_key, message_hash)
# Verify: check equation using public_key, (r, s), message_hash
# ============================================================

def ecc_sign(message: str, private_key: int) -> dict:
    # Sign a message using ECC private key (ECDSA)
    # Returns signature as (r, s) pair

    # Hash the message first
    msg_hash = int(
        hashlib.sha256(message.encode('utf-8')).hexdigest(),
        16
    )

    # Generate random nonce k (must be unique per signature)
    # Reusing k leaks the private key — so we use secrets
    k = secrets.randbelow(ECC_N - 1) + 1

    # R = k * G — compute point
    R = ecc_scalar_multiply(k, ECC_G)
    r = R[0] % ECC_N   # r = x coordinate of R mod n

    if r == 0:
        # Extremely rare — retry
        return ecc_sign(message, private_key)

    # s = k^(-1) * (hash + r * private_key) mod n
    k_inv = mod_inverse(k, ECC_N)
    s = (k_inv * (msg_hash + r * private_key)) % ECC_N

    if s == 0:
        return ecc_sign(message, private_key)

    return {'r': r, 's': s}


def ecc_verify_signature(message: str, signature: dict,
                         public_key: tuple) -> bool:
    # Verify an ECC signature
    # Returns True if signature is valid

    r = signature['r']
    s = signature['s']

    # Basic range checks
    if not (1 <= r < ECC_N and 1 <= s < ECC_N):
        return False

    # Hash the message
    msg_hash = int(
        hashlib.sha256(message.encode('utf-8')).hexdigest(),
        16
    )

    # Compute w = s^(-1) mod n
    w = mod_inverse(s, ECC_N)

    # Compute u1 = hash * w mod n
    u1 = (msg_hash * w) % ECC_N

    # Compute u2 = r * w mod n
    u2 = (r * w) % ECC_N

    # Compute point X = u1*G + u2*PublicKey
    point1 = ecc_scalar_multiply(u1, ECC_G)
    point2 = ecc_scalar_multiply(u2, public_key)
    X      = ecc_point_add(point1, point2)

    if X is None:
        return False

    # Signature valid if x coordinate of X equals r
    return (X[0] % ECC_N) == r


def serialize_signature(sig: dict) -> str:
    # Convert signature dict to storable string
    return f"{sig['r']}|{sig['s']}"


def deserialize_signature(sig_str: str) -> dict:
    # Convert stored string back to signature dict
    r, s = sig_str.split('|')
    return {'r': int(r), 's': int(s)}




# ============================================================
# SECTION 10: SECURE SESSION TOKEN MANAGEMENT
# ============================================================
# Session tokens are:
# 1. Generated with cryptographically secure randomness
# 2. Signed using ECC private key
# 3. Verified on every request
# 4. Expired after inactivity
# ============================================================

def generate_session_token() -> str:
    # Generate a cryptographically secure random session token
    # 32 bytes = 256 bits of entropy
    # Returned as hex string for easy storage
    return secrets.token_hex(32)


def sign_session_token(token: str, private_key: int) -> str:
    # Sign session token with ECC private key
    # This proves the token was issued by our server
    # and has not been forged or tampered with
    signature = ecc_sign(token, private_key)
    return serialize_signature(signature)


def verify_session_token(token: str, signature_str: str,
                         public_key: tuple) -> bool:
    # Verify session token signature
    # Returns True only if token was signed by matching private key
    try:
        signature = deserialize_signature(signature_str)
        return ecc_verify_signature(token, signature, public_key)
    except Exception:
        return False


def generate_session_fingerprint(ip: str, user_agent: str) -> str:
    # Create a fingerprint from client's IP and browser info
    # Used to detect session hijacking
    # If fingerprint changes mid-session → suspicious activity
    raw = f"{ip}:{user_agent}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


# ============================================================
# SECTION 11: RSA-BASED KEY WRAPPING
# ============================================================
# Purpose: Encrypt user private keys using RSA
#          so storage is 100% asymmetric
#
# How it works:
# 1. Derive a MASTER RSA key pair from user's password
#    (deterministic — same password = same master keys)
# 2. Wrap (encrypt) user's RSA/ECC private key
#    using the MASTER RSA PUBLIC key
# 3. Store the wrapped (RSA-encrypted) private key in DB
# 4. On login: re-derive master key from password
#              unwrap using MASTER RSA PRIVATE key
#
# This is 100% asymmetric — no symmetric cipher used
# The master key pair is NEVER stored anywhere
# It is re-derived from password on every login
# ============================================================


def derive_master_rsa_keys(password: str, salt: str) -> tuple:
    # Derive a deterministic RSA key pair from password + salt
    # Same password + salt always produces same key pair
    # This master key pair is used ONLY for wrapping other keys
    #
    # How deterministic generation works:
    # 1. Hash password+salt many times to get seed material
    # 2. Use seed to deterministically generate primes
    # 3. Build RSA key pair from those primes

    # Step 1: Generate seed from password + salt
    # Use many iterations to make it expensive to brute force
    combined = (password + salt).encode('utf-8')
    seed     = hashlib.sha256(combined).digest()

    for i in range(50000):
        # Mix in iteration to prevent shortcuts
        seed = hashlib.sha256(
            seed + combined + i.to_bytes(4, 'big')
        ).digest()

    # Convert seed to integer for use as RNG seed
    seed_int = int.from_bytes(seed, 'big')

    # Step 2: Deterministically generate two primes
    # We use a seeded pseudo-random generator
    # so same seed always gives same primes
    p = _deterministic_prime(seed_int, bits=256)
    q = _deterministic_prime(seed_int + 1, bits=256)

    # Make sure p != q
    attempts = 0
    while q == p:
        attempts += 1
        q = _deterministic_prime(seed_int + attempts + 1, bits=256)

    # Step 3: Build RSA key pair
    n   = p * q
    phi = (p - 1) * (q - 1)
    e   = 65537

    # Ensure e and phi are coprime
    while gcd(e, phi) != 1:
        e += 2

    d = mod_inverse(e, phi)

    master_public_key  = {'e': e, 'n': n}
    master_private_key = {'d': d, 'n': n}

    return master_public_key, master_private_key


def _deterministic_prime(seed: int, bits: int = 256) -> int:
    # Generate a prime deterministically from a seed
    # Same seed always returns same prime
    # Uses a simple LCG (Linear Congruential Generator)
    # seeded with our derived value

    # LCG parameters (standard values)
    a = 6364136223846793005
    c = 1442695040888963407
    m = 2 ** 64

    state = seed % m

    def next_rand():
        nonlocal state
        state = (a * state + c) % m
        return state

    while True:
        # Build a candidate prime from LCG output
        # Combine multiple outputs for enough bits
        candidate = 0
        for _ in range(bits // 64 + 1):
            candidate = (candidate << 64) | next_rand()

        # Trim to desired bit length
        candidate = candidate % (2 ** bits)

        # Ensure it has the right bit length and is odd
        candidate |= (1 << (bits - 1))  # set top bit
        candidate |= 1                   # make odd

        if is_prime(candidate):
            return candidate


def rsa_wrap_key(private_key_str: str,
                 master_public_key: dict) -> str:
    # Wrap (encrypt) a private key string using
    # master RSA public key
    #
    # Since RSA encrypts integers and our private key string
    # is large (hundreds of chars), we split it into chunks
    # Each chunk is encrypted separately
    # This is called RSA with chunking

    e = master_public_key['e']
    n = master_public_key['n']

    # Calculate max chunk size based on key size
    # n is ~512 bits = ~77 decimal digits
    # We use chunks of 10 chars to be safe
    CHUNK_SIZE = 8

    chunks = []
    for i in range(0, len(private_key_str), CHUNK_SIZE):
        chunk = private_key_str[i:i + CHUNK_SIZE]

        # Convert chunk to integer
        # Each char becomes 3-digit ASCII code
        chunk_int = int(''.join(
            f"{ord(c):03d}" for c in chunk
        ))

        # RSA encrypt: c = m^e mod n
        encrypted_chunk = pow(chunk_int, e, n)
        chunks.append(str(encrypted_chunk))

    # Join chunks with pipe separator
    return '|'.join(chunks)


def rsa_unwrap_key(wrapped_str: str,
                   master_private_key: dict) -> str:
    # Unwrap (decrypt) a wrapped private key using
    # master RSA private key

    d = master_private_key['d']
    n = master_private_key['n']

    CHUNK_SIZE = 8
    chunks     = wrapped_str.split('|')
    result     = ''

    for encrypted_chunk_str in chunks:
        encrypted_chunk = int(encrypted_chunk_str)

        # RSA decrypt: m = c^d mod n
        chunk_int = pow(encrypted_chunk, d, n)

        # Convert integer back to string
        # Each 3 digits = one ASCII code
        chunk_str_raw = str(chunk_int)

        # Pad to multiple of 3
        while len(chunk_str_raw) % 3 != 0:
            chunk_str_raw = '0' + chunk_str_raw

        chunk_chars = ''
        for j in range(0, len(chunk_str_raw), 3):
            ascii_code = int(chunk_str_raw[j:j+3])
            if ascii_code > 0:  # skip null padding
                chunk_chars += chr(ascii_code)

        result += chunk_chars

    return result


def wrap_private_key(private_key_str: str,
                     password: str,
                     salt: str) -> str:
    # High-level function: wrap private key with RSA
    # Derives master key from password then wraps
    #
    # This replaces the old XOR-based encryption
    # Now 100% asymmetric (RSA wrapping RSA)

    master_pub, _ = derive_master_rsa_keys(password, salt)
    wrapped       = rsa_wrap_key(private_key_str, master_pub)
    return wrapped


def unwrap_private_key(wrapped_str: str,
                        password: str,
                        salt: str) -> str:
    # High-level function: unwrap private key with RSA
    # Derives master key from password then unwraps

    _, master_priv = derive_master_rsa_keys(password, salt)
    unwrapped      = rsa_unwrap_key(wrapped_str, master_priv)
    return unwrapped

























