"""
Configuration constants for the Post-Quantum E-Voting System.

Cryptographic algorithms used:
  - Key Encapsulation : ML-KEM-768  (NIST FIPS 203 / CRYSTALS-Kyber level 3)
  - Digital Signatures: ML-DSA-65   (NIST FIPS 204 / CRYSTALS-Dilithium level 3)
  - Symmetric cipher  : AES-256-GCM (shared secret from ML-KEM)
  - Hash / XOF        : SHA3-256 / SHAKE256 (quantum-safe)
  - FHE               : BFV scheme  (TenSEAL)
  - ZKP               : Lattice-based Ajtai commitment with Fiat-Shamir
  - Biometrics        : BioHashing on ORB features (SOCOFing dataset)
"""

# ---------------------------------------------------------------------------
# Post-Quantum Key algorithms
# ---------------------------------------------------------------------------
PQ_KEM_ALGORITHM = "ml_kem_768"   # CRYSTALS-Kyber (NIST ML-KEM Level 3)
PQ_SIG_ALGORITHM = "ml_dsa_65"    # CRYSTALS-Dilithium (NIST ML-DSA Level 3)

# ---------------------------------------------------------------------------
# Symmetric encryption
# ---------------------------------------------------------------------------
SYM_KEY_SIZE   = 32   # 256-bit AES-GCM key
SYM_NONCE_SIZE = 12   # 96-bit GCM nonce (recommended)

# ---------------------------------------------------------------------------
# FHE parameters (TenSEAL BFV)
# ---------------------------------------------------------------------------
# poly_modulus_degree controls the BFV noise budget (larger = more additions
# before ciphertext corruption).  plain_modulus must be prime and satisfy
# plain_modulus ≡ 1 (mod 2 * poly_modulus_degree).
#
#   degree=4096  → plain_modulus=1032193 → ~1,000 votes  (previous default)
#   degree=8192  → plain_modulus=1032193 → ~4,000 votes
#   degree=16384 → plain_modulus=786433  → ~16,000 votes (current default)
#
# degree=16384 provides ~128-bit post-quantum security (NIST recommended).
# degree=8192 provided only ~64-bit post-quantum security (below NIST minimum).
#
# For unlimited voters regardless of degree, use ShardedFHETally which
# decrypts in FHE_SHARD_SIZE batches and sums the integer counts.
FHE_POLY_MOD_DEGREE = 16384
FHE_PLAIN_MODULUS   = 786433    # 786433 ≡ 1 (mod 32768); required for degree=16384
FHE_SHARD_SIZE      = 3200      # conservative ceiling for degree=16384 (noise safe)

# ---------------------------------------------------------------------------
# ZKP parameters — Lattice-based Ajtai commitment
# ---------------------------------------------------------------------------
# q = 2^31 - 1 is the Mersenne prime 2147483647.  It is the largest modulus
# that avoids int64 overflow in the column-wise modular matrix multiply used
# throughout zkp.py: each partial sum is bounded by q + q*beta < 2^63.
# This raises the modulus from the previous toy value (2^23 ≈ 8.4 M) to a
# value that approaches meaningful MSIS hardness.
ZKP_MODULUS = (1 << 31) - 1    # Mersenne prime 2^31 - 1 = 2 147 483 647
ZKP_N       = 128              # Commitment vector dimension (was 64)
ZKP_M       = 256              # Randomness vector dimension (was 128)
ZKP_BETA    = 2000             # ∞-norm bound for short randomness vectors (was 800)

# ---------------------------------------------------------------------------
# Cancellable biometric parameters
# ---------------------------------------------------------------------------
BIO_FEATURE_DIM     = 2048   # Output dimension after BioHash projection (was 512)
BIO_KEYPOINTS       = 256    # ORB keypoints to extract per fingerprint
BIO_MATCH_THRESHOLD = 0.818  # EER-optimal threshold (SOCOFing 100 subjects, Real+Altered, EER=2.61%)

# ---------------------------------------------------------------------------
# Blockchain parameters
# ---------------------------------------------------------------------------
BLOCKCHAIN_DIFFICULTY = 4    # PoW leading-zero count (~65 k SHA3 hashes; was 2 (~256))

# ---------------------------------------------------------------------------
# Authentication session timeout
# ---------------------------------------------------------------------------
# A biometric authentication token is valid for this many seconds.
# After this window the voter must re-authenticate before casting their vote.
# Without a timeout, an authentication from the start of polling day would
# remain valid indefinitely, even if the voter walked away.
AUTH_SESSION_TIMEOUT = 600   # 10 minutes

# ---------------------------------------------------------------------------
# Biometric brute-force lockout
# ---------------------------------------------------------------------------
# After BIO_MAX_AUTH_ATTEMPTS consecutive failed biometric checks the voter
# account is locked for BIO_LOCKOUT_SECONDS.  The counter resets on any
# successful verification.
BIO_MAX_AUTH_ATTEMPTS = 5     # consecutive failures before lockout
BIO_LOCKOUT_SECONDS   = 300   # 5-minute lockout window

# ---------------------------------------------------------------------------
# Election domain separator (embedded in every hash / ZKP challenge)
# ---------------------------------------------------------------------------
ELECTION_DOMAIN = b"pq_evoting_2024_domain_sep"
