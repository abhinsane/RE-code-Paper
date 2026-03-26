# System Parameter Reference

All configuration constants defined in `pq_evoting/config.py`.

---

## Post-Quantum Key Algorithms

| Parameter | Value | Why this value |
|-----------|-------|----------------|
| `PQ_KEM_ALGORITHM` | `ml_kem_768` | ML-KEM Level 3 (NIST FIPS 203). Provides 128-bit quantum security. Level 512 gives only ~100-bit (below NIST minimum); Level 1024 is overkill with larger keys for no practical gain. |
| `PQ_SIG_ALGORITHM` | `ml_dsa_65` | ML-DSA Level 3 (NIST FIPS 204). Same 128-bit quantum security target as the KEM, keeping the overall system at a consistent NIST Level 3 security baseline. |

---

## Symmetric Encryption

| Parameter | Value | Why this value |
|-----------|-------|----------------|
| `SYM_KEY_SIZE` | `32` bytes (256-bit) | Grover's algorithm halves effective key length on a quantum computer. AES-128 → 64-bit quantum security (insufficient). AES-256 → 128-bit quantum security, matching the PQ primitives. |
| `SYM_NONCE_SIZE` | `12` bytes (96-bit) | NIST SP 800-38D recommended GCM nonce length. Allows the counter to be used directly without additional hashing; any other length requires an extra GHASH step and is less analysed. |

---

## FHE Parameters (TenSEAL BFV)

| Parameter | Value | Why this value |
|-----------|-------|----------------|
| `FHE_POLY_MOD_DEGREE` | `16384` | Ring dimension controlling both security and noise budget. `n=4096` → ~64-bit quantum; `n=8192` → ~96-bit quantum; `n=16384` → ~128-bit quantum (NIST minimum). Previous default of 8192 was below the NIST minimum. |
| `FHE_PLAIN_MODULUS` | `786433` | Must satisfy `plain_modulus ≡ 1 (mod 2n)` for BFV correctness. With `n=16384`: `2n = 32768`. `786433 = 24 × 32768 + 1` is the smallest prime satisfying this congruence that is large enough to hold vote counts. Standard TenSEAL choice for this degree. |
| `FHE_SHARD_SIZE` | `3200` | BFV ciphertexts tolerate a finite number of homomorphic additions before noise corrupts the plaintext. At `n=16384` the safe ceiling is ~4000–5000 additions. 3200 leaves ~20% headroom below that limit to avoid decryption failures on edge cases. |

---

## ZKP Parameters (Lattice-Based Ajtai Commitment + Fiat-Shamir)

| Parameter | Value | Why this value |
|-----------|-------|----------------|
| `ZKP_MODULUS` (q) | `2³¹ − 1 = 2,147,483,647` | Mersenne prime chosen for two reasons: (1) avoids int64 overflow — worst-case partial sum in `_matvec_mod` is `q × beta ≈ 4.3 × 10¹²`, safely below the int64 limit of ~9.2 × 10¹⁸; (2) meaningful MSIS hardness — the previous toy value of `2²³−7 ≈ 8.4M` made the lattice problem trivially breakable; `2³¹−1 ≈ 2.1B` approaches a realistic hardness assumption. |
| `ZKP_N` | `128` | Number of rows in public matrix A (commitment vector dimension). MSIS hardness grows with n. The previous value of 64 is too small for any real security claim. 128 is the minimum typically cited in lattice ZKP literature for a research-grade parameter set. |
| `ZKP_M` | `256` | Randomness vector dimension, always `2 × N`. The M/N = 2 ratio ensures sufficient entropy in r for the commitment to be statistically hiding. If M/N < 2, the commitment can leak information about the vote. |
| `ZKP_BETA` (β) | `2000` | ∞-norm bound on short randomness vectors. Small β strengthens binding but raises the abort probability during proof generation. Large β lowers abort probability but weakens MSIS hardness. 2000 is chosen so that rejection sampling almost never aborts (2000 << 2.1B = q) while maintaining the short-vector gap that underlies security. |

---

## Cancellable Biometric Parameters

| Parameter | Value | Why this value |
|-----------|-------|----------------|
| `BIO_FEATURE_DIM` | `2048` | Output bit-length of the BioHash projection. Too small (e.g. 512) → genuine/impostor Hamming distance distributions overlap → higher EER. Too large (e.g. 8192) → diminishing accuracy gains with slower projection. 2048 is the empirically optimal length for Gabor+HOG fingerprint features (~8100 HOG coefficients), consistent with Jin et al. BioHash literature. |
| `BIO_MATCH_THRESHOLD` | `0.818` | Hamming distance threshold at which FAR = FRR (Equal Error Rate point). Measured empirically on the SOCOFing dataset (100 subjects, Real + Altered fingerprints). At this threshold EER = 2.61%. Higher → more impostors accepted; lower → more genuine users rejected. |

---

## Blockchain Parameters

| Parameter | Value | Why this value |
|-----------|-------|----------------|
| `BLOCKCHAIN_DIFFICULTY` | `4` (leading zero nibbles) | Each difficulty level multiplies expected SHA3-256 hash attempts by 16. Level 4 → ~65,536 hashes per block (~100 ms on one CPU core): slow enough to deter bulk ballot stuffing, fast enough for real-time vote recording. Previous level 2 (~256 hashes) was trivially fast and provided no meaningful deterrent. |

---

## Authentication & Lockout Parameters

| Parameter | Value | Why this value |
|-----------|-------|----------------|
| `AUTH_SESSION_TIMEOUT` | `600` s (10 min) | Prevents an authentication token from remaining valid all day. 10 minutes matches standard banking and government system timeouts — long enough to complete the voting flow, short enough to limit exposure if the voter walks away. |
| `BIO_MAX_AUTH_ATTEMPTS` | `5` | Mirrors NIST SP 800-63B guidance for biometric authenticators. Five attempts cover legitimate failures (poor finger placement, skin condition) without opening the door to brute-force. |
| `BIO_LOCKOUT_SECONDS` | `300` s (5 min) | Paired with 5 attempts gives an effective rate of 1 attempt/minute for an attacker — impractical for brute-force. Short enough not to permanently lock out a legitimate voter who is having trouble. |

---

## Domain Separator

| Parameter | Value | Why this value |
|-----------|-------|----------------|
| `ELECTION_DOMAIN` | `b"pq_evoting_2024_domain_sep"` | Embedded in every hash and ZKP challenge to prevent cross-protocol attacks — a proof or hash computed for one election cannot be replayed against a different system or election instance. |
