# Biometric System — Quantum Safety Analysis
## Post-Quantum Secure E-Voting System

---

## Summary Claim (for paper)

> "The biometric template protection layer is post-quantum secure. All
> cryptographic primitives used for template storage and integrity are drawn
> from NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65). The biometric
> matching algorithm (Hamming distance on BioHash vectors) is a non-cryptographic
> distance function to which quantum speedup does not apply."

---

## Layer-by-Layer Analysis

### Layer 1 — Feature Extraction (Gabor + HOG)

```
Algorithm : CLAHE preprocessing → 48-filter Gabor bank → HOG descriptor
Output    : 8100-dimensional float32 feature vector

Quantum threat : NONE
Reason        : Pure signal processing (convolution, histogram binning).
                No trapdoor, no hardness assumption. A quantum computer
                offers zero algorithmic advantage over a classical one here.
```

---

### Layer 2 — Token-to-Seed Derivation

```
Algorithm : seed = SHAKE256("biohash_rng_seed" ‖ user_token, 32 bytes)
            → 256-bit integer seed

Quantum threat : Grover's algorithm
Classical security : 2^256 brute-force on token
Quantum security   : 2^128 (Grover halves the search exponent)

Status : SAFE
Reason : 2^128 operations remain computationally infeasible for any
         foreseeable quantum hardware. NIST considers 128-bit quantum
         security acceptable for symmetric primitives (SP 800-57 §5.6.1).

Paper note:
  "The BioHash token seed is derived via SHAKE256 with a 256-bit output,
   providing 128-bit post-quantum security against exhaustive token search
   under Grover's algorithm [Grover 1996]."
```

---

### Layer 3 — Projection Matrix (Cancelability Core)

```
Algorithm : M  ← NumPy RNG(seed).standard_normal(8100 × 2048)
            Q  ← QR decompose(M)   → orthonormal columns
            P  ← Q.T               → 2048 × 8100 projection matrix
            BioHash ← (P @ feature > median(P @ feature)).astype(uint8)

Quantum threat : NONE
Reason        : The projection matrix is a linear algebra object derived
                deterministically from the token seed. Its security is
                entirely dependent on the secrecy of the token (Layer 2),
                not on a computational hardness assumption.

Cancelability property (quantum perspective):
  Unlinkability between old BioHash (token_A) and new BioHash (token_B)
  is GEOMETRIC, not computational:
    - P_A and P_B are independently QR-decomposed orthonormal bases.
    - Hamming(BioHash_A, BioHash_B) ≈ 50% regardless of the adversary's
      compute power.
    - This is an INFORMATION-THEORETIC property: even an unbounded
      adversary cannot link the two templates without the tokens.

Status : SAFE (information-theoretic cancelability)
```

---

### Layer 4 — Template Storage (Encryption)

```
Algorithm : ML-KEM-768 key encapsulation → shared secret
            SHAKE256(shared_secret) → 256-bit AES key
            AES-256-GCM.encrypt(biohash_bytes) → ciphertext

Quantum threat : Shor's algorithm (breaks RSA, ECDH, ECC — NOT lattices)
                 Grover's algorithm (halves AES key search space)

ML-KEM-768:
  Security basis : Module Learning With Errors (MLWE) over lattices
  Standard       : NIST FIPS 203 (2024)
  Quantum status : SAFE — Shor does not apply to MLWE.
                   Best known quantum attack is BKZ lattice reduction,
                   estimated at ~2^178 operations for parameter set 768.

AES-256-GCM:
  Quantum status : ACCEPTABLE
                   Grover reduces exhaustive key search from 2^256 → 2^128.
                   128-bit quantum security is NIST-approved for symmetric
                   algorithms (SP 800-131A Rev. 2).

Status : SAFE

Paper note:
  "Templates are encrypted using ML-KEM-768 [NIST FIPS 203] — a lattice-based
   key encapsulation mechanism secure against both classical and quantum
   adversaries. The symmetric payload is protected by AES-256-GCM, providing
   128-bit post-quantum security under Grover's algorithm."
```

---

### Layer 5 — Template Integrity (Signature)

```
Algorithm : ML-DSA-65 (Dilithium variant) signs
            (kem_ct ‖ aes_ct ‖ nonce ‖ token_hash)

Quantum threat : Shor's algorithm (breaks ECDSA, RSA-PSS — NOT lattices)

ML-DSA-65:
  Security basis : Module Short Integer Solution (MSIS) over lattices
  Standard       : NIST FIPS 204 (2024)
  Security level : NIST Level 3 (~AES-192 equivalent)
  Quantum status : SAFE

Status : SAFE

Paper note:
  "Template integrity is guaranteed by an ML-DSA-65 [NIST FIPS 204] signature
   over the encrypted template and token hash. This prevents template
   substitution attacks even under a quantum-capable adversary."
```

---

### Layer 6 — Token Hash Storage

```
Algorithm : token_hash = SHA3-256(user_token).hexdigest()
            stored in voters table, UNIQUE constraint enforced

Quantum threat : Grover's algorithm (preimage search)
Classical preimage security : 2^256
Quantum preimage security   : 2^128

Status : SAFE (same analysis as Layer 2)

Paper note:
  "Only SHA3-256(token) is stored server-side. Under Grover's algorithm,
   token preimage recovery requires O(2^128) quantum operations — infeasible
   for any foreseeable quantum hardware."
```

---

### Layer 7 — Biometric Matching (Hamming Distance)

```
Algorithm : sim = 1 - count(stored_bits ≠ query_bits) / 2048
            accept if sim ≥ 0.818

Quantum threat : NONE
Reason        : Hamming distance is a non-cryptographic comparison function.
                There is no "break the matching" attack. The question of
                whether a given fingerprint exceeds threshold 0.818 is a
                physics / sensor problem, not a cryptographic one.
                Amplitude amplification (Grover-like) cannot be meaningfully
                applied because there is no oracle for "find a fingerprint
                that matches voter X" — the stored template is encrypted and
                the threshold check happens inside the authority's trusted
                environment after ML-KEM decryption.

Status : NOT APPLICABLE (not a cryptographic primitive)
```

---

### Layer 8 — Bio-Commitment (Biometric-Ballot Binding)

```
Algorithm : bio_commitment = SHA3-256(BioHash.tobytes())
            stored in VoteRecord.bio_commitment
            included in ML-DSA-65 ballot signature payload:
              sig = ML-DSA-65.sign(enc_vote ‖ zkp_hash ‖ bio_commitment)

Quantum threat : Grover (second preimage on SHA3-256)
Quantum security : 2^128 second preimage resistance

Status : SAFE

Paper note:
  "The biometric commitment binds each ballot to the voter's live biometric
   session. The commitment is SHA3-256 of the BioHash output, providing
   128-bit second-preimage resistance against quantum adversaries."
```

---

## Complete Quantum Safety Summary Table

| Biometric Component | Algorithm | Quantum Threat | Quantum Security | Status |
|---|---|---|---|---|
| Feature extraction (Gabor+HOG) | Signal processing | None | N/A | Safe |
| Token seed derivation | SHAKE256, 256-bit output | Grover | 2^128 | Safe |
| Projection matrix (QR decomp) | Linear algebra | None | Information-theoretic | Safe |
| Template encryption (key) | ML-KEM-768 (FIPS 203) | Shor (inapplicable) | ~2^178 (BKZ est.) | Safe |
| Template encryption (payload) | AES-256-GCM | Grover | 2^128 | Safe |
| Template integrity | ML-DSA-65 (FIPS 204) | Shor (inapplicable) | NIST Level 3 | Safe |
| Token hash | SHA3-256 | Grover | 2^128 | Safe |
| Hamming distance matching | Integer arithmetic | None | N/A | Safe |
| Bio-commitment | SHA3-256 | Grover (2nd preimage) | 2^128 | Safe |

---

## The One Real Limitation

```
The projection matrix's cancelability is ONLY as strong as the token's secrecy.

If an attacker obtains the raw token (not just its SHA3 hash), they can:
  1. Regenerate the projection matrix deterministically.
  2. Re-compute BioHash(fingerprint, stolen_token) for any fingerprint they
     have access to.
  3. Compare to the stored (encrypted) template — IF they also break the
     ML-KEM-768 encryption (which requires a quantum computer capable of
     attacking MLWE, not currently feasible).

This is NOT a quantum problem — it is a secret management problem.
A classical attacker who steals the token faces the same capability.

Mitigation already implemented:
  - Token never stored in plaintext (only SHA3-256 hash).
  - Template encrypted with ML-KEM-768 (quantum-safe).
  - 5-attempt lockout prevents online token guessing.
  - Voter-initiated revocation (prepare_revocation_request) allows
    immediate cancellation if compromise is suspected.

Paper framing:
  "The security of template cancelability reduces to the secrecy of the
   user token, which is protected by SHA3-256 hashing (128-bit quantum
   preimage resistance) and ML-KEM-768-encrypted storage. This security
   model is consistent with ISO/IEC 24745:2022 §6.2 (irreversibility
   and unlinkability requirements)."
```

---

## Suggested Paper Paragraph (Section 4 — Security Analysis)

```
4.X Post-Quantum Security of the Biometric Layer

The biometric template protection layer achieves end-to-end post-quantum
security through the following design choices:

(1) Template Confidentiality. The raw BioHash template is encrypted using
ML-KEM-768 [NIST FIPS 203, 2024], a Module-LWE-based key encapsulation
mechanism. Since Shor's algorithm [Shor 1994] does not apply to lattice
problems, this encryption remains secure against quantum adversaries.
The symmetric payload is protected by AES-256-GCM, which retains 128-bit
security under Grover's algorithm [Grover 1996; NIST SP 800-131A Rev. 2].

(2) Template Integrity. An ML-DSA-65 [NIST FIPS 204, 2024] signature over
the encrypted template and token hash prevents substitution attacks. ML-DSA-65
is based on Module-SIS hardness, which is not threatened by known quantum
algorithms.

(3) Token Protection. Only SHA3-256(token) is stored. Under Grover's
algorithm, preimage recovery requires O(2^128) quantum operations — beyond
the reach of any foreseeable quantum hardware.

(4) Cancelability. The unlinkability between revoked and fresh templates
is information-theoretic (orthogonal subspaces from QR decomposition) and
independent of any computational hardness assumption. Quantum computing
does not affect this property.

(5) Biometric Matching. The Hamming distance comparison used for template
verification is a non-cryptographic distance function. Quantum algorithms
provide no advantage in matching or forging biometric comparisons.

We note that biometric liveness detection (Presentation Attack Detection,
PAD) is a hardware dependency outside the scope of this software prototype
[ISO/IEC 30107-3:2023].
```

---

## References to Cite

1. NIST FIPS 203 (2024) — ML-KEM (Kyber): Module-Lattice Key Encapsulation
2. NIST FIPS 204 (2024) — ML-DSA (Dilithium): Module-Lattice Digital Signatures
3. NIST SP 800-131A Rev. 2 (2019) — Transitioning Use of Cryptographic Algorithms
4. Grover, L.K. (1996). "A fast quantum mechanical algorithm for database search." STOC.
5. Shor, P.W. (1994). "Algorithms for quantum computation." FOCS.
6. ISO/IEC 24745:2022 — Biometric Information Protection (cancelability, irreversibility)
7. Jin, A.T.B., Ling, D.N.C., Goh, A. (2004). "Biohashing." Pattern Recognition.
8. Teoh, A.B.J., et al. (2006). "Random multispace quantisation as an analytic mechanism
   for BioHashing of biometric and random identity inputs." IEEE TPAMI.
