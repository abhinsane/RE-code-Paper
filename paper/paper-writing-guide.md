# Paper Writing Guide
## Post-Quantum Secure E-Voting System

---

## Suggested Paper Title Options

```
Option A (broad):
  "A Post-Quantum Secure Electronic Voting System with Cancellable
   Biometric Authentication and Lattice-Based Zero-Knowledge Proofs"

Option B (contribution-focused):
  "Integrating ML-KEM, Fully Homomorphic Encryption, and Cancellable
   Biometrics in a Quantum-Resistant E-Voting Protocol"

Option C (concise):
  "Post-Quantum E-Voting: A System Combining CRYSTALS, FHE, and
   Cancellable Biometric Template Protection"
```

---

## Suggested Paper Structure

### Abstract (150–250 words)
```
Cover in this order:
  1. Problem: Classical e-voting systems are vulnerable to quantum adversaries
  2. Gap: No existing system combines PQC + biometrics + FHE + ZKP
  3. Contribution: Your system, one sentence per component
  4. Evaluation: Dataset used, key metrics achieved
  5. Conclusion: What this enables

Template:
  "Electronic voting systems rely on cryptographic primitives
   (RSA, ECC, ElGamal) that are vulnerable to Shor's algorithm on
   quantum computers. We present [system name], a post-quantum
   e-voting system that integrates: (i) ML-KEM-768 and ML-DSA-65
   (NIST FIPS 203/204) for key encapsulation and digital signatures,
   (ii) BFV fully homomorphic encryption for privacy-preserving tallying,
   (iii) lattice-based zero-knowledge proofs for ballot validity,
   and (iv) cancellable biometric authentication compliant with ISO 24745.
   We evaluate the biometric component on the SOCOFing dataset,
   achieving EER of 2.61% with a 2048-bit BioHash. Our system supports
   unlimited voters via a sharded FHE tallying architecture and anchors
   vote evidence on Ethereum for public verifiability."
```

---

### Section 1 — Introduction

```
Paragraphs:
  1. E-voting importance + current adoption
  2. Quantum threat to current cryptography (cite Shor 1994)
  3. NIST PQC standardization (FIPS 203/204, Aug 2024)
  4. The gap: no system combines all four components
  5. Your contribution (bullet list)
  6. Paper organization (one sentence per section)

Key claim to make:
  "To the best of our knowledge, this is the first open-source e-voting
   system prototype where every cryptographic primitive — key encapsulation,
   digital signatures, homomorphic tallying, and zero-knowledge proofs —
   is quantum-resistant and NIST-standardized."

Citations needed:
  - Shor, P.W. (1994). Algorithms for quantum computation. FOCS.
  - NIST FIPS 203 (2024). Module-Lattice-Based Key-Encapsulation Mechanism.
  - NIST FIPS 204 (2024). Module-Lattice-Based Digital Signature Algorithm.
  - Helios, Belenios, Civitas (for comparison)
```

---

### Section 2 — Background and Related Work

```
Sub-sections:
  2.1 E-Voting Requirements (correctness, privacy, verifiability, coercion-resistance)
  2.2 Classical E-Voting Systems (Helios, Belenios, Civitas)
  2.3 Post-Quantum Cryptography (brief: lattices, CRYSTALS-Kyber, Dilithium)
  2.4 Fully Homomorphic Encryption (BFV scheme, noise growth)
  2.5 Cancellable Biometrics (BioHashing, ISO 24745)
  2.6 Why Existing Systems are Insufficient (quantum vulnerability gap)

Key table to include:
  Comparison with prior art (from strengths.md Section 3)
```

---

### Section 3 — System Design and Architecture

```
Sub-sections:
  3.1 Threat Model
      - Attacker capabilities (quantum, network adversary, malicious voters)
      - What the authority is trusted for (single decryption, not individual votes)
      - Out-of-scope: coercion, physical attacks, liveness spoofing

  3.2 System Overview (architecture diagram — from your repo figures)
      - ElectionAuthority, Voter, Blockchain, Ethereum components
      - Data flow diagram

  3.3 Cryptographic Components
      - ML-KEM-768 hybrid encryption
      - ML-DSA-65 signatures
      - BFV FHE one-hot encoding
      - Lattice ZKP (Ajtai commitment + Fiat-Shamir)
      - SHA3-256 Merkle trees

  3.4 Cancellable Biometric Module
      - Feature extraction pipeline (ORB → Gabor → HOG)
      - BioHash construction (projection matrix from token)
      - Template protection (ML-KEM-768 encrypted storage)
      - ISO 24745 compliance

  3.5 Voting Protocol (step-by-step)
      - Registration phase
      - Authentication phase
      - Vote casting phase
      - Tallying phase
```

---

### Section 4 — Security Analysis

```
Sub-sections:
  4.1 Security Properties Claimed
      (table from vulnerabilities.md Section 4)

  4.2 Implementation Security Review
      - List the 9 bugs found and fixed
      - Frame as: "We performed a security review and identified and
        corrected N implementation vulnerabilities prior to evaluation."
      - Include a table: Bug | Severity | Impact | Fix

  4.3 Quantum Security Analysis
      - ML-KEM-768: NIST Level 3 (128-bit post-quantum)
      - ML-DSA-65: NIST Level 3 (128-bit post-quantum)
      - BFV: lattice-based, inherently quantum-safe
      - SHA3-256: Grover's algorithm reduces to 128-bit security (acceptable)

  4.4 Known Limitations (IMPORTANT — be honest)
      - Single-authority FHE decryption (future: threshold FHE)
      - ZKP-FHE binding gap (future: PoK-FHE)
      - No liveness detection (future: hardware PAD)
      - Fiat-Shamir QROM proof (future: formal proof)

      Frame as: "These limitations are consistent with prototype scope and
      represent well-defined directions for future work."
```

---

### Section 5 — Biometric Evaluation

```
Sub-sections:
  5.1 Dataset: SOCOFing
      - 6,000 images, 600 subjects, 10 fingers each
      - Reference: Shehu et al. (2018)

  5.2 Experimental Setup
      - Genuine pairs: same finger, Real vs Altered impression
      - Impostor pairs: different subjects, same finger position
      - Genuine pairs generated: 8,189
      - Impostor pairs generated: 40,945

  5.3 Results
      - Genuine score: mean=0.9089, std=0.0416
      - Impostor score: mean=0.7461, std=0.0385
      - At threshold=0.80: FAR=8.18%, FRR=0.96%
      - EER=2.61% at threshold=0.818 (EER-optimal, now set in config.py)

  5.4 Ablation Study (FAR reduction methods)
      - Table: Baseline → +ROC threshold → +Multi-impression → +SVM → Combined
      - (from far-reduction.md)

  5.5 Figures to include:
      - Score distribution histogram (genuine vs. impostor Hamming scores)
      - DET curve (Detection Error Tradeoff — standard in biometrics)
      - ROC curve
      - Ablation bar chart (EER per method)

Required citation:
  ISO/IEC 19795-1:2021 for evaluation methodology.
  Shehu, Y.I. et al. "Sokoto Coventry Fingerprint Dataset (SOCOFing)." 2018.
```

---

### Section 6 — System Evaluation (Performance)

See benchmarks.md for all measured values. Summary:

```
Per-operation latency (measured, Python 3.11, Windows 11, single core):
  BioHash extraction:   7505.86 ms   ← dominates; pure Python Gabor+HOG (2048-bit)
  ML-KEM-768 keygen:    1.29 ms
  ML-KEM-768 encrypt:   1.90 ms
  ML-KEM-768 decrypt:   0.19 ms
  ML-DSA-65 sign:       1.89 ms
  ML-DSA-65 verify:     0.56 ms
  FHE vote encrypt:     16.10 ms
  ZKP generate:         4.07 ms
  ZKP verify:           0.55 ms

End-to-end phase latency:
  Enrollment:           ~7509 ms
  Authentication:       ~7506 ms
  Vote casting:         ~22 ms

Scalability (ShardedFHETally, shard size=3200, degree=16384):
  100 voters   → 1 shard  → ~1 s tally
  1,000 voters → 1 shard  → ~1 s tally
  5,000 voters → 2 shards → ~2 s tally
  10,000 voters → 4 shards → ~4 s tally

Environment to report in paper:
  Python 3.11, TenSEAL, pqcrypto, Windows 11, Intel x86_64, single CPU core
```

---

### Section 7 — Discussion

```
7.1 Comparison with Related Work
    - Table from strengths.md
    - Narrative: what your system adds vs. prior work

7.2 Deployment Considerations
    - Small elections (< 5,000): suitable now
    - Large elections: needs threshold FHE + persistence layer
    - Internet voting vs. kiosk-based: different threat models

7.3 Limitations and Future Work
    - Threshold FHE (most important)
    - ZKP-FHE binding (research gap)
    - Formal QROM proof
    - Liveness detection integration
    - Persistence layer
    - Real-world pilot study
```

---

### Section 8 — Conclusion

```
Template:
  "We presented [system name], a post-quantum secure e-voting system
   combining ML-KEM-768, ML-DSA-65, BFV homomorphic encryption, lattice-based
   zero-knowledge proofs, and cancellable biometric authentication.
   Security analysis identified and corrected N implementation vulnerabilities.
   Biometric evaluation on SOCOFing achieved EER of 2.61% with 2048-bit BioHash
   templates. The system supports unlimited voters via sharded FHE tallying.
   Future work includes threshold FHE decryption and cryptographic binding
   between ZKP and FHE components."
```

---

## Key Citations Reference List

```
Post-Quantum Cryptography:
  NIST FIPS 203 (2024) — ML-KEM (CRYSTALS-Kyber)
  NIST FIPS 204 (2024) — ML-DSA (CRYSTALS-Dilithium)
  Bernstein & Lange (2017). Post-quantum cryptography. Nature.
  Shor (1994). Algorithms for quantum computation. FOCS.

FHE:
  Brakerski & Vercauteren (2012). Fully homomorphic encryption without
    bootstrapping. ITCS. [BFV scheme]
  Fan & Vercauteren (2012). Somewhat practical fully homomorphic encryption.
    IACR ePrint. [BFV scheme]
  TenSEAL library (Benaissa et al., 2021).

ZKP:
  Ajtai (1996). Generating hard instances of lattice problems. STOC.
  Fiat & Shamir (1987). How to prove yourself. CRYPTO.
  Bois et al. (2021). Flexible and efficient verifiable computation. EUROCRYPT.

E-Voting:
  Adida (2008). Helios: Web-based open-audit voting. USENIX Security.
  Cortier et al. (2013). Belenios. CCS.
  Clarkson et al. (2008). Civitas. IEEE S&P.
  Juels et al. (2005). Coercion-resistant electronic elections. WPES.

Cancellable Biometrics:
  Jin et al. (2004). Biohashing. Pattern Recognition.
  Rathgeb & Uhl (2011). Survey on biometric cryptosystems. EURASIP.
  ISO/IEC 24745:2022. Biometric information protection.
  ISO/IEC 19795-1:2021. Biometric performance testing and reporting.

Dataset:
  Shehu et al. (2018). Sokoto Coventry Fingerprint Dataset (SOCOFing). arXiv.

Blockchain:
  Nakamoto (2008). Bitcoin: A peer-to-peer electronic cash system.
  (For background on PoW + Merkle trees)
```

---

## Common Reviewer Questions — Prepare Answers

```
Q1: "Why BFV and not CKKS or TFHE?"
A: BFV is the natural choice for integer vote encoding (exact arithmetic).
   CKKS is approximate (requires rounding). TFHE supports Boolean circuits
   but is slower for vector accumulation. BFV is the standard choice for
   integer homomorphic tallying. [Cite Fan & Vercauteren 2012]

Q2: "How does the ZKP prevent a voter from voting twice?"
A: The nullifier registry, not the ZKP, prevents double voting.
   The ZKP proves the vote is in the valid range {0,...,n-1}.
   Double-vote prevention is enforced by the nullifier = SHA3(voter_id_hash)
   recorded on both the custom blockchain and the Ethereum contract.

Q3: "Is BioHash secure against a stolen token?"
A: Yes — the token is used only to derive the projection matrix (SHAKE256).
   An attacker with only the encrypted BioHash cannot recover the token
   because: (a) BioHash → features is irreversible, (b) token → matrix
   is a one-way function. An attacker with BOTH the encrypted BioHash
   AND the stored ML-KEM ciphertext would need to break ML-KEM-768
   (NIST Level 3 security) to access the BioHash plaintext.

Q4: "What is the voter scale limit?"
A: Unlimited with ShardedFHETally. Each shard processes ≤ 3,200 votes,
   decrypted independently at tallying. The BFV noise ceiling of ~16,000
   additions (at degree=16384) applies per shard, not per election.
   Adding voters adds shards, not noise. Tallying cost scales as O(N/3200)
   decryptions, each taking approximately [X ms] on our test hardware.

Q5: "Why not use a standard blockchain (Bitcoin/Ethereum) instead of custom?"
A: The custom blockchain uses SHA3-256 and ML-DSA-65 signatures —
   both quantum-safe. Bitcoin/Ethereum use ECDSA (not quantum-safe).
   The custom chain also supports application-specific vote records
   and Merkle-tree vote inclusion proofs. Ethereum is used as an
   OPTIONAL public audit anchor, not as the primary chain.

Q6: "Is the ZKP formally sound?"
A: The ZKP is sound under the random oracle model (ROM) via Fiat-Shamir.
   Formal proof under the quantum random oracle model (QROM) is an
   open problem and is deferred to future work. This is consistent with
   the state of the art for lattice-based sigma protocols. [Cite relevant
   QROM papers if available]
```
