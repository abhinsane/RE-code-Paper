# System Expandability Assessment
## Post-Quantum Secure E-Voting System

---

## Overall Expandability Rating: 8.5 / 10

Architecture is modular — each component is independently replaceable.
Clean separation: biometric, FHE, ZKP, blockchain, Ethereum are loosely coupled.

---

## Easy Expansions (< 1 week, no architectural change)

### E1. Increase Voter/Candidate Counts
```
File: pq_evoting/config.py

Change:
  NUM_CANDIDATES — increase for more candidates (ZKP adjusts automatically)
  FHE_SHARD_SIZE — tune per deployment (currently 3200; safe up to ~16,000 at degree=16384)

No other changes needed. ZKP bit-length and FHE one-hot vector both
auto-scale from num_candidates.
```

### E2. Stronger Authentication Window
```
File: pq_evoting/config.py

Change:
  AUTH_SESSION_TIMEOUT = 300   # 5 minutes (stricter)
  BIO_MAX_AUTH_ATTEMPTS = 3    # stricter lockout
  BIO_LOCKOUT_SECONDS   = 600  # longer lockout
```

### E3. Persistent Storage ✓ IMPLEMENTED (VoterRegistry)
```
Status: IMPLEMENTED for VoterRegistry.

pq_evoting/voter.py — VoterRegistry uses SQLite-backed write-through cache.
  Schema: voters table (13 columns, token_hash UNIQUE) + audit_events table.
  All mutations persist immediately; cache rebuilds from DB on startup.
  Token uniqueness enforced at registration time.

Remaining: Blockchain vote records still in-memory only.
Impact: Makes voter enrollment crash-safe; blockchain persistence is future work.
```

### E4. Batch Ethereum Anchoring
```
File: eth_integration/bridge.py

Current: One Ethereum transaction per vote (~50,000 gas each)
Fix: Batch 100 votes per transaction, store Merkle root only
Result: ~500 gas per vote (100× cheaper)

Estimated effort: 2–3 days
```

### E5. REST API Layer
```
New file: api.py (FastAPI or Flask)

Expose endpoints:
  POST /register     — voter enrollment
  POST /authenticate — biometric check
  POST /vote         — cast ballot
  GET  /results      — election results (after close)
  GET  /chain        — blockchain explorer

Estimated effort: 1 week
Impact: Makes system deployable as a web service.
```

### E6. Export Results to PDF / CSV
```
File: gui/app.py or new export.py

Generate:
  - PDF election report (plotly → kaleido → PDF)
  - CSV tally export
  - JSON audit log

Estimated effort: 1–2 days
```

---

## Medium Expansions (1–4 weeks)

### M1. Per-User Adaptive Biometric Threshold
```
Concept:
  Set a personalised Hamming threshold per voter at enrollment time.
  Accounts for individual fingerprint quality variation.

Changes:
  - voter.py: add bio_genuine_mean, bio_genuine_std, bio_threshold fields
  - cancellable_biometric.py: enroll_with_calibration() method
  - voting_system.py: pass per-user threshold to verify()

Expected gain: Simultaneous FAR↓ and FRR↓ vs. global threshold.
Estimated effort: 1 week
Paper value: High — novel contribution if combined with PQ context.
```

### M2. ML-Based Biometric Score Classifier (SVM)
```
Concept:
  Replace hard Hamming threshold with SVM trained on genuine/impostor pairs.
  Keeps BioHash format — no change to template storage or encryption.

Changes:
  - New file: pq_evoting/bio_classifier.py
  - cancellable_biometric.py: call classifier.predict() after BioHash comparison

Training data:
  SOCOFing 6,000 images → ~5,000 genuine pairs + ~50,000 impostor pairs.
  SVM in 11D feature space (block-wise Hamming + entropy features).

Expected gain: FAR drops from ~3–5% → ~0.3–0.8% (at same FRR).
Estimated effort: 1–2 weeks
Paper value: Very high — clean ablation study contribution.
```

### M3. Multi-Impression Enrollment
```
Concept:
  Enroll 3–5 fingerprint impressions per voter.
  Compute mean BioHash across all impressions → lower intra-class variance.

Changes:
  - cancellable_biometric.py: enroll_multi(image_paths) method
  - voter.py: store multiple templates or mean template
  - voting_system.py: register_voter() accepts list of images

Expected gain: 30–50% FRR reduction, allowing higher threshold → lower FAR.
Estimated effort: 1 week
```

### M4. Upgrade FHE to CKKS
```
Concept:
  Replace BFV with CKKS (Cheon-Kim-Kim-Song) for approximate arithmetic.
  CKKS supports unlimited additions (no noise ceiling in practice).

Changes:
  - fhe_voting.py: replace ts.SCHEME_TYPE.BFV with ts.SCHEME_TYPE.CKKS
  - Change context parameters (scale, coeff_mod_bit_sizes)
  - finalize(): round CKKS real-valued output to nearest integer

Trade-off:
  CKKS gives approximate values — need rounding at decryption.
  For vote counting, rounding error < 0.5 means exact integer recovery.

Estimated effort: 2–3 weeks
Impact: Removes all vote ceiling concerns even without sharding.
```

### M5. Ethereum Mainnet / Testnet Deployment
```
Current: In-memory EVM emulator (eth-tester + py-evm).
VotingLedger.sol is already production-ready.

Steps:
  1. Configure ETH_RPC_URL (Infura, Alchemy, or self-hosted node)
  2. Set ETH_CONTRACT_ADDR (deploy VotingLedger.sol via hardhat/foundry)
  3. Set ETH_PRIVATE_KEY (authority wallet)
  4. Switch EthBridge from in-memory to live mode

Estimated effort: 1–2 weeks (mostly DevOps, not crypto)
Impact: Public, immutable audit trail — major deployment milestone.
```

---

## Hard Expansions (1–3 months, research-grade)

### H1. Threshold FHE Decryption
```
Concept:
  Require k-of-n election officials to jointly decrypt the tally.
  No single official can decrypt alone.

Technical approach:
  Use OpenFHE's ThresholdFHE module (C++ with Python bindings).
  Alternative: MK-CKKS (Multi-Key CKKS) where each official has own key.

Changes:
  - Replace FHEAuthority with ThresholdFHEAuthority
  - Add distributed key generation protocol
  - Add partial decryption + combination protocol

Why hard:
  Requires multi-party coordination protocol.
  Network layer needed for officials to exchange partial decryptions.
  Key ceremony must be secure (HSMs recommended).

Paper value: Extremely high — solves the #1 remaining architectural weakness.
Estimated effort: 4–8 weeks
```

### H2. ZKP-FHE Cryptographic Binding (Proof-of-Knowledge of BFV Plaintext)
```
Concept:
  Prove that the ZKP and the FHE ciphertext encrypt the SAME value.
  Closes the most significant cryptographic gap in the current system.

Technical approach:
  See: Bois et al. "Flexible and Efficient Verifiable Computation on
  Encrypted Data." EUROCRYPT 2021.
  Also: Ganesh et al. "Rinocchio: SNARKs for Ring Arithmetic." 2021.

Why hard:
  Requires zkSNARK or sigma protocol that spans both lattice domains.
  No off-the-shelf Python library for this.
  Implementing from scratch = publishable paper.

Paper value: Publishable on its own if implemented correctly.
Estimated effort: 2–4 months
```

### H3. Mix-Net Layer for Submission Anonymity
```
Concept:
  Voters submit encrypted ballots to N mix servers in sequence.
  Each server shuffles and re-encrypts the batch.
  Authority receives shuffled batch — cannot link voter to ballot by timing.

Why needed:
  Currently, the authority sees: "voter X submitted ballot Y at time T."
  A traffic-analysing adversary can link voter to ballot timing.

Technical approach:
  Verifiable Shuffle (ElGamal or lattice-based).
  Abe-Imai shuffle or Wikstrom shuffle.

Estimated effort: 2–3 months
```

### H4. Formal Security Proofs
```
What's needed:
  - QROM (Quantum Random Oracle Model) soundness proof for the Fiat-Shamir ZKP
  - Simulation-based security (UC model) for the full protocol
  - Game-based proof of ballot secrecy

Why hard:
  Requires academic cryptography expertise.
  QROM proofs are more complex than ROM proofs.
  Full UC security proofs for voting systems are conference-paper-length work.

Estimated effort: 6–12 months with academic collaboration
```

---

## Expansion Priority Map for a Student Project

```
Semester 1 (Prototype — done):
  ✓ ML-KEM-768 + ML-DSA-65 encryption and signatures
  ✓ BFV homomorphic tallying (degree=16384, shard_size=3200)
  ✓ Lattice ZKP range proof (q=2³¹-1, n=128, m=256, β=2000, bit-sum check)
  ✓ Cancellable BioHash authentication (2048-bit, Gabor+HOG)
  ✓ Custom blockchain + Ethereum anchoring
  ✓ SQLite-backed VoterRegistry with audit log
  ✓ 12 security bugs identified and fixed

Semester 2 (Evaluation — do these):
  → ROC-optimal biometric threshold (1 day)
  → Multi-impression enrollment study (1 week)
  → SVM classifier ablation (2 weeks)
  → ShardedFHETally vote limit removal (done)
  → Performance benchmarks (see paper-writing-guide.md)

If time permits (thesis extension):
  → Per-user adaptive threshold (elegant contribution)
  → Threshold FHE (major contribution)
  → PoK-FHE binding (publication-level contribution)
```
