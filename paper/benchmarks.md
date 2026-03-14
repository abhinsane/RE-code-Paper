# Performance Benchmarks
## Section 6 — System Evaluation

Measured on: Python 3.11, Windows 11, Intel x86_64, single CPU core, no hardware acceleration.
All values are mean over repeated runs (see counts below).

---

## Per-Operation Latency

| Component | Operation | Time (ms) | Runs |
|-----------|-----------|-----------|------|
| Biometric | BioHash extraction (Gabor+HOG → 2048-bit) | 7505.86 | 10 |
| ML-KEM-768 | Key generation | 1.29 | 20 |
| ML-KEM-768 | Encapsulate (hybrid AES-256-GCM encrypt) | 1.90 | 20 |
| ML-KEM-768 | Decapsulate (hybrid decrypt) | 0.19 | 20 |
| ML-DSA-65 | Sign | 1.89 | 50 |
| ML-DSA-65 | Verify | 0.56 | 50 |
| BFV FHE | Vote encrypt (one-hot, 3 candidates) | 16.10 | 5 |
| Lattice ZKP | Proof generation | 4.07 | 10 |
| Lattice ZKP | Proof verification | 0.55 | 10 |

---

## End-to-End Phase Latency

| Phase | Total (ms) | Breakdown |
|-------|-----------|-----------|
| Voter enrollment | ~7509 | BioHash (7505.86) + KEM-keygen (1.29) + KEM-enc (1.90) |
| Authentication | ~7506 | BioHash (7505.86) + KEM-dec (0.19) |
| Vote casting | ~22 | FHE-enc (16.10) + ZKP-gen (4.07) + DSA-sign (1.89) |

---

## Notes for Paper

- **BioHash (7505.86 ms)** dominates enrollment and authentication. This is the
  Gabor+HOG feature extraction pipeline running in pure Python with no
  hardware acceleration. On dedicated fingerprint scanner hardware with
  native C++ processing this is typically 20–50 ms.

- **All cryptographic primitives** (ML-KEM, ML-DSA, ZKP) are sub-millisecond
  to single-digit ms — negligible overhead compared to the biometric step.

- **FHE encryption (16.10 ms)** uses BFV with poly_modulus_degree=16384.
  Decryption (tallying) is performed once at election close, not per-voter,
  so its cost is amortised across all votes.

- **Vote casting (~22 ms)** is the voter-facing interactive latency after
  biometric authentication completes. This is well within acceptable UX.

---

## Scalability

| N voters | Enrollment (s) | Tallying shards | Tally time (est.) |
|----------|---------------|-----------------|-------------------|
| 100 | ~751 | 1 | ~1 s |
| 1,000 | ~7,509 | 1 | ~1 s |
| 5,000 | ~37,545 | 2 | ~2 s |
| 10,000 | ~75,090 | 4 | ~4 s |

Shard size: 3,200 votes/shard (ShardedFHETally). Tallying scales as O(N/3200).
Enrollment is parallelisable across kiosks in a real deployment.
