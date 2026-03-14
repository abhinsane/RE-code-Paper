# System Vulnerability Assessment
## Post-Quantum Secure E-Voting System

---

## Overall Security Rating: 8.0 / 10

The cryptographic primitives are all NIST-standardized (FIPS 203/204).
Vulnerabilities are **architectural**, not algorithmic.

---

## 1. Bugs Found and Fixed (All Patched in Current Codebase)

These were real security holes that were identified and corrected. Useful to
mention in a paper as part of your security analysis / implementation
hardening section.

| # | Bug | Severity | Impact if Exploited | Fix Applied |
|---|-----|----------|---------------------|-------------|
| 1 | ZKP bit commitments never verified in `verify_vote_proof()` | Critical | Voter could submit out-of-range vote (e.g., candidate index 99 in a 4-candidate election) | Enforced `len(bc) == n_bits` check |
| 2 | ZKP proof dict included `bits_s` (raw binary vote) | Critical | Authority could directly read voter's choice from the proof | Removed `bits_s` from returned proof |
| 3 | BioHash RNG seed only 32-bit entropy (reduced from 8 bytes) | Critical | Token brute-forceable in seconds on commodity hardware | Now derives full 256-bit seed via SHAKE256 |
| 4 | Genesis block skipped in `verify_chain()` | High | Attacker could silently replace the first block | Genesis now verified like all other blocks |
| 5 | VoteRecord serialisation excluded signature + public key | High | Adversary could swap voter keys without invalidating Merkle root | All 7 fields now included in serialisation |
| 6 | Fiat-Shamir challenge used only 4 bytes of SHA3-256 | High | Soundness error ~2^{-32} instead of ~2^{-256} | Now uses all 32 bytes |
| 7 | ZKP bit-length off-by-one: used `num_candidates.bit_length()` | Medium | Range proof admitted one extra invalid index | Fixed to `(num_candidates - 1).bit_length()` |
| 8 | Auth session token had no expiry | Medium | Auth from morning valid all day; voter walks away unattended | `AUTH_SESSION_TIMEOUT = 600 s` enforced |
| 9 | FHETally used full secret-key context for accumulation | Low | Secret key embedded in tally object unnecessarily | Tally now uses public context only |
| 10 | ZKP verifier never checked bit-sum consistency (`C_main ≠ Σ 2^i · C_bit_i`) | High | Prover could supply mismatched `r_main` and pass verification | Verifier now recomputes `C_sum = Σ 2^i · C_bit_i (mod q)` and asserts `C_sum == C_main` |
| 11 | Blockchain nullifier was `SHA3(voter_id_hash)` — cross-election replay possible | Medium | Voter nullifier from election A also valid in election B (same voter_id) | Nullifier now `SHA3(voter_id_hash ‖ election_id)` — unique per election |
| 12 | VoterRegistry allowed duplicate token registration | Medium | Same token reused across voters could corrupt BioHash lookups | `token_hash` column has UNIQUE constraint; duplicate rejected at registration |

---

## 2. Remaining Architectural Vulnerabilities (Documented Limitations)

### 2.1 Single-Authority FHE Decryption — HIGH

```
Problem:
  The ElectionAuthority holds the sole BFV secret key.
  Compromise of the authority server exposes ALL votes retroactively.

Real-world analogy:
  One official holds the only key to every sealed ballot box.

Academic framing:
  Violates the "no single point of trust" requirement of Juels et al. [2005]
  and the multi-authority model of Cramer et al. [1997].

Fix (future work):
  Threshold FHE — require k-of-n officials to jointly decrypt.
  OpenFHE supports threshold BFV/CKKS natively.
  MK-CKKS (Multi-Key CKKS) is the state-of-the-art approach.

Paper note:
  Cite as an open limitation. Threshold FHE is an active research area.
  Do NOT claim your system solves this.
```

### 2.2 ZKP-FHE Binding Gap — HIGH

```
Problem:
  Your ZKP proves: "I know a vote value v in {0,...,n-1}"    [lattice proof]
  Your FHE encrypts: some value v'                            [BFV ciphertext]

  There is NO cryptographic link between v and v'.

  A malicious voter could:
    (a) ZKP-prove vote = 2  (valid range, accepted)
    (b) FHE-encrypt vote = 0 (votes differently than proved)

  The authority accepts both checks independently.

Why this is hard to fix:
  Requires a "Proof of Knowledge of BFV Plaintext" (PoK-FHE).
  This is an active research topic. Recent papers:
    - Bois et al. "Flexible and Efficient Verifiable Computation on
      Encrypted Data" (EUROCRYPT 2021)
    - Ganesh et al. "Rinocchio: SNARKs for Ring Arithmetic" (2021)

  Implementing this from scratch is a publishable contribution.

Paper note:
  EXPLICITLY state this gap in your threat model section.
  Frame it as: "The ZKP and FHE components are independently sound;
  binding them cryptographically is deferred to future work."
  Reviewers will ask if you don't address this proactively.
```

### 2.3 BFV Noise Ceiling — MEDIUM (Now Mitigated)

```
Status: MITIGATED via ShardedFHETally + degree upgrade

Original problem:
  BFV ciphertext noise grows linearly with each homomorphic addition.
  At poly_modulus_degree=4096 → corruption after ~1,000 votes.

Current status after fix:
  poly_modulus_degree=16384, plain_modulus=786433 (≡1 mod 32768).
  → ~16,000 votes per shard before noise ceiling.
  ShardedFHETally splits stream into shards of ≤ 3,200 votes.
  Each shard decrypted independently → no noise crosses boundaries.
  Effective limit: unlimited voters.

Paper note:
  Report the original parameter choice and the mitigation.
  Include a figure showing noise growth vs. vote count (before/after).
```

### 2.4 No Liveness Detection (PAD) — MEDIUM

```
Problem:
  The biometric module accepts a printed photograph of a fingerprint.
  No Presentation Attack Detection (PAD) implemented.

Why:
  PAD requires hardware (capacitive sensors, optical sensors with IR)
  or deep learning on high-resolution images.

Paper note:
  Cite ISO/IEC 30107 (Biometric Presentation Attack Detection).
  State this is a hardware dependency, out of scope for the software
  prototype. Recommend future integration with FIDO2 authenticators
  or hardware security modules (HSMs).
```

### 2.5 In-Memory Storage — LOW (Now Implemented)

```
Status: IMPLEMENTED — VoterRegistry is now SQLite-backed.

VoterRegistry uses a write-through in-memory cache backed by SQLite.
Schema: voters table (13 columns incl. token_hash) + audit_events table.
All mutations persist immediately; cache rebuilds from DB on startup.
Token uniqueness enforced at registration time (UNIQUE constraint).

Remaining gap:
  Blockchain vote records still in-memory only.
  Persistence for the blockchain is deferred to future work.

Paper note:
  State "voter enrollment data is persisted to SQLite with an append-only
  audit log. Blockchain persistence is deferred to future engineering work."
```

---

## 3. What a Real Attacker Would Target (Threat Model)

```
Attack Surface 1 — Compromise Authority Server
  Goal: Steal BFV secret key
  Consequence: Decrypt all votes retroactively
  Likelihood: High (nation-state adversary)
  Mitigation: Threshold FHE (future work)

Attack Surface 2 — Submit Malformed ZKP + Mismatched FHE
  Goal: Cast vote for unintended candidate while passing all checks
  Consequence: Vote recorded for wrong candidate
  Likelihood: Medium (requires technical sophistication)
  Mitigation: PoK-FHE binding (future work)

Attack Surface 3 — Fingerprint Presentation Attack
  Goal: Authenticate as another voter using printed fingerprint
  Consequence: Vote cast fraudulently on victim's behalf
  Likelihood: Low-Medium (requires physical access)
  Mitigation: Hardware PAD sensor (future work)

Attack Surface 4 — Blockchain Replay / Fork
  Goal: Submit same vote twice or fork the chain
  Consequence: Double-vote or altered tally
  Likelihood: Low (requires authority-level access)
  Mitigation: Nullifier registry + Ethereum anchoring (already implemented)

Attack Surface 5 — Quantum Adversary
  Goal: Break encryption post-election using a quantum computer
  Consequence: All votes decrypted
  Likelihood: Future threat (5–20 year horizon)
  Mitigation: ML-KEM-768 + ML-DSA-65 (already implemented, NIST FIPS 203/204)
```

---

## 4. Security Properties Achieved

| Property | Achieved | Method |
|----------|----------|--------|
| Ballot secrecy | Yes | FHE (no decryption mid-election) |
| Voter anonymity | Yes | SHA3-256(voter_id) on chain, not plaintext |
| Vote integrity | Yes | ML-DSA-65 per-ballot signature |
| Verifiability | Yes | ZKP range proof per vote |
| Double-vote prevention | Yes | Nullifier registry + Ethereum |
| Quantum resistance | Yes | ML-KEM-768 + ML-DSA-65 (NIST FIPS 203/204) |
| Template cancelability | Yes | BioHash with per-voter token |
| Threshold decryption | No | Future work |
| ZKP-FHE binding | No | Future work |
| Liveness detection | No | Hardware dependency |
