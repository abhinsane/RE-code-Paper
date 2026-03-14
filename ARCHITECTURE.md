# Post-Quantum E-Voting System — Architecture, Code Flow & Full System Working

---

## 1. High-Level Architecture

The system is built from **six independent cryptographic layers** composed by a central
orchestrator (`voting_system.py`).

```
┌──────────────────────────────────────────────────────────┐
│                    voting_system.py                       │
│          ElectionAuthority  ←→  Voter                    │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ │
│  │PQ    │ │BioHsh│ │ FHE  │ │ ZKP  │ │Chain │ │Voter │ │
│  │Crypto│ │      │ │(BFV) │ │Lattice│ │(PoW) │ │Regist│ │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ │
└──────────────────────────────────────────────────────────┘
         ↕ anchors final hash to
┌──────────────────────────────────────────────────────────┐
│             Ethereum (VotingLedger.sol)                   │
│          in-memory emulator OR live testnet               │
└──────────────────────────────────────────────────────────┘
```

---

## 2. Repository Layout

```
pq_evoting/
├── config.py                # All cryptographic parameters & tuning constants
├── pq_crypto.py             # ML-KEM-768 + ML-DSA-65 + AES-256-GCM primitives
├── cancellable_biometric.py # Gabor+HOG BioHashing + SOCOFing image loader
├── fhe_voting.py            # BFV homomorphic vote encryption & tallying
├── zkp.py                   # Lattice ZKP (two-component Sigma + CDS OR proofs)
├── blockchain.py            # SHA3-256 chain with PoW + ML-DSA-65 signed blocks
├── voter.py                 # Voter registration, SQLite registry, biometric lockout
├── voting_system.py         # ElectionAuthority + Voter orchestration classes
└── __init__.py

contracts/
└── VotingLedger.sol         # Solidity smart contract (Ethereum anchoring)

eth_integration/
└── bridge.py                # EthBridge: in-memory emulator OR live Web3

gui/
└── app.py                   # Streamlit 5-tab web dashboard

demo.py                      # CLI end-to-end demonstration
eval_biometric.py            # FAR/FRR/EER evaluation on SOCOFing
benchmark.py                 # Per-operation latency benchmarks
```

---

## 3. Cryptographic Parameter Reference

| Parameter | Value | Purpose |
|-----------|-------|---------|
| ZKP modulus q | 2^31 − 1 (Mersenne prime) | Lattice commitment modulus |
| ZKP n | 128 | Commitment output dimension |
| ZKP m | 256 | Randomness vector dimension |
| ZKP β | 2000 | Randomness ∞-norm bound |
| FHE poly_modulus_degree | 16384 | BFV ring dimension (~128-bit PQ security) |
| FHE plain_modulus | 786433 | ≡1 (mod 32768); prime; enables SIMD batching |
| FHE shard_size | 3200 | Votes per shard (5× safety margin vs. ~16k limit) |
| BioHash feature_dim | 2048 | BioHash output bits |
| PoW difficulty | 4 | Leading zero hex digits in block hash |
| BioHash threshold | 0.818 | Hamming similarity accept/reject boundary (EER-optimal) |
| Auth session timeout | 600 s | Biometric auth token validity window |
| Max auth attempts | 5 | Consecutive failures before lockout |
| Lockout duration | 300 s | Biometric lockout length |

---

## 4. Module-by-Module Breakdown

---

### 4.1 `pq_crypto.py` — Post-Quantum Primitives

Foundation for everything else. Three algorithms:

| Primitive | Algorithm | Standard |
|-----------|-----------|----------|
| Key encapsulation | ML-KEM-768 (Kyber) | NIST FIPS 203 |
| Digital signatures | ML-DSA-65 (Dilithium) | NIST FIPS 204 |
| Symmetric cipher | AES-256-GCM | NIST SP 800-38D |

**Hybrid encryption (`pq_encrypt`):**
```
recipient_kem_pk
  → ML-KEM-768.encapsulate()
  → (kem_ct, shared_secret)

shared_secret → SHAKE256("aes256gcm_key_derivation") → aes_key (256-bit)
aes_key + random nonce → AES-256-GCM.encrypt(plaintext) → aes_ct

return { kem_ct_hex, aes_ct_hex, nonce_hex }
```

**Hybrid decryption (`pq_decrypt`):**
```
kem_ct → ML-KEM-768.decapsulate(kem_sk) → shared_secret
shared_secret → SHAKE256(...) → aes_key
AES-256-GCM.decrypt(aes_ct, nonce, aes_key) → plaintext
```

`PQKeyPair` generates both a KEM keypair and DSA keypair in one call.
Every voter and the authority each hold their own `PQKeyPair`.
Secret keys never leave the entity that generated them.

---

### 4.2 `cancellable_biometric.py` — Biometric Template Protection

**Feature extraction pipeline (`extract_features`):**
```
fingerprint.BMP
  → grayscale + resize to 256×256
  → CLAHE (local contrast enhancement, clipLimit=3.0)
  → Gabor bank (48 filters: 3 wavelengths × 16 orientations)
       λ ∈ {6, 9, 12} px  (fine/medium/coarse ridge spacing)
       θ ∈ 0°–168.75° in 11.25° steps
       per-pixel maximum across all 48 filter responses
  → HOG descriptor on Gabor-enhanced image
       blockSize=32×32, blockStride=16×16, cellSize=16×16, nbins=9
       output: 225 blocks × 36 values = 8100-dim float32 vector
  → L2-normalise → fixed 8100-dim feature vector
```

**BioHash transformation (`compute_biohash`):**
```
user_token → SHAKE256("biohash_rng_seed" ‖ token, 32 bytes) → 256-bit seed
seed → numpy RNG → 8100×2048 normal matrix M
M → QR decompose → Q (8100×2048 orthonormal columns) → Q.T (2048×8100)
Q.T @ feature_vector → 2048-dim projected vector
projected > median(projected) → 2048-bit binary template
```

The QR decomposition guarantees orthonormality: different tokens produce
projection matrices that are geometrically unrelated. Templates from
different tokens cannot be linked or compared.

**Enrollment (`enroll`):**
```
extract_features(image) → 8100-dim feature
compute_biohash(feature, user_token) → 2048-bit binary template
template.tobytes() → pq_encrypt(authority_kem_pk, raw_bytes)
store: { encrypted_template, template_hash, token_hash, feature_dim }
```

**Verification (`verify`):**
```
1. SHA3(live_token) == stored token_hash?  → early reject if not
2. pq_decrypt(authority_kem_sk, encrypted_template) → stored_bits
3. extract_features(live_image) → compute_biohash(live_token) → query_bits
4. Hamming similarity = 1 - count(stored ≠ query) / 2048
5. return (similarity ≥ 0.818), similarity
```

**Template cancellation (`cancel_and_reenroll`):**
```
verify(old_token) must pass
enroll(image, new_token, authority_kem_pk) → completely new template
  (different projection matrix → different binary template → no linkage)
```

---

### 4.3 `zkp.py` — Lattice Zero-Knowledge Proof

Proves `vote ∈ {0, …, n_candidates−1}` **without revealing** which candidate.

**Public parameters (fixed, derived from `ELECTION_DOMAIN`):**
```
A ∈ Z_q^{128×256}  — deterministic public matrix (seeded from ELECTION_DOMAIN)
e₀ = [1, 0, …, 0]  — first standard basis vector (encodes the message)
q = 2^31 − 1        — Mersenne prime
β = 2000            — randomness bound
```

**`_matvec_mod(A, v, q)` — overflow-safe matrix-vector multiply:**

Direct `A @ v` overflows int64 when q = 2^31−1 because each row accumulates
up to 256 products of magnitude q² ≈ 2^62, which can exceed 2^63.
Solution: accumulate column-by-column, reduce mod q after each step.
Running sum always stays in [0, q) so the next product fits safely in int64.

**Main Ajtai commitment:**
```
C = A·r + vote·e₀  (mod q)
where r ∈ [−β, β]^256 is short randomness
```

**`prove_vote_range(vote, voter_id, election_id)`:**
```
ctx = voter_id ‖ election_id ‖ ELECTION_DOMAIN

Step 1: Binary decomposition (MSB first)
  bits = binary representation of vote in n_bits digits
  r_main = zeros(256)

  For each bit b_i:
    r_bit_i ← SHAKE256(ctx ‖ ":bit{i}") → short random vector in [-β,β]^256
    C_bit_i = A·r_bit_i + b_i·e₀  (mod q)
    bit_proof_i = CDS 1-of-2 OR proof (C_bit_i commits to 0 OR 1)
    r_main += 2^(n_bits−1−i) × r_bit_i  (mod q)

Step 2: Main commitment (derived — not independently sampled)
  C_main = A·r_main + vote·e₀  (mod q)
  By construction: C_main ≡ Σ 2^i · C_bit_i (mod q)

Step 3: Sigma proof of knowledge of (vote, r_main) for C_main
  Announcement: w = A·ρ_r + ρ_v·e₀
  Challenge:    c = SHA3(w ‖ C_main ‖ ctx)  (Fiat-Shamir)
  Response:     z_r = ρ_r + c·r_main  (mod q)
                z_v = ρ_v + c·vote    (mod q)

Step 4: Consistency hash
  SHA3(C_main ‖ all_C_bit_i ‖ ctx)  — binds all commitments to voter context
                                       (vote value NOT included — would reveal it)
```

**`verify_vote_proof(proof, voter_id, election_id)`:**
```
1. voter_id_hash in proof matches SHA3(voter_id)?
2. num_candidates matches?
3. Sigma knowledge proof for C_main:
     A·z_r + z_v·e₀ ≡ w + c·C_main  (mod q)
     c == SHA3(w ‖ C_main ‖ ctx)?
4. len(bit_commitments) == len(bit_proofs) == n_bits?
5. For each bit i: CDS OR proof checks:
     (c_0 + c_1) ≡ FS(w_0 ‖ w_1 ‖ T_0 ‖ T_1 ‖ ctx)  (mod q)
     A·z_0 ≡ w_0 + c_0·T_0  (mod q)
     A·z_1 ≡ w_1 + c_1·T_1  (mod q)
6. BIT-SUM CHECK:
     C_sum = Σ 2^(n_bits−1−i) · C_bit_i  (mod q)
     C_sum == C_main?   ← closes the soundness gap
7. Consistency hash matches?
```

**Why the bit-sum check matters:** Without it, the prover could generate valid per-bit
OR proofs for arbitrary bit commitments, then supply an independently sampled `r_main`
for a different value. The check enforces that the bit decomposition arithmetically
equals the main commitment, making forgery require breaking MSIS.

**CDS 1-of-2 OR proof (`_prove_bit`):**
```
For actual bit b, other = 1−b:
  T = [C_bit, (C_bit − e₀) mod q]  — adjusted targets

SIMULATE fake branch (index `other`):
  c_fake, z_fake ← random
  w_fake = A·z_fake − c_fake·T[other]  (mod q)

REAL announcement (index `b`):
  ρ ← short random; w_real = A·ρ  (mod q)

FIAT-SHAMIR on both announcements:
  c_total = SHA3(w[0] ‖ w[1] ‖ T[0] ‖ T[1] ‖ ctx)

SPLIT challenge:
  c_real = (c_total − c_fake) mod q
  z_real = ρ + c_real · r_bit  (mod q)

Verifier checks (c_0 + c_1) ≡ c_total without knowing which branch is real.
```

---

### 4.4 `fhe_voting.py` — Fully Homomorphic Encryption Tally

BFV scheme via TenSEAL — allows computing on ciphertexts without decrypting.

**`FHEAuthority` (holds secret key):**
```
ts.context(BFV,
  poly_modulus_degree = 16384,
  plain_modulus       = 786433,   # prime, ≡1 (mod 32768) for SIMD batching
)
→ generate Galois keys + relinearisation keys
→ serialise WITH secret key     → authority keeps this
→ serialise public-only context → broadcast to all voters
```

**`FHEVoter` (public context only, cannot decrypt):**
```
vote for candidate i → one_hot = [0, …, 1 at position i, …, 0]
ts.bfv_vector(pub_ctx, one_hot).serialize() → encrypted vote bytes
```

**`FHETally` (single-shard homomorphic accumulation):**
```
running_ct = None

for each encrypted vote:
    if running_ct is None: running_ct = enc_vote
    else:                  running_ct = running_ct + enc_vote   # BFV addition
                           # noise grows ~1 bit per addition

at finalize:
    authority.decrypt(running_ct) → [count₀, count₁, …, countₙ]
```

**`ShardedFHETally` (unlimited scale):**
```
shards = [FHETally()]

for each encrypted vote:
    if shards[-1].vote_count >= 3200:
        shards.append(FHETally())     # fresh context, fresh noise budget
    shards[-1].add_encrypted_vote(enc_bytes)

at finalize:
    combined = [0] * n_candidates
    for shard in shards:
        shard_counts = shard.finalize()      # one decryption per shard
        combined += shard_counts             # plain integer addition
    return combined
```

**Noise budget:**
- degree=16384 → q large enough for ~16,000 additions before corruption
- shard_size=3200 → 5× safety margin
- 10,000 voters → ceil(10000/3200) = 4 decryptions, not 10,000

---

### 4.5 `blockchain.py` — SHA3-256 PoW Chain

**Data structures:**
```
VoteRecord:
  voter_id_hash   — SHA3(voter_id)  (privacy: ID not stored directly)
  encrypted_vote  — hex FHE ciphertext
  zkp_commitment  — hex first 32 int64 elements of C_main
  zkp_proof_hash  — SHA3(full proof dict)
  signature       — ML-DSA-65(enc_vote_hex ‖ zkp_proof_hash)
  voter_sig_pk    — voter's ML-DSA-65 public key (hex)
  timestamp

Block:
  index, timestamp, prev_hash, votes[], difficulty
  merkle_root       — SHA3 Merkle tree of all VoteRecords
  nonce             — PoW result
  hash              — SHA3(header JSON)
  authority_signature — ML-DSA-65(hash ‖ merkle_root)
```

**Mining (`mine`):**
```
1. merkle_root = compute_merkle_root()
     leaves:   SHA3(0x00 ‖ vote_record_bytes)     ← RFC 6962 leaf prefix
     internal: SHA3(0x01 ‖ left_child ‖ right_child) ← RFC 6962 internal prefix
     (domain separation prevents second-preimage attacks on the tree)

2. nonce = 0
   while SHA3(header_with_nonce) does not start with "0"×difficulty:
       nonce++

3. sign(authority_sig_sk, block_hash ‖ merkle_root)
```

**Double-vote prevention:**
```
nullifier = SHA3(voter_id_hash ‖ election_id)
```
Including `election_id` is critical: a nullifier based only on `voter_id_hash`
would be identical across all elections, allowing cross-election replay attacks.

**`verify_chain` checks for every block including genesis:**
```
stored_hash == recomputed SHA3(header)?
hash starts with "0"×difficulty?
ML-DSA-65 signature valid?
prev_hash == predecessor's hash?
stored merkle_root == recomputed merkle_root from actual vote records?
  (last check prevents swapping vote records while keeping block hash intact)
```

---

### 4.6 `voter.py` — SQLite-Backed Registry

**`VoterRegistration` dataclass fields:**
```
voter_id          — UUID string
voter_id_hash     — SHA3(voter_id) — stored on-chain instead of voter_id
kem_pk            — ML-KEM-768 public key (bytes)
sig_pk            — ML-DSA-65  public key (bytes)
biometric_data    — dict from CancellableBiometric.enroll()
registered_at     — unix timestamp
is_active         — can this voter cast a ballot?
has_voted         — set True once valid vote accepted
bio_authenticated — set True after successful biometric auth in this session
bio_auth_time     — timestamp of last successful auth (for expiry check)
bio_fail_count    — consecutive failed attempts
bio_locked_until  — lockout expiry timestamp (or None)
```

**`VoterRegistry` — write-through in-memory cache backed by SQLite:**
```
_conn  = sqlite3.connect(db_path)    # ":memory:" default or file path
_cache = {}                          # dict[voter_id → VoterRegistration]

All READS  → _cache (O(1) dict lookup, no DB round-trip)
All WRITES → update _cache
           → _persist() → INSERT OR REPLACE INTO voters
           → _log()     → INSERT INTO audit_events
```

**SQLite schema:**
```sql
CREATE TABLE voters (
    voter_id         TEXT PRIMARY KEY,
    voter_id_hash    TEXT NOT NULL,
    kem_pk           TEXT NOT NULL,           -- hex
    sig_pk           TEXT NOT NULL,           -- hex
    biometric_data   TEXT NOT NULL,           -- JSON
    token_hash       TEXT NOT NULL DEFAULT '', -- UNIQUE constraint enforced in app
    registered_at    REAL NOT NULL,
    is_active        INTEGER NOT NULL DEFAULT 1,
    has_voted        INTEGER NOT NULL DEFAULT 0,
    bio_authenticated INTEGER NOT NULL DEFAULT 0,
    bio_auth_time    REAL,
    bio_fail_count   INTEGER NOT NULL DEFAULT 0,
    bio_locked_until REAL
);

CREATE TABLE audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL NOT NULL,
    voter_id_prefix TEXT NOT NULL,  -- first 16 hex chars of SHA3(voter_id)
    event           TEXT NOT NULL   -- "enrolled", "vote_recorded", etc.
);
```

**Session lifecycle:**
```
authenticate() passes
  → mark_authenticated(voter_id)
       bio_authenticated = True, bio_auth_time = now
       persisted to SQLite immediately

is_authenticated(voter_id)
  → bio_authenticated == True?
  → (now − bio_auth_time) < AUTH_SESSION_TIMEOUT (600 s)?
  → auto-expire and return False if timeout exceeded

receive_vote() accepted
  → mark_voted()
  → clear_authentication()    ← one-time use: token consumed

Lockout:
  record_failed_auth() → bio_fail_count++
  if count ≥ BIO_MAX_AUTH_ATTEMPTS (5):
      bio_locked_until = now + BIO_LOCKOUT_SECONDS (300)
  is_auth_locked() auto-clears expired locks on first check
```

---

### 4.7 `voting_system.py` — Election Orchestrator

**`ElectionAuthority`** owns all secret keys (KEM sk, DSA sk, FHE sk).

**`ElectionConfig`** (immutable):
```python
ElectionConfig(election_id="Election_2025", candidates=["Alice", "Bob", "Carol"])
```

**`public_params()`** — what the authority broadcasts (NO secrets):
```
election_id, candidates, num_candidates,
authority_kem_pk, authority_sig_pk,
fhe_public_context   ← BFV context without secret key
```

**`Voter`** client (holds only own secret keys):
```python
Voter(voter_id, public_params)
  → PQKeyPair()                      ← voter's own KEM + DSA keys
  → FHEVoter(fhe_public_context)     ← public context, cannot decrypt
  → LatticeZKP(num_candidates)       ← same deterministic A as authority
```

---

## 5. Full End-to-End Lifecycle

```
┌──────────────────────────────────────────┬──────────────────────────────────────────┐
│           VOTER CLIENT                   │          ELECTION AUTHORITY               │
├──────────────────────────────────────────┼──────────────────────────────────────────┤
│                                          │  PHASE 0 — SETUP                         │
│                                          │  PQKeyPair()                             │
│                                          │  FHEAuthority() → BFV context            │
│                                          │  ShardedFHETally()                       │
│                                          │  LatticeZKP() → derive matrix A          │
│                                          │  VotingBlockchain()                      │
│                                          │    → mine genesis block (PoW difficulty=4)│
│                                          │  VoterRegistry() → SQLite init           │
│                                          │  broadcast public_params                 │
│                                          │                                          │
│  PHASE 1 — REGISTRATION                  │                                          │
│  PQKeyPair() → voter KEM + DSA keys      │                                          │
│  fingerprint.BMP + user_token →──────────┤→ bio.enroll():                          │
│                                          │    Gabor+HOG → 8100-dim feature         │
│                                          │    BioHash(feature, token) → 2048 bits  │
│                                          │    pq_encrypt(kem_pk, template)         │
│                                          │  VoterRegistration created              │
│                                          │  token_hash uniqueness check            │
│                                          │  SQLite INSERT + audit_events           │
│                                          │                                          │
│  PHASE 2 — AUTHENTICATION                │                                          │
│  fingerprint.BMP + user_token →──────────┤→ authenticate():                        │
│                                          │    is_auth_locked()? → reject if so     │
│                                          │    bio.verify():                         │
│                                          │      SHA3(token) == stored token_hash?  │
│                                          │      pq_decrypt → stored_bits           │
│                                          │      BioHash(live_img, token) → query   │
│                                          │      Hamming sim = 1 − dist/2048        │
│                                          │      sim ≥ 0.818? → PASS               │
│                                          │    on PASS: mark_authenticated()        │
│                                          │             starts 600s timer           │
│                                          │    on FAIL: record_failed_auth()        │
│                                          │             lock after 5 attempts       │
│                                          │                                          │
│  PHASE 2b — VOTE CASTING                 │                                          │
│  candidate_idx = 2                       │                                          │
│  fhe.encrypt_vote(2)                     │                                          │
│    one_hot = [0, 0, 1, 0]               │                                          │
│    BFV encrypt → enc_bytes              │                                          │
│                                          │                                          │
│  zkp.prove_vote_range(2, voter_id, elec) │                                          │
│    bits = "10"  (2 bits for 4 cands)    │                                          │
│    bit0=1: r_bit0, C_bit0, OR_proof0   │                                          │
│    bit1=0: r_bit1, C_bit1, OR_proof1   │                                          │
│    r_main = 2¹·r_bit0 + 2⁰·r_bit1     │                                          │
│    C_main = A·r_main + 2·e₀            │                                          │
│    sigma_proof of knowledge of (2, r_main)│                                        │
│    consistency_hash = SHA3(C_main‖...)  │                                          │
│                                          │                                          │
│  zkp_hash = SHA3(proof_dict_JSON)       │                                          │
│  sig = ML-DSA-65.sign(enc_hex‖zkp_hash)│                                          │
│                                          │                                          │
│  ballot = {voter_id, enc_vote_hex,      │                                          │
│             zkp_proof, signature, …} →──┤→ PHASE 3 — VOTE RECEPTION               │
│                                          │  receive_vote():                         │
│                                          │    voter registered, active, !has_voted? │
│                                          │    is_authenticated()? within 600s?     │
│                                          │    pq_verify(voter_sig_pk, sig) ✓       │
│                                          │    zkp.verify_vote_proof():             │
│                                          │      voter_id_hash match?               │
│                                          │      sigma knowledge proof ✓            │
│                                          │      per-bit CDS OR proofs ✓            │
│                                          │      BIT-SUM: Σ2^i·C_bit_i = C_main ✓  │
│                                          │      consistency_hash ✓                 │
│                                          │    tally.add_encrypted_vote(enc_bytes)  │
│                                          │      → BFV addition (no decryption)     │
│                                          │      → new shard if count ≥ 3200        │
│                                          │    chain.add_vote(record):              │
│                                          │      nullifier = SHA3(id_hash‖election) │
│                                          │      check nullifier set → add          │
│                                          │      append to pending_votes            │
│                                          │    mark_voted()                         │
│                                          │    clear_authentication()  ← one-use    │
│                                          │                                          │
│                                          │  PHASE 4 — FINALIZATION                  │
│                                          │  finalize():                             │
│                                          │    chain.mine_pending_votes()           │
│                                          │      Merkle(RFC6962) → PoW → DSA sign  │
│                                          │    chain.verify_chain()                 │
│                                          │      hash chain ✓, PoW ✓, sig ✓        │
│                                          │      merkle_root ✓ per block            │
│                                          │    tally.finalize()                     │
│                                          │      decrypt shard 0 → [c0, c1, …]     │
│                                          │      decrypt shard 1 → [c0, c1, …]     │
│                                          │      sum all → final_counts             │
│                                          │    sweep_expired_sessions()             │
│                                          │    authenticated_not_voted() → warn     │
│                                          │    ML-DSA-65.sign(results_JSON)         │
│                                          │    → publish verifiable result package  │
└──────────────────────────────────────────┴──────────────────────────────────────────┘
```

---

## 6. Ballot Package Structure

A complete ballot dict submitted by the voter to the authority:

```json
{
  "voter_id":           "550e8400-e29b-41d4-a716-446655440000",
  "encrypted_vote_hex": "<hex-encoded BFV ciphertext of one-hot vector>",
  "zkp_proof": {
    "commitment":       [c0, c1, ..., c127],      // C_main ∈ Z_q^128
    "main_proof": {
      "w":  [w0, ..., w127],                       // Sigma announcement
      "c":  <integer challenge>,
      "z_r": [zr0, ..., zr255],                    // response vector
      "z_v": <integer response>
    },
    "bit_commitments":  [[c0,...,c127], ...],       // n_bits commitments
    "bit_proofs": [
      {
        "w": [[w0...], [w0...]],                   // two branch announcements
        "c": [c_branch0, c_branch1],               // split challenge
        "z": [[z0...], [z0...]]                    // two response vectors
      },
      ...
    ],
    "consistency_hash": "<hex SHA3-256>",
    "num_candidates":   4,
    "voter_id_hash":    "<hex SHA3-256 of voter_id>"
  },
  "zkp_commitment":     "<hex first 32 int64 elements of C_main>",
  "zkp_proof_hash":     "<hex SHA3-256 of zkp_proof JSON>",
  "signature":          "<hex ML-DSA-65 signature over enc_vote_hex ‖ zkp_proof_hash>"
}
```

---

## 7. Security Properties — Enforcement Mapping

| Property | Mechanism | File | Location |
|----------|-----------|------|----------|
| Vote secrecy | FHE: never decrypted during tally; ZKP: no value revealed | fhe_voting.py, zkp.py | ShardedFHETally, prove_vote_range |
| Vote validity (range proof) | ZKP: per-bit CDS OR proofs + bit-sum check | zkp.py | verify_vote_proof:422–488 |
| Double-vote prevention | Nullifier SHA3(voter_id_hash ‖ election_id) in set | blockchain.py | add_vote:278–286 |
| Cross-election replay prevention | election_id in nullifier | blockchain.py | add_vote:279 |
| Voter authenticity | ML-DSA-65 signature on every ballot | pq_crypto.py | pq_verify |
| Biometric forgery | 2048-bit BioHash Hamming distance ≥ 0.818 | cancellable_biometric.py | verify:301–304 |
| Brute-force lockout | 5-attempt lockout, 300 s duration | voter.py | record_failed_auth:275 |
| Session expiry | 600 s AUTH_SESSION_TIMEOUT, auto-expire | voter.py | is_authenticated:337–356 |
| Template confidentiality | ML-KEM-768 + AES-256-GCM encryption of raw template | cancellable_biometric.py | enroll:250 |
| Template unlinkability | QR-decomposed orthogonal projection per token | cancellable_biometric.py | _projection_matrix:186 |
| Token brute-force | SHAKE256 256-bit seed (not 32-bit) | cancellable_biometric.py | _token_to_seed:55 |
| Token uniqueness | UNIQUE token_hash check at registration | voter.py | register:238–244 |
| Chain tamper evidence | SHA3 hash chain + ML-DSA-65 per block | blockchain.py | verify_chain:321–366 |
| Merkle second-preimage | RFC 6962 domain-separated leaf/internal hashes | blockchain.py | compute_merkle_root:136–144 |
| Block signature forgery | ML-DSA-65 post-quantum signatures on every block | blockchain.py | Block.sign:189–193 |
| int64 arithmetic safety | Column-wise mod reduce in _matvec_mod | zkp.py | _matvec_mod:62–81 |
| Voter registry durability | SQLite write-through; append-only audit log | voter.py | _persist, _log |
| One-time auth token | clear_authentication() called after vote accepted | voting_system.py | receive_vote:312 |
| Quantum resistance | All key material from NIST FIPS 203/204 | pq_crypto.py | PQKeyPair |

---

## 8. Key Design Decisions — Rationale

**Why BFV with sharding instead of CKKS?**
BFV gives exact integer arithmetic — no rounding error at decryption. Vote counts
must be exact integers. Sharding removes the noise ceiling without switching
schemes. CKKS would introduce approximate values requiring rounding, which is
unnecessary complexity for discrete vote tallying.

**Why lattice ZKP instead of Schnorr/discrete-log proofs?**
Schnorr is broken by Shor's algorithm on a quantum computer. The Ajtai commitment
+ Fiat-Shamir construction is secure under the Module-SIS (MSIS) hardness
assumption, believed quantum-safe. This makes the entire protocol end-to-end
quantum-resistant.

**Why Gabor+HOG instead of ORB keypoints?**
ORB produces sparse, location-dependent keypoints — different crops of the same
finger give different keypoints, causing high FRR. Gabor filters capture the
global ridge orientation field across the entire image; HOG encodes it densely.
This gives stable, alignment-insensitive features achieving EER=2.61% at
threshold 0.818, vs. ~15%+ with ORB alone.

**Why derive r_main from bit randomnesses instead of sampling independently?**
If r_main is independently sampled, the verifier has no way to check that
C_main is arithmetically consistent with the bit commitments. An adversary could
generate valid per-bit proofs for bits that sum to one value, but supply a
C_main that commits to a different value. Deriving r_main = Σ 2^i·r_bit_i makes
C_main ≡ Σ 2^i·C_bit_i an algebraic identity, allowing the verifier to check it
with one linear combination.

**Why SQLite write-through cache instead of pure in-memory?**
Pure in-memory is fast but lost on crash. Pure DB is slow for read-heavy paths
(is_authenticated, is_auth_locked called on every vote). Write-through gives
O(1) cache reads with crash-safe persistence for all voter state.

**Why include election_id in the nullifier?**
A per-voter SHA3(voter_id_hash) nullifier is identical across all elections the
same voter participates in. An attacker who records a nullifier from election A
can present it to election B to block that voter (or in a replay scenario). The
election_id salt makes each election's nullifier space disjoint.

**Why QR-decompose the projection matrix?**
Random matrices without orthogonalisation can have correlated rows, causing
nearby projected values and reducing the discrimination power of the BioHash.
QR decomposition gives an orthonormal basis, maximising the angular spread of
projections and thus the Hamming distance between genuine and impostor templates.

---

## 9. Component Dependency Graph

```
voting_system.py
├── pq_crypto.py         (no internal deps)
├── cancellable_biometric.py
│   └── pq_crypto.py
├── fhe_voting.py        (no internal deps — wraps TenSEAL)
├── zkp.py
│   ├── pq_crypto.py
│   └── config.py
├── blockchain.py
│   └── pq_crypto.py
├── voter.py
│   ├── pq_crypto.py
│   └── config.py
└── config.py            (no internal deps — pure constants)

gui/app.py
└── voting_system.py     (full system via public API)

demo.py
└── voting_system.py

eth_integration/bridge.py
└── (web3 / eth-tester, no internal deps)
```

---

## 10. Performance at a Glance

Measured on Python 3.11, Windows 11, Intel x86_64, single CPU core.

| Operation | Time |
|-----------|------|
| BioHash extraction (Gabor+HOG, 2048-bit) | 7505 ms |
| ML-KEM-768 key generation | 1.29 ms |
| ML-KEM-768 encrypt | 1.90 ms |
| ML-KEM-768 decrypt | 0.19 ms |
| ML-DSA-65 sign | 1.89 ms |
| ML-DSA-65 verify | 0.56 ms |
| FHE vote encrypt (BFV, degree=16384) | 16.10 ms |
| ZKP generate | 4.07 ms |
| ZKP verify | 0.55 ms |
| Enrollment (end-to-end) | ~7509 ms |
| Authentication (end-to-end) | ~7506 ms |
| Vote casting (end-to-end) | ~22 ms |

**Scalability (ShardedFHETally, shard_size=3200):**

| N voters | Enrollment | Shards | Tally |
|----------|-----------|--------|-------|
| 100 | ~751 s | 1 | ~1 s |
| 1,000 | ~7,509 s | 1 | ~1 s |
| 5,000 | ~37,545 s | 2 | ~2 s |
| 10,000 | ~75,090 s | 4 | ~4 s |

BioHash dominates enrollment/auth (pure-Python Gabor+HOG pipeline).
All PQ crypto primitives are sub-2 ms.
In a production deployment, hardware-accelerated biometric processing
reduces BioHash to ~20–50 ms per voter.

---

*Last updated: 2026-03-14*
*Branch: claude/post-quantum-evoting-system-W2QQV*
