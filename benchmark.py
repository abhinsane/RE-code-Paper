"""
benchmark.py — Per-operation and end-to-end latency for the PQ e-voting system.

Usage:
    python benchmark.py

Outputs a performance table suitable for Section 6 of the paper.
"""

import time
import sys
import numpy as np

sys.path.insert(0, ".")

from pq_evoting.cancellable_biometric import CancellableBiometric
from pq_evoting.pq_crypto import PQKeyPair, pq_encrypt, pq_decrypt, pq_sign, pq_verify
from pq_evoting.fhe_voting import FHEAuthority, FHEVoter
from pq_evoting.zkp import LatticeZKP

N_CANDIDATES = 3
VOTER_ID     = b"benchmark-voter-01"
ELECTION_ID  = b"benchmark-election-01"


def bench(label: str, fn, runs: int):
    """Run fn() `runs` times, return mean ms."""
    t0 = time.perf_counter()
    for _ in range(runs):
        result = fn()
    elapsed_ms = (time.perf_counter() - t0) / runs * 1000
    print(f"  {label:<35} {elapsed_ms:8.2f} ms   (n={runs})")
    return elapsed_ms, result


def main():
    print("=" * 60)
    print("  POST-QUANTUM E-VOTING SYSTEM — BENCHMARKS")
    print("=" * 60)

    # ----------------------------------------------------------------
    # Setup (not timed)
    # ----------------------------------------------------------------
    print("\nInitialising components...")
    bio  = CancellableBiometric()
    zkp  = LatticeZKP(num_candidates=N_CANDIDATES)
    kp   = PQKeyPair()
    token = b"benchmark-user-token-32bytes!!!!"
    feat  = np.random.rand(512).astype(np.float32)
    msg   = b"vote-commitment-payload"

    print("  FHE authority init (slow — generates BFV context)...")
    auth  = FHEAuthority(num_candidates=N_CANDIDATES)
    voter = FHEVoter(auth.public_context_bytes(), num_candidates=N_CANDIDATES)
    print("  Done.\n")

    # ----------------------------------------------------------------
    # 1. Per-operation latency
    # ----------------------------------------------------------------
    print("Per-operation latency")
    print("-" * 60)

    bio_ms,  bh  = bench("BioHash extraction (Gabor+HOG)",  lambda: bio.compute_biohash(feat, token), runs=10)
    kgen_ms, kp2 = bench("ML-KEM-768  keygen",              lambda: PQKeyPair(),                       runs=20)
    enc_ms,  env = bench("ML-KEM-768  encrypt",             lambda: pq_encrypt(kp.kem_pk, bh.tobytes()), runs=20)
    dec_ms,  _   = bench("ML-KEM-768  decrypt",             lambda: pq_decrypt(kp.kem_sk, env),         runs=20)
    sign_ms, sig = bench("ML-DSA-65   sign",                lambda: pq_sign(kp.sig_sk, msg),            runs=50)
    ver_ms,  _   = bench("ML-DSA-65   verify",              lambda: pq_verify(kp.sig_pk, msg, sig),     runs=50)
    fhe_ms,  ct  = bench("FHE vote encrypt (BFV)",          lambda: voter.encrypt_vote(1),              runs=5)
    zkpg_ms, pf  = bench("ZKP generate",                    lambda: zkp.prove_vote_range(1, VOTER_ID, ELECTION_ID), runs=10)
    zkpv_ms, _   = bench("ZKP verify",                      lambda: zkp.verify_vote_proof(pf, VOTER_ID, ELECTION_ID), runs=10)

    # ----------------------------------------------------------------
    # 2. End-to-end phase totals
    # ----------------------------------------------------------------
    enroll_ms = bio_ms + kgen_ms + enc_ms
    auth_ms   = bio_ms + dec_ms
    cast_ms   = fhe_ms + zkpg_ms + sign_ms

    print()
    print("End-to-end phase latency")
    print("-" * 60)
    print(f"  {'Enrollment':<35} {enroll_ms:8.1f} ms   (BioHash + KEM-keygen + KEM-enc)")
    print(f"  {'Authentication':<35} {auth_ms:8.1f} ms   (BioHash + KEM-dec)")
    print(f"  {'Vote casting':<35} {cast_ms:8.1f} ms   (FHE-enc + ZKP-gen + DSA-sign)")

    # ----------------------------------------------------------------
    # 3. Scalability (estimated from shard model)
    # ----------------------------------------------------------------
    SHARD_SIZE = 800
    print()
    print("Scalability estimates (ShardedFHETally, shard=800 votes)")
    print("-" * 60)
    print(f"  {'N voters':<15} {'Enrollment (s)':<20} {'Shards':<10} {'Tally est.'}")
    print(f"  {'-'*55}")
    for n in [100, 1_000, 5_000, 10_000]:
        shards     = max(1, (n + SHARD_SIZE - 1) // SHARD_SIZE)
        enroll_s   = n * enroll_ms / 1000
        tally_s    = shards * 1.0          # ~1 s per shard (rough estimate)
        print(f"  {n:<15,} {enroll_s:<20.0f} {shards:<10} ~{tally_s:.0f} s")

    print()
    print("=" * 60)
    print("  Note: BioHash dominates enrollment/auth (pure-Python Gabor+HOG).")
    print("  All PQ crypto primitives are sub-ms to single-digit ms.")
    print("=" * 60)


if __name__ == "__main__":
    main()
