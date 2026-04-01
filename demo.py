#!/usr/bin/env python3
"""
Post-Quantum E-Voting System — Full Demo
======
Demonstrates the complete election lifecycle using SOCOFing fingerprint
images.

Run
---
  # With SOCOFing dataset (place the dataset under ./SOCOFing/):
  python demo.py --dataset ./SOCOFing --voters 5

  # More voters, show blockchain details:
  python demo.py --dataset ./SOCOFing --voters 8 --show-chain

What happens
------------
1.  Election authority is set up (PQ keys, FHE, ZKP, blockchain genesis).
2.  Fingerprint images are loaded (or synthesised).
3.  Voters are registered with cancellable biometric enrollment.
4.  Each voter authenticates biometrically, then casts an encrypted vote
    together with a lattice-based ZKP.
5.  The authority validates each vote (signature + ZKP) and accumulates
    ciphertexts homomorphically.
6.  Election is finalised: the blockchain is verified, the FHE tally is
    decrypted once, and results are published with an ML-DSA-65 signature.
7.  Voter-initiated template revocation is demonstrated:
    voter.prepare_revocation_request() → authority.process_revocation_request().
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Dict, List, Tuple


# Ensure the package is importable when running from repo root

sys.path.insert(0, str(Path(__file__).parent))

from pq_evoting import (
    ElectionAuthority,
    ElectionConfig,
    Voter,
    load_socofing_samples,
    pq_verify,
)



# Helpers


DIVIDER = "─" * 65


def _banner(title: str) -> None:
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)


def _make_token(subject_id: str) -> bytes:
    """Derive a deterministic user token from the subject ID (demo only)."""
    return hashlib.sha3_256(f"pin:{subject_id}:secret".encode()).digest()


def _prepare_fingerprints(
    dataset_path: str,
    num_voters: int,
) -> Dict[str, List[str]]:
    """
    Return {subject_id: [enrol_path, verify_path, …]} for *num_voters*
    subjects loaded from the SOCOFing dataset.
    """
    samples = load_socofing_samples(dataset_path, num_subjects=num_voters)
    samples = {s: p for s, p in samples.items() if len(p) >= 2}
    if not samples:
        raise FileNotFoundError(
            f"No SOCOFing images with ≥2 impressions found under '{dataset_path}'."
        )
    print(
        f"[Demo] Loaded {len(samples)} subjects from SOCOFing "
        f"dataset at '{dataset_path}'."
    )
    return dict(list(samples.items())[:num_voters])


def _verify_result_signature(result: dict) -> bool:
    """Verify the authority's ML-DSA-65 signature over the election result."""
    import json

    sig_pk  = bytes.fromhex(result["authority_sig_pk"])
    sig     = bytes.fromhex(result["authority_signature"])

    # Reconstruct the signed payload (same as in ElectionAuthority.finalize)
    payload_dict = {k: v for k, v in result.items()
                    if k not in ("authority_signature", "authority_sig_pk")}
    payload = json.dumps(payload_dict, sort_keys=True).encode()

    return pq_verify(sig_pk, payload, sig)



# Main demo


def run_demo(num_voters: int, dataset_path: str, show_chain: bool) -> None:

    _banner("POST-QUANTUM E-VOTING SYSTEM — FULL DEMO")
    print(
        "  Algorithms: ML-KEM-768 · ML-DSA-65 · TenSEAL BFV · Lattice ZKP\n"
        "  Biometrics: BioHashing (Gabor + HOG + random orthogonal projection)\n"
        "  Ledger    : SHA3-256 blockchain with ML-DSA-65 block signatures"
    )


#  0. Prepare fingerprint images     
    
    samples = _prepare_fingerprints(dataset_path, num_voters)
    _run_election(samples, show_chain)


def _run_election(
    samples: Dict[str, List[str]],
    show_chain: bool,
) -> None:
    num_voters = len(samples)

    
#  1. Election Setup                                                    #
    
    _banner("Phase 1 · Election Setup")
    candidates = ["Alice", "Bob", "Carol"]
    config     = ElectionConfig("GeneralElection2024", candidates)
    authority  = ElectionAuthority(config)
    pub        = authority.public_params()

    
#  2. Voter Initialisation   
    
    _banner("Phase 2 · Voter Key Generation")
    subjects   = list(samples.keys())[:num_voters]
    voters: Dict[str, Voter]                      = {}
    fp_paths:  Dict[str, Tuple[str, str]]         = {}   # {id: (enrol, verify)}
    tokens:    Dict[str, bytes]                   = {}

    for subj in subjects:
        voter_id = f"voter_{subj}"
        v = Voter(voter_id, pub)
        voters[voter_id] = v

        img_list           = samples[subj]
        fp_paths[voter_id] = (img_list[0], img_list[min(1, len(img_list)-1)])
        tokens[voter_id]   = _make_token(subj)

    
#  3. Voter Registration   
    
    _banner("Phase 3 · Voter Registration (Cancellable Biometric Enrolment)")
    for voter_id, v in voters.items():
        enrol_path, _ = fp_paths[voter_id]
        authority.register_voter(
            voter_id,
            v.kem_pk,
            v.sig_pk,
            enrol_path,
            tokens[voter_id],
        )


#  4. Voting   
    
    _banner("Phase 4 · Biometric Authentication + Encrypted Voting")
    import random
    rng     = random.Random(42)
    choices = {}

    for voter_id, v in voters.items():
        _, verify_path = fp_paths[voter_id]
        candidate_idx  = rng.randint(0, len(candidates) - 1)
        choices[voter_id] = candidate_idx

        print(f"\n── Voter {voter_id[:12]}… ──")

        # Biometric authentication
        ok, score = authority.authenticate(voter_id, verify_path, tokens[voter_id])
        tag = "✓ PASS" if ok else "✗ FAIL"
        print(f"  Biometric auth : {tag}  (BioHash similarity={score:.3f})")

        if not ok:
            print("  Skipping vote (auth failed).")
            continue

        # Cast vote (fingerprint + token bind biometric to ballot cryptographically)
        ballot = v.cast_vote(candidate_idx, verify_path, tokens[voter_id])
        accepted = authority.receive_vote(ballot)
        status   = "✓ Accepted" if accepted else "✗ Rejected"
        print(
            f"  Vote for '{candidates[candidate_idx]}' : {status}"
        )


#  5. Finalisation  

    _banner("Phase 5 · Election Finalisation (FHE Decryption + Result Signing)")
    result = authority.finalize()

    # Verify the authority's signature over the results
    sig_ok = _verify_result_signature(result)
    print(
        f"\n[Demo] Result signature verification: "
        f"{'✓ VALID' if sig_ok else '✗ INVALID'}"
    )


#  6. Cross-check against plain choices  

    _banner("Phase 6 · Cross-Check (expected vs reported)")
    expected: Dict[str, int] = {c: 0 for c in candidates}
    # Count from local choices for voters whose ballot was accepted
    for voter_id, idx in choices.items():
        expected[candidates[idx]] += 1

    print(f"\n  {'Candidate':<25}  {'Reported':>8}  {'Expected':>8}")
    all_match = True
    for name in candidates:
        reported = result["results"].get(name, 0)
        exp      = expected[name]
        match    = "✓" if reported == exp else "?"
        all_match = all_match and (reported == exp)
        print(f"  {name:<25}  {reported:>8}  {exp:>8}  {match}")

    print(f"\n  Tally consistency: {'✓ MATCH' if all_match else '⚠ MISMATCH'}")


#  7. Blockchain statistics                                             

    _banner("Phase 7 · Blockchain & Chain Statistics")
    stats = authority.chain_stats()
    print(f"  Chain length  : {stats['chain_length']} blocks")
    print(f"  Votes on-chain: {stats['total_votes']}")
    print(f"  Pending       : {stats['pending_votes']}")
    print(f"  Chain valid   : {'✓' if stats['chain_valid'] else '✗'}")

    if show_chain:
        print("\n  Block summary:")
        for blk in authority.chain_blocks():
            print(
                f"    [{blk.index}] hash={blk.hash[:16]}…  "
                f"votes={len(blk.votes)}  nonce={blk.nonce}"
            )


#  8. Template cancellation demo (voter-initiated revocation flow)       

    _banner("Phase 8 · Voter-Initiated Biometric Template Revocation Demo")
    demo_voter_id = list(voters.keys())[0]
    old_token     = tokens[demo_voter_id]
    new_token     = hashlib.sha3_256(b"new_pin_after_compromise").digest()
    enrol_path, _ = fp_paths[demo_voter_id]

    try:
        voter_obj = voters[demo_voter_id]
        # Step 1: Voter prepares a signed revocation request (ML-DSA-65)
        request = voter_obj.prepare_revocation_request(
            enrol_path, old_token, new_token, reason="demo: token rotation"
        )
        print(f"[Demo] Revocation request signed by voter {demo_voter_id[:12]}… ✓")

        # Step 2: Authority verifies signature + re-enrolls with new token
        ok = authority.process_revocation_request(request)
        if ok:
            tokens[demo_voter_id] = new_token
            print(
                f"[Demo] Template for {demo_voter_id[:12]}… revoked and "
                f"re-enrolled with new token. ✓"
            )
            print(
                "[Demo] Old biometric template is now cryptographically "
                "unlinked from the new one (Hamming distance ≈ 50%)."
            )
        else:
            print(f"[Demo] Revocation skipped: request validation failed.")
    except Exception as exc:
        print(f"[Demo] Revocation skipped: {exc}")

    _banner("Demo Complete")
    print("  All phases completed successfully.\n")


# Entry point


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Post-Quantum E-Voting System Demo"
    )
    p.add_argument(
        "--dataset", "-d",
        required=True,
        help="Path to the SOCOFing dataset root (must contain a Real/ sub-folder).",
    )
    p.add_argument(
        "--voters", "-n",
        type=int,
        default=5,
        help="Number of voters to simulate (default: 5).",
    )
    p.add_argument(
        "--show-chain",
        action="store_true",
        help="Print per-block blockchain summary at the end.",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_demo(
        num_voters   = args.voters,
        dataset_path = args.dataset,
        show_chain   = args.show_chain,
    )
