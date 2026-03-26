"""
Post-Quantum E-Voting System — Main Orchestrator
===============
Integrates all cryptographic components into a complete election lifecycle:

  Phase 0 – Setup
      The :class:`ElectionAuthority` generates its PQ key pair, sets up
      the FHE context (TenSEAL BFV), the lattice-based ZKP system, and
      mines the genesis block of the voting blockchain.

  Phase 1 – Voter Registration
      Each voter generates their own PQ key pair (:class:`Voter`).
      The authority enrolls their cancellable biometric template
      (BioHash of a SOCOFing fingerprint encrypted with ML-KEM-768).

  Phase 2 – Authentication & Voting
      Before casting a ballot the voter is authenticated biometrically.
      The voter:
        a) FHE-encrypts their choice as a one-hot BFV vector.
        b) Generates a lattice-based ZKP proving the choice is valid
           (in range) without revealing it.
        c) Signs the (ciphertext ‖ ZKP-hash) with their ML-DSA-65 key.
        d) Submits the signed ballot package to the authority.

  Phase 3 – Vote Reception & Validation
      The authority:
        a) Checks the voter is registered, active, and has not yet voted.
        b) Verifies the ML-DSA-65 signature.
        c) Verifies the ZKP.
        d) Adds the FHE ciphertext to the homomorphic tally (never decrypts).
        e) Records a :class:`VoteRecord` on the blockchain.
        f) Marks the voter as having voted.

  Phase 4 – Tallying & Result Publication
      After polls close the authority:
        a) Mines any remaining pending votes into a block.
        b) Verifies the full blockchain.
        c) Decrypts the FHE tally (one decryption for all votes combined).
        d) Signs the result set with ML-DSA-65.
        e) Returns a publicly verifiable result package.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Dict, List, Optional, Tuple

from .blockchain import VoteRecord, VotingBlockchain
from .cancellable_biometric import CancellableBiometric
from .config import BLOCKCHAIN_DIFFICULTY, MAX_CANDIDATES
from .fhe_voting import FHEAuthority, FHEVoter, FHETally, ShardedFHETally
from .pq_crypto import PQKeyPair, pq_sign, pq_verify, sha3_256
from .voter import VoterRegistration, VoterRegistry
from .zkp import LatticeZKP


# ---------------
# Election configuration
# ---------------

class ElectionConfig:
    """Immutable election configuration."""

    def __init__(self, election_id: str, candidates: List[str]) -> None:
        if len(candidates) < 2:
            raise ValueError("An election requires at least 2 candidates.")
        if len(candidates) > MAX_CANDIDATES:
            raise ValueError(
                f"Candidate list exceeds MAX_CANDIDATES limit ({MAX_CANDIDATES})."
            )
        self.election_id  = election_id
        self.election_id_bytes = election_id.encode()
        self.candidates  = list(candidates)
        self.num_candidates  = len(candidates)


# ---------------
# Election authority
# ---------------

class ElectionAuthority:
    """
    Manages the entire election lifecycle on the authority side.

    Holds ALL secret key material (FHE secret key, PQ secret keys).
    In a real deployment this entity would be a threshold multi-party
    committee; here it is a single trusted party for prototype purposes.
    """

    def __init__(self, config: ElectionConfig) -> None:
        self.config = config
        self._active  = True
        self._finalized  = False
        self._registration_open = True   # set to False when voting begins

        print("[Authority] Generating post-quantum key pair (ML-KEM-768 + ML-DSA-65) …")
        self._kp = PQKeyPair()

        print("[Authority] Setting up FHE context (TenSEAL BFV) …")
        self._fhe  = FHEAuthority(config.num_candidates)
        self._tally = ShardedFHETally(self._fhe)

        print("[Authority] Initialising lattice-based ZKP system …")
        # FIX: pass election_id_bytes so the public matrix A is election-specific,
        # preventing cross-election ZKP replay attacks.
        self._zkp   = LatticeZKP(
            config.num_candidates,
            election_id_bytes=config.election_id_bytes,
        )

        print("[Authority] Initialising blockchain …")
        self._chain    = VotingBlockchain(
            self._kp.sig_sk, self._kp.sig_pk,
            difficulty=BLOCKCHAIN_DIFFICULTY,
            election_id=config.election_id_bytes,
        )

        self._bio = CancellableBiometric()
        self._registry = VoterRegistry()
        # FIX: lock to prevent concurrent vote submissions for the same voter
        # from both passing the has_voted check before either marks voted.
        self._vote_lock = threading.Lock()

        print(
            f"[Authority] Election '{config.election_id}' ready.  "
            f"Candidates: {config.candidates}"
        )

    # ------
    # Public parameter broadcast
    # ------

    def public_params(self) -> dict:
        """
        Return all public parameters that voters need to encrypt their
        votes and generate ZKPs.  Contains NO secret material.
        """
        return {
            "election_id":        self.config.election_id,
            "candidates":         self.config.candidates,
            "num_candidates":     self.config.num_candidates,
            "authority_kem_pk":   self._kp.kem_pk,
            "authority_sig_pk":   self._kp.sig_pk,
            "fhe_public_context": self._fhe.public_context_bytes(),
        }

    # ------
    # Voter registration
    # ------

    def lock_registration(self) -> None:
        """
        Close the voter roll.  Must be called before voting begins.
        After this point register_voter() raises RuntimeError.
        """
        self._registration_open = False
        print("[Authority] Voter registration closed — electoral roll locked.")

    def register_voter(
        self,
        voter_id: str,
        voter_kem_pk: bytes,
        voter_sig_pk: bytes,
        fingerprint_path: str,
        user_token: bytes,
    ) -> VoterRegistration:
        """
        Enrol a new voter.

        Parameters
        ----------
        voter_id   : Unique identifier (UUID string recommended).
        voter_kem_pk : Voter's ML-KEM-768 public key.
        voter_sig_pk : Voter's ML-DSA-65  public key.
        fingerprint_path : Path to voter's SOCOFing fingerprint image.
        user_token         : Secret token (e.g. SHA3-256 of PIN) for
                           cancellable biometric.  The authority only
                           stores a hash of this token.
        """
        if not self._registration_open:
            raise RuntimeError(
                "Voter registration is closed — the electoral roll was locked "
                "when voting opened.  No new voters can be added."
            )
        print(f"[Authority] Enrolling voter {voter_id[:8]}… ")
        bio_data = self._bio.enroll(
            fingerprint_path, user_token, self._kp.kem_pk, self._kp.sig_sk
        )
        reg = VoterRegistration(
            voter_id=voter_id,
            kem_pk=voter_kem_pk,
            sig_pk=voter_sig_pk,
            biometric_data=bio_data,
        )
        if not self._registry.register(reg):
            raise ValueError(f"Voter {voter_id} is already registered.")
        print(f"[Authority]   → voter {voter_id[:8]}… enrolled. ✓")
        return reg

    # ------
    # Biometric authentication
    # ------

    def authenticate(
        self,
        voter_id: str,
        fingerprint_path: str,
        user_token: bytes,
    ) -> Tuple[bool, float]:
        """
        Biometrically authenticate a voter before letting them vote.

        Returns (ok, similarity_score).
        """
        reg = self._registry.get(voter_id)
        if reg is None or not reg.is_active:
            return False, 0.0
        if reg.has_voted:
            print(f"[Authority] Voter {voter_id[:8]}… already voted — rejected.")
            return False, 0.0

        # Brute-force lockout check
        if self._registry.is_auth_locked(voter_id):
            import time as _time
            # FIX: use monotonic clock to match voter.py lockout timestamps.
            remaining = int(reg.bio_locked_until - _time.monotonic()) if reg.bio_locked_until else 0
            print(
                f"[Authority] Voter {voter_id[:8]}… is locked out "
                f"({remaining}s remaining).  Too many failed attempts."
            )
            return False, 0.0

        ok, score, bio_commitment = self._bio.verify(
            fingerprint_path, user_token,
            self._kp.kem_sk, reg.biometric_data,
            authority_sig_pk=self._kp.sig_pk,
        )
        if ok:
            self._registry.reset_auth_attempts(voter_id)                    # clear failure counter
            self._registry.mark_authenticated(voter_id, bio_commitment)     # grant session + store binding
            print(f"[Authority] Biometric PASSED for {voter_id[:8]}… (score={score:.3f})")
        else:
            locked = self._registry.record_failed_auth(voter_id)
            if locked:
                print(
                    f"[Authority] Biometric FAILED for {voter_id[:8]}… "
                    f"(score={score:.3f}) — account LOCKED after too many failures."
                )
            else:
                rec  = self._registry.get(voter_id)
                from .config import BIO_MAX_AUTH_ATTEMPTS as _MAX
                left = max(0, _MAX - (rec.bio_fail_count if rec else 0))
                print(
                    f"[Authority] Biometric FAILED for {voter_id[:8]}… "
                    f"(score={score:.3f}, {left} attempt(s) remaining before lockout)"
                )
        return ok, score

    # ------
    # Vote reception
    # ------

    def receive_vote(self, submission: dict) -> bool:  # noqa: C901
        """
        Accept, validate, and record an incoming vote submission.

        Expected keys in *submission*
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        voter_id   : str
        encrypted_vote_hex   : str  (hex-encoded FHE ciphertext)
        zkp_proof  : dict (full ZKP proof)
        zkp_commitment : str  (hex)
        zkp_proof_hash : str  (hex)
        bio_commitment_hex : str  (hex, SHA3-256 of live BioHash at auth time)
        signature  : str  (hex, ML-DSA-65 over enc_vote ‖ zkp_hash ‖ bio_commitment)

        Returns True iff the vote was successfully recorded.
        """
        voter_id = submission.get("voter_id", "")

        # Hold the vote lock for the ENTIRE method so that two concurrent
        # submissions for the same voter cannot both pass eligibility/auth
        # before either reaches mark_voted, and cannot both add to the FHE
        # tally before the blockchain nullifier blocks the duplicate.
        with self._vote_lock:
            reg = self._registry.get(voter_id)

            # ---- Eligibility -------------------------------------------------
            if reg is None or not reg.is_active or reg.has_voted:
                print(f"[Authority] Vote rejected — voter ineligible: {voter_id[:8]}…")
                return False

            # ---- Biometric authentication gate --------------------------------
            # The voter MUST have passed biometric verification (via authenticate())
            # in this session AND within the AUTH_SESSION_TIMEOUT window before
            # their ballot is accepted.  is_authenticated() auto-expires stale
            # tokens so a voter who authenticated hours ago cannot still vote.
            if not self._registry.is_authenticated(voter_id):
                print(
                    f"[Authority] Vote NULLIFIED — biometric not verified or session "
                    f"expired: {voter_id[:8]}…"
                )
                return False

            # ---- Bio-commitment cross-check ----------------------------------
            # Retrieve the bio_commitment stored at authentication time and verify
            # it matches the one embedded in the submission.  This is the critical
            # link: a ballot whose bio_commitment doesn't match what the authority
            # observed during biometric auth cannot pass — the two are bound.
            stored_bio_commitment = self._registry.get_bio_commitment(voter_id)
            submitted_bio_commitment_hex = submission.get("bio_commitment_hex", "")
            if not submitted_bio_commitment_hex:
                print(f"[Authority] Vote rejected — missing bio_commitment: {voter_id[:8]}…")
                return False
            if bytes.fromhex(submitted_bio_commitment_hex) != stored_bio_commitment:
                print(f"[Authority] Vote rejected — bio_commitment mismatch: {voter_id[:8]}…")
                return False
            bio_commitment = stored_bio_commitment

            # ---- ML-DSA-65 signature -----------------------------------------
            # Signature now covers enc_hex | zkp_hash | bio_commitment_hex so the
            # biometric binding is authenticated under the voter's signing key.
            sig_payload = (
                submission["encrypted_vote_hex"] + "|"
                + submission["zkp_proof_hash"] + "|"
                + submitted_bio_commitment_hex
            ).encode()
            if not pq_verify(
                reg.sig_pk,
                sig_payload,
                bytes.fromhex(submission["signature"]),
            ):
                print(f"[Authority] Vote rejected — invalid signature: {voter_id[:8]}…")
                return False

            # ---- ZKP verification (bio_commitment in Fiat-Shamir ctx) --------
            if not self._zkp.verify_vote_proof(
                submission["zkp_proof"],
                voter_id.encode(),
                self.config.election_id_bytes,
                bio_commitment=bio_commitment,
            ):
                print(f"[Authority] Vote rejected — ZKP invalid: {voter_id[:8]}…")
                return False

            # ---- FHE tally ---------------------------------------------------
            enc_bytes = bytes.fromhex(submission["encrypted_vote_hex"])
            self._tally.add_encrypted_vote(enc_bytes)

            # ---- Blockchain --------------------------------------------------
            record = VoteRecord(
                voter_id_hash=reg.voter_id_hash,
                encrypted_vote=submission["encrypted_vote_hex"],
                zkp_commitment=submission["zkp_commitment"],
                zkp_proof_hash=submission["zkp_proof_hash"],
                signature=submission["signature"],
                voter_sig_pk=reg.sig_pk.hex(),
                bio_commitment=submitted_bio_commitment_hex,
            )
            if not self._chain.add_vote(record):
                print(f"[Authority] Duplicate nullifier — vote rejected: {voter_id[:8]}…")
                return False

            # ---- Mark voter --------------------------------------------------
            self._registry.mark_voted(voter_id)
            self._registry.clear_authentication(voter_id)   # one-time use auth token
            print(f"[Authority] Vote accepted and recorded. Voter: {voter_id[:8]}…")
            return True

    # ------
    # Election finalisation
    # ------

    def finalize(self) -> dict:
        """
        Close the election and compute final results.

        Steps
        -----
        1. Mine any pending votes into a final block.
        2. Verify the full blockchain.
        3. Decrypt the FHE tally (single decryption operation).
        4. Sign the results with ML-DSA-65.
        5. Return a fully verifiable result package.
        """
        if self._finalized:
            raise RuntimeError("Election has already been finalised.")

        print("\n[Authority] ─── Finalising election ───")

        # Mine remaining votes
        blk = self._chain.mine_pending_votes()
        if blk:
            print(
                f"[Authority] Mined block #{blk.index} "
                f"({len(blk.votes)} votes)"
            )

        # Verify chain
        chain_ok = self._chain.verify_chain()
        print(
            f"[Authority] Blockchain integrity: "
            f"{'VALID ✓' if chain_ok else 'INVALID ✗'}"
        )

        # Decrypt FHE tally
        tally = self._tally.finalize()
        counts = tally["per_candidate"]
        total = tally["total_votes"]

        # Build results dict
        results_by_name = {
            self.config.candidates[i]: counts[i]
            for i in range(self.config.num_candidates)
        }
        winner_idx  = max(counts, key=lambda k: counts[k])
        winner_name = self.config.candidates[winner_idx]

        # Force-expire stale auth tokens that were never checked via
        # is_authenticated() (e.g. voter authenticated then abandoned the session).
        expired = self._registry.sweep_expired_sessions()
        if expired:
            print(f"[Authority] Swept {expired} expired auth session(s).")

        # Cross-check: any voter still holding bio_authenticated=True at
        # finalization time never had their vote accepted — report them.
        nullified = self._registry.authenticated_not_voted()
        if nullified:
            print(
                f"[Authority] WARNING: {len(nullified)} voter(s) passed biometric "
                f"but no vote was recorded — auth tokens cleared: "
                + ", ".join(v[:8] + "…" for v in nullified)
            )
        for vid in nullified:
            self._registry.clear_authentication(vid)

        result = {
            "election_id":  self.config.election_id,
            "candidates":  self.config.candidates,
            "results":  results_by_name,
            "total_votes":  total,
            "winner":  winner_name,
            "blockchain_ok": chain_ok,
            "chain_length": len(self._chain.chain),
            "nullified_count": len(nullified),
            "timestamp":   time.time(),
        }

        # Sign results
        result_bytes = json.dumps(result, sort_keys=True).encode()
        sig          = pq_sign(self._kp.sig_sk, result_bytes)
        result["authority_signature"] = sig.hex()
        result["authority_sig_pk"]    = self._kp.sig_pk.hex()

        self._finalized = True
        self._active    = False
        self._fhe.seal()   # unlock audit-only decrypt_single_vote after polls close

        # Print summary
        print("\n[Authority] ══════ ELECTION RESULTS ══════")
        for name, cnt in results_by_name.items():
            pct = (cnt / total * 100) if total else 0
            print(f"  {name:<25} {cnt:>4} votes  ({pct:.1f} %)")
        print(f"\n  Winner  : {winner_name}")
        print(f"  Total   : {total}")
        print(f"  Signed with ML-DSA-65 ✓")

        return result

    # ------
    # Public accessors (avoid GUI/tests touching private attributes)
    # ------

    @property
    def authority_sig_pk(self) -> bytes:
        """ML-DSA-65 public key of the authority (for signature verification)."""
        return self._kp.sig_pk

    @property
    def authority_kem_pk(self) -> bytes:
        """ML-KEM-768 public key of the authority (safe to share publicly)."""
        return self._kp.kem_pk

    def get_voter_reg(self, voter_id: str):
        """Return the VoterRegistration for voter_id, or None if not found."""
        return self._registry.get(voter_id)

    def chain_blocks(self) -> list:
        """Return a snapshot of the mined block list (read-only view)."""
        return list(self._chain.chain)

    def cancel_voter_biometric(
        self,
        voter_id: str,
        fingerprint_path: str,
        old_token: bytes,
        new_token: bytes,
        reason: str = "",
    ) -> bool:
        """
        Revoke a voter's biometric template and re-enrol with a new token.

        Must only be called by the authority (holds the KEM secret key needed
        to decrypt the stored template).  External callers must never receive
        raw access to the KEM secret key — use this method instead.

        *reason* is logged to the audit trail.  Callers should always supply
        a human-readable justification (e.g. "lost token", "device stolen").

        Returns True on success, False if the voter is not found.
        Raises ValueError if old-token verification fails.
        """
        reg = self._registry.get(voter_id)
        if reg is None:
            return False
        new_template = self._bio.cancel_and_reenroll(
            fingerprint_path,
            old_token,
            new_token,
            self._kp.kem_pk,
            self._kp.kem_sk,
            reg.biometric_data,
            authority_sig_sk=self._kp.sig_sk,
            authority_sig_pk=self._kp.sig_pk,
        )
        # Use registry method so the token_hash uniqueness column is updated
        # and the cancellation is written to the audit log with the reason.
        self._registry.update_biometric_data(voter_id, new_template, reason=reason)
        return True

    def process_revocation_request(self, request: dict) -> bool:
        """
        Accept and execute a voter-signed biometric revocation request.

        Steps
        -----
        1. Look up the voter — must be registered and active.
        2. Verify the ML-DSA-65 signature on the request payload; this
           proves the request originated from the holder of the voter's
           signing key, preventing forged revocation by a third party.
        3. Delegate to :meth:`cancel_voter_biometric`, which re-verifies
           the live fingerprint against the old token before re-enrolling
           with the new token (so physical possession of the finger is
           still required — a leaked token alone is not enough).

        Returns True on success, False on signature failure or unknown voter.
        Raises ValueError if the old-token biometric verification fails
        (propagated from :meth:`cancel_voter_biometric`).
        """
        voter_id = request.get("voter_id", "")
        reg = self._registry.get(voter_id)
        if reg is None or not reg.is_active:
            print(f"[Authority] Revocation rejected — voter not found or inactive: {voter_id[:8]}…")
            return False

        sig_input = (
            voter_id
            + request.get("new_token_hash", "")
            + request.get("reason", "")
            + request.get("ts", "")
        ).encode()
        if not pq_verify(reg.sig_pk, sig_input, bytes.fromhex(request["signature"])):
            print(f"[Authority] Revocation rejected — invalid signature: {voter_id[:8]}…")
            return False

        old_token = bytes.fromhex(request["old_token"])
        new_token = bytes.fromhex(request["new_token"])
        reason    = f"voter_requested: {request.get('reason', '')}"[:200]
        print(f"[Authority] Processing revocation request for voter {voter_id[:8]}…")
        return self.cancel_voter_biometric(
            voter_id,
            request["fingerprint_path"],
            old_token,
            new_token,
            reason=reason,
        )

    # ------
    # Blockchain statistics
    # ------

    def chain_stats(self) -> dict:
        return self._chain.stats()


# ---------------
# Voter client
# ---------------

class Voter:
    """
    Voter client — handles key generation, vote encryption, ZKP, and signing.

    The voter holds their own ML-KEM + ML-DSA secret keys locally;
    these are never transmitted to the authority.
    """

    def __init__(self, voter_id: str, public_params: dict) -> None:
        self.voter_id  = voter_id
        self._id_bytes  = voter_id.encode()
        self._params  = public_params

        print(f"[Voter {voter_id[:8]}…] Generating PQ key pair …")
        self._kp  = PQKeyPair()

        self._fhe = FHEVoter(
            public_params["fhe_public_context"],
            public_params["num_candidates"],
        )
        # FIX: bind the ZKP public matrix to this election's ID so proofs
        # generated for one election cannot be replayed in another.
        self._zkp = LatticeZKP(
            public_params["num_candidates"],
            election_id_bytes=public_params["election_id"].encode(),
        )
        # Used by cast_vote() to compute bio_commitment from fingerprint+token
        # without needing the authority's KEM secret key.
        self._bio = CancellableBiometric()
        print(f"[Voter {voter_id[:8]}…] Ready.")

    # ------
    # Public key accessors (for registration)
    # ------

    @property
    def kem_pk(self) -> bytes:
        return self._kp.kem_pk

    @property
    def sig_pk(self) -> bytes:
        return self._kp.sig_pk

    # ------
    # Ballot casting
    # ------

    def cast_vote(
        self,
        candidate_idx: int,
        fingerprint_path: str,
        user_token: bytes,
    ) -> dict:
        """
        Prepare a fully encrypted, ZK-proved, signed ballot package with
        cryptographic biometric binding.

        Steps
        -----
        1. Compute bio_commitment = SHA3-256(BioHash(fingerprint, token)).
           This value is independently computable by the voter and binds the
           specific biometric session to the ballot without leaking raw data.
        2. FHE-encrypt the vote as a one-hot BFV vector.
        3. Generate a lattice-based ZKP proving the choice is in range,
           with bio_commitment mixed into the Fiat-Shamir context.
        4. Sign (FHE_ct_hex ‖ zkp_hash ‖ bio_commitment_hex) with ML-DSA-65.

        The authority verifies that bio_commitment matches the value stored
        during authentication, closing the loop of biometric-ballot binding.

        Returns a dict ready to pass to :meth:`ElectionAuthority.receive_vote`.
        """
        election_id = self._params["election_id"].encode()

        # ---- Step 1: Biometric commitment ------------------------------
        bio_commitment  = self._bio.compute_bio_commitment(fingerprint_path, user_token)
        bio_commitment_hex = bio_commitment.hex()
        print(f"[Voter {self.voter_id[:8]}…] Bio-commitment derived from live BioHash.")

        # ---- Step 2: FHE encryption ------------------------------------
        enc_bytes = self._fhe.encrypt_vote(candidate_idx)
        enc_hex   = enc_bytes.hex()
        print(f"[Voter {self.voter_id[:8]}…] Vote FHE-encrypted (BFV one-hot).")

        # ---- Step 3: Lattice ZKP (bio_commitment in Fiat-Shamir ctx) ---
        zkp_proof      = self._zkp.prove_vote_range(
            candidate_idx, self._id_bytes, election_id,
            bio_commitment=bio_commitment,
        )
        zkp_commitment = bytes(
            self._zkp.commitment_bytes(zkp_proof)
        ).hex()
        zkp_proof_hash = sha3_256(
            json.dumps(zkp_proof, sort_keys=True).encode()
        ).hex()
        print(f"[Voter {self.voter_id[:8]}…] Lattice ZKP generated (bio-bound).")

        # ---- Step 4: ML-DSA-65 signature --------------------------------
        # Signature covers enc_hex | zkp_hash | bio_commitment_hex so any
        # tampering with the biometric binding is detected during verification.
        sig_payload = (enc_hex + "|" + zkp_proof_hash + "|" + bio_commitment_hex).encode()
        signature   = pq_sign(self._kp.sig_sk, sig_payload)
        print(f"[Voter {self.voter_id[:8]}…] Ballot signed with ML-DSA-65 (bio-bound).")

        return {
            "voter_id":   self.voter_id,
            "encrypted_vote_hex":  enc_hex,
            "zkp_proof":   zkp_proof,
            "zkp_commitment":   zkp_commitment,
            "zkp_proof_hash":   zkp_proof_hash,
            "bio_commitment_hex":  bio_commitment_hex,
            "signature":  signature.hex(),
        }

    def prepare_revocation_request(
        self,
        fingerprint_path: str,
        old_token: bytes,
        new_token: bytes,
        reason: str = "",
    ) -> dict:
        """
        Build a signed revocation request to submit to the authority.

        The voter signs the request payload with their ML-DSA-65 key so the
        authority can verify the request came from the legitimate key-holder
        before executing the template cancellation.

        The old and new tokens are included in plaintext; in a real deployment
        this request would be sent over an ML-KEM-established encrypted channel.

        Returns a dict to pass to :meth:`ElectionAuthority.process_revocation_request`.
        """
        ts = str(time.time())
        new_token_hash = sha3_256(new_token).hex()
        sig_input = (self.voter_id + new_token_hash + reason + ts).encode()
        sig = pq_sign(self._kp.sig_sk, sig_input)
        print(f"[Voter {self.voter_id[:8]}…] Revocation request signed with ML-DSA-65.")
        return {
            "voter_id":         self.voter_id,
            "fingerprint_path": fingerprint_path,
            "old_token":        old_token.hex(),
            "new_token":        new_token.hex(),
            "new_token_hash":   new_token_hash,
            "reason":           reason,
            "ts":               ts,
            "signature":        sig.hex(),
        }
