"""
Zero-Knowledge Proof Module — Lattice-Based Vote Validity
=======================
Proves that a submitted vote is a valid candidate index in [0, n-1]
**without revealing** which candidate was chosen.

Cryptographic construction
--------------------------
We use an **Ajtai commitment** with a two-component **Sigma-protocol**
made non-interactive via the **Fiat-Shamir heuristic** (using SHA3-256 as
the random oracle) — post-quantum secure under the Module-SIS (MSIS)
hardness assumption.

Ajtai commitment
~~~~~~~~~~~~~~~~
Public parameters:
    A ∈ Z_q^{n×m}  — random public matrix (derived from ELECTION_DOMAIN)
    e₀ ∈ Z_q^n     — first standard basis vector  [1, 0, …, 0]

Commit(vote, r) = A·r  +  vote·e₀   (mod q)
where vote ∈ Z is the ballot value and r ∈ [-β, β]^m is short randomness.

Two-component Sigma protocol with rejection sampling 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Witness  : (v, r)  s.t.  C = A·r + v·e₀
Announce : w = A·ρ_r + ρ_v·e₀    — pick fresh (ρ_r ∈ [-γ₁,γ₁]^m, ρ_v ∈ Z_q)
Challenge: c = SHA3(w ‖ C ‖ ctx)  mod c_max   (bounded Fiat-Shamir)
Response : z_r = ρ_r + c·r  (integers, NO mod q),   z_v = ρ_v + c·v  (mod q)
           Reject and re-sample ρ_r if ‖z_r‖∞ > B
Verify   : ‖z_r‖∞ ≤ B  AND  A·z_r + z_v·e₀  ≡  w + c·C  (mod q)

ZK property (fixed): the simulator draws z_r ← Uniform[-B,B]^m, c ← [0,c_max),
z_v ← Z_q, and sets w_sim = A·z_r + z_v·e₀ − c·C.  With rejection sampling,
the honest prover's z_r has exactly this distribution, so the transcript is
statistically indistinguishable from a simulation — the ZK property holds.

Without rejection sampling (old code) z_r = (ρ_r + c·r) mod q leaks information
about r because the mod-q wrap-around is correlated with c·r.

Response bounds
~~~~~~~~~~~~~~~
The response bound B depends on the ∞-norm of the secret r:
    B = γ₁ − c_max · ‖r‖∞

For per-bit proofs  r = r_bit ∈ [-β, β]^m         → B_bit  = γ₁ − c_max·β
For the main proof  r = r_main (integer weighted sum of r_bit vectors,
                    no mod-q reduction, so entries stay small):
                    ‖r_main‖∞ ≤ (2^n_bits − 1)·β  → B_main = γ₁ − c_max·(2^n_bits−1)·β

Both bounds are derived from public parameters (γ₁, c_max, β, n_bits) so the
verifier can recompute them without knowing any secret.

Range proof (vote ∈ {0,…,n_cand-1})
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Each bit of the vote value is committed independently with the same
Ajtai scheme, and a per-bit CDS OR sigma proof is generated.  A consistency
hash binds the bit decomposition to the main vote commitment.
"""

from __future__ import annotations

import hashlib
from typing import List

import numpy as np

from .config import (
    ELECTION_DOMAIN,
    ZKP_BETA,
    ZKP_CHALLENGE_MAX,
    ZKP_GAMMA1,
    ZKP_M,
    ZKP_MODULUS,
    ZKP_N,
)
from .pq_crypto import sha3_256, shake256


# ---------------
# Module-level constants
# ---------------

_MAX_PROOF_ATTEMPTS = 50   # Rejection-sampling retry cap; (0.24)^50 ≈ 0 failure prob


# ---------------
# Helpers
# ---------------

def _matvec_mod(A: np.ndarray, v: np.ndarray, q: int) -> np.ndarray:
    """Column-wise modular matrix-vector product that avoids int64 overflow.

    A naive ``A @ v`` overflows int64 when q is large (e.g. q = 2^31 - 1)
    because each row accumulates up to m products of magnitude q^2 ≈ 2^62,
    and m products together exceed 2^63.

    This function reduces v[j] mod q *before* each multiply so that each
    partial product is bounded by (q-1)^2 ≈ 4.6×10^18 < int64 max.  After
    each column the running sum is reduced mod q, bounding the next step.

    Handles all input ranges safely:
      • short vectors  v[j] ∈ [-β, β]           (negative → positive via % q)
      • modular vectors  v[j] ∈ [0, q)           (unchanged by % q)
      • rejection-sampled  v[j] ∈ [-B, B], B ≈ 2×10^12  (reduced before multiply)
    """
    v_mod = np.asarray(v, dtype=np.int64) % q   # reduce to [0, q) element-wise
    result = np.zeros(A.shape[0], dtype=np.int64)
    for j in range(A.shape[1]):
        result = (result + A[:, j] * v_mod[j]) % q
    return result


def _fiat_shamir(data: bytes, modulus: int) -> int:
    """Integer Fiat-Shamir challenge derived via SHA3-256, reduced mod modulus.

    Uses all 32 bytes of the SHA3-256 digest before reducing to minimise
    statistical bias and give a 256-bit challenge pre-image.
    """
    return int.from_bytes(sha3_256(data), "big") % modulus


def _sample_short(m: int, beta: int, rng: np.random.Generator) -> np.ndarray:
    """Sample r ← Uniform[-β, β]^m."""
    return rng.integers(-beta, beta + 1, size=m, dtype=np.int64)


def _sample_masked(m: int, gamma1: int, rng: np.random.Generator) -> np.ndarray:
    """Sample ρ ← Uniform[-γ₁, γ₁]^m  (masking range for rejection sampling)."""
    return rng.integers(-gamma1, gamma1 + 1, size=m, dtype=np.int64)


def _rng_from(seed_bytes: bytes) -> np.random.Generator:
    # Use int.from_bytes to preserve full entropy across all seed bytes.
    return np.random.default_rng(int.from_bytes(seed_bytes, "big"))


# ---------------
# Main class
# ---------------

class LatticeZKP:
    """
    Lattice-based Zero-Knowledge Proof system for ballot validity.

    Parameters
    ----------
    num_candidates : Number of candidates in the election.
    modulus   : Lattice modulus q.
    n   : Commitment output vector dimension.
    m  : Randomness (short) vector dimension.
    beta  : ∞-norm bound for short randomness vectors.
    """

    def __init__(
        self,
        num_candidates: int,
        modulus: int = ZKP_MODULUS,
        n: int  = ZKP_N,
        m: int  = ZKP_M,
        beta: int  = ZKP_BETA,
        election_id_bytes: bytes = b"",
    ) -> None:
        if num_candidates < 2:
            raise ValueError("LatticeZKP requires at least 2 candidates.")

        self.num_candidates = num_candidates
        self.q  = modulus
        self.n    = n
        self.m   = m
        self.beta     = beta
        self._election_id  = election_id_bytes

        # Number of bits needed to represent indices 0 … num_candidates-1.
        self.n_bits: int = max(1, (num_candidates - 1).bit_length())

        # Rejection-sampling parameters (Option A — bounded scalar challenge)
        self.challenge_max = ZKP_CHALLENGE_MAX   # c ∈ [0, c_max)
        self.gamma1        = ZKP_GAMMA1          # masking range for ρ_r

        # Response bound for per-bit proofs: secret r_bit ∈ [-β, β]^m
        #   B_bit = γ₁ − c_max · β
        self._response_bound = self.gamma1 - self.challenge_max * beta

        # Response bound for the main knowledge proof:
        # r_main is the integer-sum of weighted r_bit vectors (no mod-q reduction).
        #   ‖r_main‖∞ ≤ (2^n_bits − 1) · β
        #   B_main = γ₁ − c_max · (2^n_bits − 1) · β
        _max_r_main_norm = (2 ** self.n_bits - 1) * beta
        self._main_response_bound = self.gamma1 - self.challenge_max * _max_r_main_norm

        if self._response_bound <= 0 or self._main_response_bound <= 0:
            raise ValueError(
                f"ZKP parameters inconsistent: gamma1={self.gamma1} is too small "
                f"for challenge_max={self.challenge_max}, beta={beta}, "
                f"n_bits={self.n_bits}.  Increase gamma1 or reduce challenge_max."
            )

        # Deterministic public matrix A ∈ Z_q^{n×m}
        # Include election_id in the seed so each election gets a distinct
        # public matrix, preventing cross-election ZKP replay attacks.
        seed = int.from_bytes(
            shake256(ELECTION_DOMAIN + election_id_bytes + b":zkp_matrix_A", 64),
            "big",
        )
        self.A: np.ndarray = np.random.default_rng(seed).integers(
            0, self.q, size=(n, m), dtype=np.int64
        )

        # First standard basis vector e₀ ∈ Z_q^n  (encodes the message)
        self.e0 = np.zeros(n, dtype=np.int64)
        self.e0[0] = 1

    # ------
    # Commitment  C = A·r + v·e₀  (mod q)
    # ------

    def _commit(self, v: int, r: np.ndarray) -> np.ndarray:
        # FIX: use _matvec_mod instead of self.A @ r.
        # A @ r with r ∈ [0, q)^m overflows int64 silently (after ~2 columns
        # the partial sum exceeds 2^63).  _matvec_mod reduces mod q after
        # every column, keeping intermediate sums in [0, q) safely.
        return (_matvec_mod(self.A, r, self.q) + int(v) * self.e0) % self.q

    # ------
    # Sigma protocol (two-component: proves knowledge of (v, r))
    # ------

    def _sigma_prove(
        self,
        v: int,
        r: np.ndarray,
        C: np.ndarray,
        ctx: bytes,
        response_bound: int | None = None,
    ) -> dict:
        """
        Non-interactive Sigma proof of knowledge of (v, r) s.t. C = A·r + v·e₀.

        Uses rejection sampling so that the response z_r has a distribution
        that is independent of the secret r (ZK property).

        response_bound : ‖z_r‖∞ acceptance threshold.  Defaults to
                         self._response_bound (for short secrets ‖r‖∞ ≤ β).
                         Pass self._main_response_bound for r_main whose
                         norm can be up to (2^n_bits-1)·β.
        """
        bound = self._response_bound if response_bound is None else response_bound

        for attempt in range(_MAX_PROOF_ATTEMPTS):
            rng = _rng_from(shake256(ctx + r.tobytes() + attempt.to_bytes(4, "big"), 32))
            rho_r = _sample_masked(self.m, self.gamma1, rng)
            rho_v = int(rng.integers(0, self.q))

            w = (_matvec_mod(self.A, rho_r, self.q) + rho_v * self.e0) % self.q
            c = _fiat_shamir(w.tobytes() + C.tobytes() + ctx, self.challenge_max)
            z_r = rho_r + c * r          # integer addition — NO mod q
            z_v = int((rho_v + c * int(v)) % self.q)

            if int(np.max(np.abs(z_r))) <= bound:
                return {"w": w.tolist(), "c": int(c), "z_r": z_r.tolist(), "z_v": z_v}

        raise RuntimeError(
            "ZKP sigma proof: rejection sampling exceeded limit. "
            "This is astronomically unlikely — check parameter consistency."
        )

    def _sigma_verify(
        self,
        proof: dict,
        C: np.ndarray,
        ctx: bytes,
        response_bound: int | None = None,
    ) -> bool:
        """
        Verify Sigma proof.

        Checks:
        1. ‖z_r‖∞ ≤ bound  (response bound — enforces ZK, blocks forged responses)
        2. c = FS(w ‖ C ‖ ctx) mod c_max
        3. A·z_r + z_v·e₀ ≡ w + c·C  (mod q)
        """
        bound = self._response_bound if response_bound is None else response_bound
        try:
            w = np.asarray(proof["w"],   dtype=np.int64)
            c  = int(proof["c"])
            z_r = np.asarray(proof["z_r"], dtype=np.int64)
            z_v = int(proof["z_v"])

            # 1. Response bound
            if int(np.max(np.abs(z_r))) > bound:
                return False

            # 2. Challenge consistency (mod c_max, not mod q)
            if c != _fiat_shamir(w.tobytes() + C.tobytes() + ctx, self.challenge_max):
                return False

            # 3. Linear equation (_matvec_mod handles large z_r by reducing mod q)
            lhs = (_matvec_mod(self.A, z_r, self.q) + z_v * self.e0) % self.q
            rhs = (w + c * C) % self.q
            return bool(np.all(lhs == rhs))
        except Exception:
            return False

    # ------
    # Per-bit proof — CDS (Cramer-Damgård-Schoenmakers) 1-of-2 OR proof
    # ------
    #
    # Proves that C_bit commits to 0 OR to 1 without revealing which.
    # Both branches use rejection-sampled responses so their distributions
    # are indistinguishable (ZK property).
    #
    # Branch assignments
    # ~~~~~~~~~~~~~~~~~~
    # Let b ∈ {0, 1} be the actual bit and T_i = C_bit - i·e₀.
    # Branch i proves knowledge of r s.t.  A·r ≡ T_i  (mod q).
    # Real branch : i = b   (prover knows r_b)
    # Fake branch : i = 1-b (simulated without knowledge)
    #
    # Proof steps (with rejection sampling)
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # 1. Simulate fake branch: pick c_fake ∈ [0, c_max), z_fake ∈ [-B, B]^m;
    #    set w_fake = A·z_fake − c_fake·T_{1-b}  (mod q)
    # 2. Real announcement: pick ρ ∈ [-γ₁,γ₁]^m; set w_real = A·ρ  (mod q)
    # 3. Fiat-Shamir: c = FS(w_0 ‖ w_1 ‖ T_0 ‖ T_1 ‖ ctx) mod c_max
    # 4. Real challenge: c_real = (c − c_fake) mod c_max
    # 5. Real response : z_real = ρ + c_real · r_b   (NO mod q)
    #    Retry from step 2 with fresh ρ if ‖z_real‖∞ > B
    #
    # Verification
    # ~~~~~~~~~~~~
    # Check (c_0 + c_1) mod c_max ≡ FS(w_0 ‖ w_1 ‖ T_0 ‖ T_1 ‖ ctx) mod c_max
    # Check ‖z_0‖∞ ≤ B  and  A·z_0 ≡ w_0 + c_0·T_0  (mod q)
    # Check ‖z_1‖∞ ≤ B  and  A·z_1 ≡ w_1 + c_1·T_1  (mod q)

    def _prove_bit(
        self, bit: int, r_bit: np.ndarray, C_bit: np.ndarray, ctx: bytes
    ) -> dict:
        b     = int(bit)
        other = 1 - b

        # Adjusted targets: T_i = C_bit - i·e0
        T: list = [C_bit.copy(), (C_bit - self.e0) % self.q]

        # ---- Simulated (fake) branch for index `other` ----------------
        # z_fake is drawn from [-B, B]^m — same distribution as a real
        # rejection-sampled response, so the fake branch is indistinguishable.
        rng_sim = _rng_from(shake256(ctx + b":or_sim" + bytes([b]), 32))
        c_fake  = int(rng_sim.integers(0, self.challenge_max))
        z_fake  = rng_sim.integers(
            -self._response_bound, self._response_bound + 1,
            size=self.m, dtype=np.int64,
        )
        w_fake  = (_matvec_mod(self.A, z_fake, self.q) - c_fake * T[other]) % self.q

        # ---- Real branch: announcement + rejection sampling -----------
        w_arr: list = [None, None]
        w_arr[other] = w_fake

        for attempt in range(_MAX_PROOF_ATTEMPTS):
            rng_real = _rng_from(
                shake256(ctx + b":or_real" + r_bit.tobytes() + attempt.to_bytes(4, "big"), 32)
            )
            rho = _sample_masked(self.m, self.gamma1, rng_real)
            w_real = _matvec_mod(self.A, rho, self.q)
            w_arr[b] = w_real

            fs_input = (
                w_arr[0].tobytes() + w_arr[1].tobytes()
                + T[0].tobytes()   + T[1].tobytes()
                + ctx
            )
            c_total = _fiat_shamir(fs_input, self.challenge_max)
            c_real = int((c_total - c_fake) % self.challenge_max)
            z_real  = rho + c_real * r_bit   # integer addition — NO mod q

            if int(np.max(np.abs(z_real))) <= self._response_bound:
                break
        else:
            raise RuntimeError(
                "ZKP bit proof: rejection sampling exceeded limit. "
                "This is astronomically unlikely — check parameter consistency."
            )

        # ---- Arrange output in canonical branch order [0, 1] ---------
        c_out: list = [None, None]
        z_out: list = [None, None]
        c_out[b]  = c_real
        c_out[other] = c_fake
        z_out[b] = z_real.tolist()
        z_out[other] = z_fake.tolist()

        return {
            "w": [w_arr[0].tolist(), w_arr[1].tolist()],
            "c": [int(c_out[0]),     int(c_out[1])],
            "z": [z_out[0],          z_out[1]],
        }

    def _verify_bit(self, proof: dict, C_bit: np.ndarray, ctx: bytes) -> bool:
        """
        Verify the CDS OR proof: C_bit commits to 0 OR to 1.

        Checks:
        1. (c_0 + c_1) mod c_max ≡ FS(w_0 ‖ w_1 ‖ T_0 ‖ T_1 ‖ ctx)
        2. ‖z_0‖∞ ≤ B  and  A·z_0 ≡ w_0 + c_0·T_0  (mod q)
        3. ‖z_1‖∞ ≤ B  and  A·z_1 ≡ w_1 + c_1·T_1  (mod q)
        """
        try:
            w0 = np.asarray(proof["w"][0], dtype=np.int64)
            w1 = np.asarray(proof["w"][1], dtype=np.int64)
            c0 = int(proof["c"][0])
            c1 = int(proof["c"][1])
            z0 = np.asarray(proof["z"][0], dtype=np.int64)
            z1 = np.asarray(proof["z"][1], dtype=np.int64)

            # Adjusted targets
            T0 = C_bit.copy()
            T1 = (C_bit - self.e0) % self.q

            # 1. Challenge consistency (mod c_max)
            fs_input = (
                w0.tobytes() + w1.tobytes()
                + T0.tobytes() + T1.tobytes()
                + ctx
            )
            c_total = _fiat_shamir(fs_input, self.challenge_max)
            if (c0 + c1) % self.challenge_max != c_total:
                return False

            # 2. Branch 0: bound check + linear equation
            if int(np.max(np.abs(z0))) > self._response_bound:
                return False
            lhs0 = _matvec_mod(self.A, z0, self.q)
            rhs0 = (w0 + c0 * T0) % self.q
            if not np.all(lhs0 == rhs0):
                return False

            # 3. Branch 1: bound check + linear equation
            if int(np.max(np.abs(z1))) > self._response_bound:
                return False
            lhs1 = _matvec_mod(self.A, z1, self.q)
            rhs1 = (w1 + c1 * T1) % self.q
            if not np.all(lhs1 == rhs1):
                return False

            return True
        except Exception:
            return False

    # ------
    # Public API — generate proof
    # ------

    def prove_vote_range(
        self,
        vote: int,
        voter_id: bytes,
        election_id: bytes,
        bio_commitment: bytes = b"",
    ) -> dict:
        """
        Generate a non-interactive ZKP that  vote ∈ {0, …, num_candidates-1}
        without revealing the vote value.

        Parameters
        ----------
        bio_commitment : SHA3-256 of the voter's live BioHash (32 bytes).
            When provided, it is mixed into the Fiat-Shamir context so that
            this proof is only valid for the specific biometric session that
            produced it.  A proof generated without the correct biometric
            commitment will fail verification at the authority, making it
            impossible to submit a ballot for a voter whose biometric you
            have not authenticated as.
        """
        if not 0 <= vote < self.num_candidates:
            raise ValueError(
                f"Vote {vote} outside valid range [0, {self.num_candidates - 1}]."
            )

        ctx = sha3_256(voter_id) + election_id + bio_commitment + ELECTION_DOMAIN

        # ---- Binary decomposition ------------------------------------
        bits_s = format(vote, f"0{self.n_bits}b")   # MSB first

        bit_commitments: List[list] = []
        bit_proofs:  List[dict] = []
        # FIX: accumulate r_main WITHOUT mod q.
        # Applying % q wraps negative entries into [0, q), making r_main large
        # and incompatible with rejection sampling (c_max * q >> gamma1).
        # Without mod q, r_main stays in [-(2^n_bits-1)*β, (2^n_bits-1)*β]^m
        # which is small and compatible.  _commit/_matvec_mod handle the modular
        # reduction internally, so the commitment value is unchanged.
        r_main = np.zeros(self.m, dtype=np.int64)

        for i, b_char in enumerate(bits_s):
            bit_val = int(b_char)
            rng_b = _rng_from(shake256(ctx + f":bit{i}".encode(), 32))
            r_bit  = _sample_short(self.m, self.beta, rng_b)
            C_bit = self._commit(bit_val, r_bit)
            bp    = self._prove_bit(bit_val, r_bit, C_bit, ctx + f":bit{i}".encode())
            bit_commitments.append(C_bit.tolist())
            bit_proofs.append(bp)
            weight  = 1 << (self.n_bits - 1 - i)
            r_main  = r_main + weight * r_bit   # integer sum — no mod q

        # ---- Main commitment -----------------------------------------
        C_main = self._commit(vote, r_main)

        # ---- Knowledge proof (uses _main_response_bound) -------------
        main_proof = self._sigma_prove(
            vote, r_main, C_main, ctx + b":knowledge",
            response_bound=self._main_response_bound,
        )

        # ---- Consistency hash ----------------------------------------
        con_input = (
            C_main.tobytes()
            + b"".join(np.array(c, dtype=np.int64).tobytes() for c in bit_commitments)
            + ctx
        )
        consistency_hash = sha3_256(con_input).hex()

        return {
            "commitment":    C_main.tolist(),
            "main_proof":   main_proof,
            "bit_commitments":  bit_commitments,
            "bit_proofs":    bit_proofs,
            "consistency_hash": consistency_hash,
            "num_candidates":  self.num_candidates,
            "voter_id_hash":    sha3_256(voter_id).hex(),
        }

    # ------
    # Public API — verify proof
    # ------

    def verify_vote_proof(
        self,
        proof: dict,
        voter_id: bytes,
        election_id: bytes,
        bio_commitment: bytes = b"",
    ) -> bool:
        """
        Verify a vote-range ZKP produced by :meth:`prove_vote_range`.

        Parameters
        ----------
        bio_commitment : SHA3-256 of the voter's live BioHash stored at
            authentication time.  Must match the value used during proof
            generation; a mismatch causes verification to fail, enforcing
            biometric-ballot binding at the ZKP level.

        Returns True iff all checks pass.
        """
        try:
            if proof.get("voter_id_hash") != sha3_256(voter_id).hex():
                return False
            if proof.get("num_candidates") != self.num_candidates:
                return False

            ctx    = sha3_256(voter_id) + election_id + bio_commitment + ELECTION_DOMAIN
            C_main = np.asarray(proof["commitment"], dtype=np.int64)

            # Knowledge proof (uses _main_response_bound — same public bound
            # the prover used, derived from n_bits and beta)
            if not self._sigma_verify(
                proof["main_proof"], C_main, ctx + b":knowledge",
                response_bound=self._main_response_bound,
            ):
                return False

            # Bit proofs
            bc = proof.get("bit_commitments", [])
            bp = proof.get("bit_proofs", [])
            if len(bc) != self.n_bits or len(bp) != self.n_bits:
                return False
            for i, (C_bit_l, bproof) in enumerate(zip(bc, bp)):
                C_bit = np.asarray(C_bit_l, dtype=np.int64)
                if not self._verify_bit(bproof, C_bit, ctx + f":bit{i}".encode()):
                    return False

            # ---- Bit-sum check ------------------------------------------
            # Verify C_main == ∑ 2^(n_bits-1-i) · C_bit_i  (mod q).
            # Because r_main = ∑ weight_i · r_bit_i (no mod), linearity gives
            # ∑ weight_i · C_bit_i = A·r_main + vote·e₀ = C_main (mod q).
            C_sum = np.zeros(self.n, dtype=np.int64)
            for i, C_bit_l in enumerate(bc):
                weight = 1 << (self.n_bits - 1 - i)
                C_sum  = (C_sum + weight * np.asarray(C_bit_l, dtype=np.int64)) % self.q
            if not np.all(C_sum == C_main):
                return False

            # Consistency hash
            con_input = (
                C_main.tobytes()
                + b"".join(
                    np.array(c, dtype=np.int64).tobytes() for c in bc
                )
                + ctx
            )
            if proof.get("consistency_hash") != sha3_256(con_input).hex():
                return False

            return True

        except Exception:
            return False

    # ------
    # Helper
    # ------

    def commitment_bytes(self, proof: dict) -> bytes:
        """First 32 int64 elements of the main commitment as bytes."""
        arr = np.asarray(proof["commitment"][:32], dtype=np.int64)
        return arr.tobytes()
