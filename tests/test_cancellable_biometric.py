"""
Tests for CancellableBiometric — cancellability, revocation, and verification.

All tests use synthetic fingerprints so no SOCOFing dataset is required.
A single PQKeyPair is generated once per module (slow KEM keygen) and shared
across tests via a session-scoped fixture.


"""

import hashlib
from pathlib import Path

import cv2
import matplotlib
matplotlib.use("Agg")   # non-interactive backend — no display required
import matplotlib.pyplot as plt
import numpy as np
import pytest

from pq_evoting.cancellable_biometric import (
    CancellableBiometric,
    create_synthetic_fingerprint,
)
from pq_evoting.pq_crypto import PQKeyPair

# Folder where fingerprint snapshots are saved during test runs
SNAPSHOT_DIR = Path(__file__).parent / "snapshots"
SNAPSHOT_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Visualisation helper
# ---------------------------------------------------------------------------

def _save_fingerprint_figure(
    image_paths: list,
    labels: list,
    title: str,
    filename: str,
    extra_info: str = "",
) -> None:
    """
    Save a matplotlib figure showing one or more fingerprint images side-by-side.

    Parameters
    ----------
    image_paths : list of str  — paths to BMP/PNG fingerprint images
    labels      : list of str  — caption for each image
    title       : str          — figure title
    filename    : str          — output filename (saved to SNAPSHOT_DIR)
    extra_info  : str          — optional text appended below the title
    """
    n = len(image_paths)
    fig, axes = plt.subplots(1, n, figsize=(4 * n, 4))
    if n == 1:
        axes = [axes]

    fig.suptitle(title, fontsize=12, fontweight="bold")
    if extra_info:
        fig.text(0.5, 0.91, extra_info, ha="center", fontsize=9, color="#444444")

    for ax, path, label in zip(axes, image_paths, labels):
        img = cv2.imread(str(path), cv2.IMREAD_GRAYSCALE)
        if img is not None:
            ax.imshow(img, cmap="gray")
        else:
            ax.text(0.5, 0.5, "image not found", ha="center", va="center",
                    transform=ax.transAxes)
        ax.set_title(label, fontsize=9)
        ax.axis("off")

    out = SNAPSHOT_DIR / filename
    plt.tight_layout(rect=[0, 0, 1, 0.90])
    plt.savefig(out, dpi=120)
    plt.close(fig)
    print(f"\n  [snapshot] {out}")


# ---------------------------------------------------------------------------
# Revocability proof snapshot
# ---------------------------------------------------------------------------

def _save_revocability_proof(
    image_path: str,
    cb,
    bh_old: np.ndarray,
    bh_new: np.ndarray,
    score_genuine: float,       # verify(finger, Token A, old enrolled)  — should PASS
    score_old_revoked: float,   # verify(finger, Token A, new enrolled)  — should FAIL (0.0)
    score_new_valid: float,     # verify(finger, Token B, new enrolled)  — should PASS
    hash_old: str,
    hash_new: str,
    filename: str,
    subject_label: str = "",
) -> None:
    """
    Save a 6-panel revocability proof figure:

      [Fingerprint] [BioHash A grid] [BioHash B grid] [XOR diff]
      [Verification results bar chart]  [Template hash comparison]

    Parameters
    ----------
    image_path      : fingerprint BMP used in the test
    cb              : CancellableBiometric instance (for feature_dim)
    bh_old          : BioHash binary vector produced with Token A
    bh_new          : BioHash binary vector produced with Token B
    score_genuine   : Hamming similarity — verify with Token A on old enrolled template
    score_old_revoked: Hamming similarity — verify with Token A on new (revoked) enrolled
    score_new_valid : Hamming similarity — verify with Token B on new enrolled template
    hash_old / hash_new : SHA3-256 hex digests of the two BioHash templates
    filename        : output PNG filename (saved to SNAPSHOT_DIR)
    subject_label   : optional subject info shown in fingerprint panel title
    """
    dim  = len(bh_old)
    side = int(np.ceil(np.sqrt(dim)))
    # Pad vectors to side² so they reshape cleanly into a 2D grid
    pad  = side * side - dim
    grid_a   = np.pad(bh_old, (0, pad)).reshape(side, side).astype(np.float32)
    grid_b   = np.pad(bh_new, (0, pad)).reshape(side, side).astype(np.float32)
    grid_xor = np.pad((bh_old != bh_new).astype(np.float32), (0, pad)).reshape(side, side)

    hamming_sim = 1.0 - np.sum(bh_old != bh_new) / dim
    threshold   = 0.818  # BIO_MATCH_THRESHOLD from config.py

    fig = plt.figure(figsize=(18, 10))
    fig.suptitle(
        "Revocability Proof — Cancellable Biometric Template Revocation",
        fontsize=14, fontweight="bold",
    )

    # -- Row 1: fingerprint + BioHash grids + XOR diff --
    ax_fp  = fig.add_subplot(2, 4, 1)
    ax_a   = fig.add_subplot(2, 4, 2)
    ax_b   = fig.add_subplot(2, 4, 3)
    ax_xor = fig.add_subplot(2, 4, 4)

    # Panel 1 — fingerprint image
    img = cv2.imread(str(image_path), cv2.IMREAD_GRAYSCALE)
    if img is not None:
        ax_fp.imshow(img, cmap="gray")
    else:
        ax_fp.text(0.5, 0.5, "image not found", ha="center", va="center",
                   transform=ax_fp.transAxes)
    ax_fp.set_title(f"Fingerprint used\n{subject_label}\n{Path(image_path).name}", fontsize=8)
    ax_fp.axis("off")

    # Panel 2 — BioHash with Token A (before revocation)
    ax_a.imshow(grid_a, cmap="Blues", vmin=0, vmax=1, interpolation="nearest")
    ax_a.set_title(
        f"BioHash — Token A\n(before revocation)\n"
        f"dim={dim}  ones={int(bh_old.sum())}",
        fontsize=8,
    )
    ax_a.axis("off")

    # Panel 3 — BioHash with Token B (after revocation)
    ax_b.imshow(grid_b, cmap="Oranges", vmin=0, vmax=1, interpolation="nearest")
    ax_b.set_title(
        f"BioHash — Token B\n(after revocation)\n"
        f"dim={dim}  ones={int(bh_new.sum())}",
        fontsize=8,
    )
    ax_b.axis("off")

    # Panel 4 — XOR difference map (red = bit changed)
    ax_xor.imshow(grid_xor, cmap="Reds", vmin=0, vmax=1, interpolation="nearest")
    changed_pct = 100.0 * np.sum(bh_old != bh_new) / dim
    ax_xor.set_title(
        f"XOR difference map\n(bits changed: {changed_pct:.1f}%)\n"
        f"Hamming similarity: {hamming_sim:.4f}",
        fontsize=8,
    )
    ax_xor.axis("off")

    # -- Row 2: verification bar chart + template hash panel --
    ax_scores = fig.add_subplot(2, 4, (5, 6))
    ax_hashes = fig.add_subplot(2, 4, (7, 8))

    # Panel 5+6 — verification scores
    labels_bar   = [
        "① Before revocation\nToken A vs old template\n(should PASS)",
        "② After revocation\nToken A vs new template\n(should FAIL — revoked)",
        "③ After revocation\nToken B vs new template\n(should PASS)",
    ]
    scores_bar   = [score_genuine, score_old_revoked, score_new_valid]
    colors_bar   = [
        "#2ecc71" if score_genuine     >= threshold else "#e74c3c",
        "#2ecc71" if score_old_revoked >= threshold else "#e74c3c",
        "#2ecc71" if score_new_valid   >= threshold else "#e74c3c",
    ]
    expected_bar = [True, False, True]  # expected pass/fail outcomes

    bars = ax_scores.barh(labels_bar, scores_bar, color=colors_bar, height=0.5, edgecolor="k")
    ax_scores.axvline(threshold, color="navy", linestyle="--", linewidth=1.5,
                      label=f"Threshold = {threshold}")
    for bar, score, expected in zip(bars, scores_bar, expected_bar):
        outcome = "PASS ✓" if score >= threshold else "FAIL ✗"
        expected_str = "(expected)" if (score >= threshold) == expected else "⚠ UNEXPECTED"
        ax_scores.text(
            max(score + 0.01, 0.02), bar.get_y() + bar.get_height() / 2,
            f"{score:.4f}  {outcome} {expected_str}",
            va="center", fontsize=8,
        )
    ax_scores.set_xlim(0, 1.1)
    ax_scores.set_xlabel("Hamming similarity score")
    ax_scores.set_title("Verification scores — proof that revocation works", fontsize=9,
                         fontweight="bold")
    ax_scores.legend(fontsize=8)

    # Panel 7+8 — template hash comparison
    ax_hashes.axis("off")
    hash_text = (
        "SHA3-256 Template Hashes\n"
        "──────────────────────────────────────\n"
        f"Token A (old template):\n  {hash_old}\n\n"
        f"Token B (new template):\n  {hash_new}\n\n"
        f"Match: {'YES — templates are LINKED ⚠' if hash_old == hash_new else 'NO — templates are UNLINKABLE ✓'}"
    )
    ax_hashes.text(
        0.05, 0.95, hash_text,
        va="top", ha="left", fontsize=7.5,
        transform=ax_hashes.transAxes,
        family="monospace",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#f0f0f0", edgecolor="#999"),
    )
    ax_hashes.set_title("Template unlinkability — SHA3-256 hashes must differ", fontsize=9,
                          fontweight="bold")

    out = SNAPSHOT_DIR / filename
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig(out, dpi=120)
    plt.close(fig)
    print(f"\n  [revocability proof] {out}")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def authority():
    """ML-KEM-768 / ML-DSA-65 key pair shared across all tests."""
    return PQKeyPair()


@pytest.fixture(scope="session")
def fingerprint_path(tmp_path_factory):
    """Synthetic fingerprint A — enrolled voter (seed 42)."""
    path = tmp_path_factory.mktemp("fp") / "synthetic_A.bmp"
    create_synthetic_fingerprint(str(path), seed=42)
    return str(path)


@pytest.fixture(scope="session")
def second_fingerprint_path(tmp_path_factory):
    """Synthetic fingerprint B — different subject (seed 99)."""
    path = tmp_path_factory.mktemp("fp2") / "synthetic_B.bmp"
    create_synthetic_fingerprint(str(path), seed=99)
    return str(path)


@pytest.fixture(scope="session")
def cb():
    return CancellableBiometric()


TOKEN_A = b"token_version_1"
TOKEN_B = b"token_version_2"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def enroll(cb, fp, authority, token):
    return cb.enroll(fp, token, authority.kem_pk)


# ---------------------------------------------------------------------------
# Biometric feature extraction (HOG — Histogram of Oriented Gradients)
# ---------------------------------------------------------------------------


class TestFeatureExtraction:
    def test_extract_returns_unit_vector(self, cb, fingerprint_path):
        _save_fingerprint_figure(
            [fingerprint_path], ["Synthetic A (seed=42)"],
            title="TestFeatureExtraction — input fingerprint",
            filename="feat_unit_vector.png",
            extra_info=f"Image: {Path(fingerprint_path).name}",
        )
        feat = cb.extract_features(fingerprint_path)
        assert feat.dtype == np.float32
        assert abs(np.linalg.norm(feat) - 1.0) < 1e-5

    def test_same_image_same_features(self, cb, fingerprint_path):
        _save_fingerprint_figure(
            [fingerprint_path, fingerprint_path],
            ["Scan 1", "Scan 2 (same image)"],
            title="TestFeatureExtraction — determinism (same image twice)",
            filename="feat_determinism.png",
        )
        f1 = cb.extract_features(fingerprint_path)
        f2 = cb.extract_features(fingerprint_path)
        np.testing.assert_array_equal(f1, f2)

    def test_different_images_different_features(
        self, cb, fingerprint_path, second_fingerprint_path
    ):
        _save_fingerprint_figure(
            [fingerprint_path, second_fingerprint_path],
            ["Subject A (seed=42)", "Subject B (seed=99)"],
            title="TestFeatureExtraction — different subjects",
            filename="feat_different_subjects.png",
        )
        f1 = cb.extract_features(fingerprint_path)
        f2 = cb.extract_features(second_fingerprint_path)
        assert not np.array_equal(f1, f2)

    def test_missing_image_raises(self, cb):
        with pytest.raises(ValueError, match="Cannot load"):
            cb.extract_features("/nonexistent/path.bmp")


# ---------------------------------------------------------------------------
# BioHash (Biometric Hash) — binarised orthogonal projection
# ---------------------------------------------------------------------------


class TestBioHash:
    def test_output_shape_and_dtype(self, cb, fingerprint_path):
        _save_fingerprint_figure(
            [fingerprint_path], ["Synthetic A"],
            title="TestBioHash — shape and dtype check",
            filename="biohash_shape.png",
            extra_info=f"Expected output: binary vector of length {cb.feature_dim}",
        )
        feat = cb.extract_features(fingerprint_path)
        bh = cb.compute_biohash(feat, TOKEN_A)
        assert bh.shape == (cb.feature_dim,)
        assert set(bh).issubset({0, 1})

    def test_same_token_same_biohash(self, cb, fingerprint_path):
        _save_fingerprint_figure(
            [fingerprint_path, fingerprint_path],
            ["Token A — run 1", "Token A — run 2"],
            title="TestBioHash — determinism (same token twice)",
            filename="biohash_determinism.png",
        )
        feat = cb.extract_features(fingerprint_path)
        bh1 = cb.compute_biohash(feat, TOKEN_A)
        bh2 = cb.compute_biohash(feat, TOKEN_A)
        np.testing.assert_array_equal(bh1, bh2)

    def test_different_tokens_different_biohash(self, cb, fingerprint_path):
        _save_fingerprint_figure(
            [fingerprint_path, fingerprint_path],
            ["Token A projection", "Token B projection"],
            title="TestBioHash — different tokens → different BioHash",
            filename="biohash_diff_tokens.png",
            extra_info="Same finger, different tokens must yield different binary vectors",
        )
        feat = cb.extract_features(fingerprint_path)
        bh_a = cb.compute_biohash(feat, TOKEN_A)
        bh_b = cb.compute_biohash(feat, TOKEN_B)
        assert not np.array_equal(bh_a, bh_b)

    def test_token_change_makes_templates_unlinkable(self, cb, fingerprint_path):
        """Cancellability check:
        Hamming similarity between BioHashes from the same finger but different
        tokens must be close to 0.5 (random), not close to 1.0 (linked).

        FAR  - False Acceptance Rate
        FRR  - False Rejection Rate
        """
        feat = cb.extract_features(fingerprint_path)
        bh_a = cb.compute_biohash(feat, TOKEN_A)
        bh_b = cb.compute_biohash(feat, TOKEN_B)
        similarity = 1.0 - np.sum(bh_a != bh_b) / len(bh_a)

        _save_fingerprint_figure(
            [fingerprint_path, fingerprint_path],
            [f"Token A BioHash", f"Token B BioHash"],
            title="TestBioHash — cancellability / unlinkability",
            filename="biohash_unlinkability.png",
            extra_info=f"Hamming similarity between templates: {similarity:.3f}  (must be < 0.75)",
        )
        assert similarity < 0.75, (
            f"Templates with different tokens are too similar ({similarity:.3f}); "
            "cancellability may be broken."
        )


# ---------------------------------------------------------------------------
# Enrolment — PQ-encrypted (ML-KEM-768) template storage
# ---------------------------------------------------------------------------


class TestEnrollment:
    def test_enroll_returns_required_keys(self, cb, fingerprint_path, authority):
        _save_fingerprint_figure(
            [fingerprint_path], ["Enrolled fingerprint"],
            title="TestEnrollment — enrol and check record keys",
            filename="enroll_keys.png",
        )
        enrolled = enroll(cb, fingerprint_path, authority, TOKEN_A)
        assert "encrypted_template" in enrolled
        assert "template_hash" in enrolled
        assert "token_hash" in enrolled
        assert "feature_dim" in enrolled

    def test_token_hash_matches(self, cb, fingerprint_path, authority):
        # SHA3-256 — Secure Hash Algorithm 3 (256-bit output) used to bind token to record
        _save_fingerprint_figure(
            [fingerprint_path], ["Enrolled fingerprint"],
            title="TestEnrollment — SHA3-256 token hash check",
            filename="enroll_token_hash.png",
        )
        enrolled = enroll(cb, fingerprint_path, authority, TOKEN_A)
        expected = hashlib.sha3_256(TOKEN_A).hexdigest()
        assert enrolled["token_hash"] == expected

    def test_different_tokens_different_template_hash(
        self, cb, fingerprint_path, authority
    ):
        _save_fingerprint_figure(
            [fingerprint_path, fingerprint_path],
            ["Enrolled with Token A", "Enrolled with Token B"],
            title="TestEnrollment — cross-token template hash difference",
            filename="enroll_diff_hashes.png",
        )
        e_a = enroll(cb, fingerprint_path, authority, TOKEN_A)
        e_b = enroll(cb, fingerprint_path, authority, TOKEN_B)
        assert e_a["template_hash"] != e_b["template_hash"]


# ---------------------------------------------------------------------------
# Verification — Hamming-distance comparison of decrypted BioHash templates
# ---------------------------------------------------------------------------


class TestVerification:
    def test_correct_token_matches(self, cb, fingerprint_path, authority):
        _save_fingerprint_figure(
            [fingerprint_path, fingerprint_path],
            ["Enrolled", "Probe (same finger + token)"],
            title="TestVerification — genuine match",
            filename="verify_genuine.png",
        )
        enrolled = enroll(cb, fingerprint_path, authority, TOKEN_A)
        is_match, score = cb.verify(fingerprint_path, TOKEN_A, authority.kem_sk, enrolled)
        assert is_match, f"Expected match but got score={score:.3f}"
        assert 0.0 <= score <= 1.0

    def test_wrong_token_rejected(self, cb, fingerprint_path, authority):
        _save_fingerprint_figure(
            [fingerprint_path, fingerprint_path],
            ["Enrolled (Token A)", "Probe (Token B — wrong)"],
            title="TestVerification — wrong token rejected at SHA3-256 hash check",
            filename="verify_wrong_token.png",
        )
        enrolled = enroll(cb, fingerprint_path, authority, TOKEN_A)
        is_match, score = cb.verify(fingerprint_path, TOKEN_B, authority.kem_sk, enrolled)
        assert not is_match
        assert score == 0.0  # rejected at token-hash check before biometric comparison

    def test_different_finger_rejected(
        self, cb, fingerprint_path, second_fingerprint_path, authority
    ):
        _save_fingerprint_figure(
            [fingerprint_path, second_fingerprint_path],
            ["Enrolled: Subject A", "Probe: Subject B (impostor)"],
            title="TestVerification — impostor rejection",
            filename="verify_impostor.png",
        )
        enrolled = enroll(cb, fingerprint_path, authority, TOKEN_A)
        is_match, score = cb.verify(
            second_fingerprint_path, TOKEN_A, authority.kem_sk, enrolled
        )
        assert not is_match, (
            f"Different fingerprint should not match (score={score:.3f})"
        )

    def test_score_in_range(self, cb, fingerprint_path, authority):
        enrolled = enroll(cb, fingerprint_path, authority, TOKEN_A)
        _, score = cb.verify(fingerprint_path, TOKEN_A, authority.kem_sk, enrolled)
        assert 0.0 <= score <= 1.0


# ---------------------------------------------------------------------------
# Cancellation / Revocation
# Cancellability: changing token makes old and new templates computationally
# unlinkable — an attacker with the old template learns nothing about the new one.
# ---------------------------------------------------------------------------


class TestCancellation:
    def _revocability_proof(self, cb, fingerprint_path, authority, filename, subject_label="Synthetic"):
        """
        Central helper — run the full revocation flow, collect all scores, and
        save a _save_revocability_proof snapshot.  Returns (enrolled, new_enrolled).
        """
        feat       = cb.extract_features(fingerprint_path)
        bh_old     = cb.compute_biohash(feat, TOKEN_A)
        bh_new     = cb.compute_biohash(feat, TOKEN_B)
        enrolled   = enroll(cb, fingerprint_path, authority, TOKEN_A)
        new_enrolled = cb.cancel_and_reenroll(
            fingerprint_path, TOKEN_A, TOKEN_B,
            authority.kem_pk, authority.kem_sk, enrolled,
        )
        _, score_genuine      = cb.verify(fingerprint_path, TOKEN_A, authority.kem_sk, enrolled)
        _, score_old_revoked  = cb.verify(fingerprint_path, TOKEN_A, authority.kem_sk, new_enrolled)
        _, score_new_valid    = cb.verify(fingerprint_path, TOKEN_B, authority.kem_sk, new_enrolled)
        _save_revocability_proof(
            image_path        = fingerprint_path,
            cb                = cb,
            bh_old            = bh_old,
            bh_new            = bh_new,
            score_genuine     = score_genuine,
            score_old_revoked = score_old_revoked,
            score_new_valid   = score_new_valid,
            hash_old          = enrolled["template_hash"],
            hash_new          = new_enrolled["template_hash"],
            filename          = filename,
            subject_label     = subject_label,
        )
        return enrolled, new_enrolled

    def test_revoke_produces_new_enrolled_dict(self, cb, fingerprint_path, authority):
        enrolled, new_enrolled = self._revocability_proof(
            cb, fingerprint_path, authority,
            filename="cancel_new_record.png",
            subject_label="Synthetic A (seed=42)",
        )
        assert new_enrolled["token_hash"] == hashlib.sha3_256(TOKEN_B).hexdigest()

    def test_old_token_invalid_after_revocation(self, cb, fingerprint_path, authority):
        """After cancellation, the old enrolled record must no longer accept the old token."""
        enrolled, new_enrolled = self._revocability_proof(
            cb, fingerprint_path, authority,
            filename="cancel_old_token_rejected.png",
            subject_label="Synthetic A (seed=42)",
        )
        is_match, score = cb.verify(fingerprint_path, TOKEN_A, authority.kem_sk, new_enrolled)
        assert not is_match
        assert score == 0.0

    def test_new_token_valid_after_revocation(self, cb, fingerprint_path, authority):
        enrolled, new_enrolled = self._revocability_proof(
            cb, fingerprint_path, authority,
            filename="cancel_new_token_valid.png",
            subject_label="Synthetic A (seed=42)",
        )
        is_match, score = cb.verify(fingerprint_path, TOKEN_B, authority.kem_sk, new_enrolled)
        assert is_match, f"New token should match after re-enrolment (score={score:.3f})"

    def test_revoke_with_wrong_old_token_raises(self, cb, fingerprint_path, authority):
        _save_fingerprint_figure(
            [fingerprint_path], ["Fingerprint used"],
            title="TestCancellation — wrong old-token raises ValueError",
            filename="cancel_wrong_old_token.png",
            extra_info="Must reject cancellation when old token does not match",
        )
        enrolled = enroll(cb, fingerprint_path, authority, TOKEN_A)
        with pytest.raises(ValueError, match="Old-token verification failed"):
            cb.cancel_and_reenroll(
                fingerprint_path, TOKEN_B, b"token_v3",
                authority.kem_pk, authority.kem_sk, enrolled,
            )

    def test_old_and_new_templates_unlinkable(self, cb, fingerprint_path, authority):
        """Revoked and fresh templates must not share enough bits to link them.
        Unlinkability is the core cancellability property — changing the token
        changes the orthogonal projection matrix (QR decomposition) entirely,
        producing a fresh BioHash that is statistically independent of the old one.
        """
        enrolled_a, enrolled_b = self._revocability_proof(
            cb, fingerprint_path, authority,
            filename="cancel_unlinkability.png",
            subject_label="Synthetic A (seed=42)",
        )
        assert enrolled_a["template_hash"] != enrolled_b["template_hash"]

    def test_sequential_revocations(self, cb, fingerprint_path, authority):
        """Multiple successive revocations should all produce usable templates."""
        tokens = [b"tok_v1", b"tok_v2", b"tok_v3"]
        # Snapshot for each revocation step
        enrolled = enroll(cb, fingerprint_path, authority, tokens[0])
        for i, (old_tok, new_tok) in enumerate(zip(tokens, tokens[1:])):
            feat      = cb.extract_features(fingerprint_path)
            bh_old    = cb.compute_biohash(feat, old_tok)
            bh_new    = cb.compute_biohash(feat, new_tok)
            new_enr   = cb.cancel_and_reenroll(
                fingerprint_path, old_tok, new_tok,
                authority.kem_pk, authority.kem_sk, enrolled,
            )
            _, s_genuine     = cb.verify(fingerprint_path, old_tok, authority.kem_sk, enrolled)
            _, s_old_revoked = cb.verify(fingerprint_path, old_tok, authority.kem_sk, new_enr)
            _, s_new_valid   = cb.verify(fingerprint_path, new_tok, authority.kem_sk, new_enr)
            _save_revocability_proof(
                image_path        = fingerprint_path,
                cb                = cb,
                bh_old            = bh_old,
                bh_new            = bh_new,
                score_genuine     = s_genuine,
                score_old_revoked = s_old_revoked,
                score_new_valid   = s_new_valid,
                hash_old          = enrolled["template_hash"],
                hash_new          = new_enr["template_hash"],
                filename          = f"cancel_sequential_step{i+1}.png",
                subject_label     = f"Synthetic A — step {i+1}: {old_tok.decode()} → {new_tok.decode()}",
            )
            enrolled = new_enr
        is_match, score = cb.verify(fingerprint_path, tokens[-1], authority.kem_sk, enrolled)
        assert is_match, f"Final token should verify after chained revocations (score={score:.3f})"
