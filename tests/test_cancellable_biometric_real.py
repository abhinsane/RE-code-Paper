"""
Real-fingerprint tests for CancellableBiometric using the SOCOFing dataset.

Requires: uses SOCOFing/Real/ directory with BMP fingerprint images.

Run:
    pytest tests/test_cancellable_biometric_real.py -v

"""

import hashlib
from pathlib import Path

import cv2
import matplotlib
matplotlib.use("Agg")   # non-interactive backend — no display required
import matplotlib.pyplot as plt
import numpy as np
import pytest

from pq_evoting.cancellable_biometric import CancellableBiometric
from pq_evoting.pq_crypto import PQKeyPair

# ---------------------------------------------------------------------------
# Dataset discovery — skip entire module if SOCOFing is absent
# ---------------------------------------------------------------------------

SOCOFING_DIR = Path(__file__).parent.parent / "SOCOFing" / "Real"

pytestmark = pytest.mark.skipif(
    not SOCOFING_DIR.exists(),
    reason="SOCOFing dataset not found at SOCOFing/Real/",
)

# Folder where fingerprint snapshots are saved during test runs
SNAPSHOT_DIR = Path(__file__).parent / "snapshots"
SNAPSHOT_DIR.mkdir(exist_ok=True)


def _images_for_subject(subject_id: str):
    """Return sorted list of BMP (Bitmap) paths for a given SOCOFing subject ID."""
    return sorted(SOCOFING_DIR.glob(f"{subject_id}__*.BMP"))


# Subject 100 — 10 fingers available, used as the enrolled (genuine) voter
SUBJECT_A = "100"
# Subject 101 — different person, used as the impostor probe
SUBJECT_B = "101"


# ---------------------------------------------------------------------------
# Visualisation helper
# ---------------------------------------------------------------------------

def _save_revocability_proof(
    image_path: str,
    cb,
    bh_old: np.ndarray,
    bh_new: np.ndarray,
    score_genuine: float,
    score_old_revoked: float,
    score_new_valid: float,
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
    image_path        : fingerprint BMP used in the test
    cb                : CancellableBiometric instance (for feature_dim)
    bh_old            : BioHash binary vector produced with Token A (before revocation)
    bh_new            : BioHash binary vector produced with Token B (after revocation)
    score_genuine     : verify(finger, Token A, old enrolled)  — should PASS
    score_old_revoked : verify(finger, Token A, new enrolled)  — should FAIL (0.0)
    score_new_valid   : verify(finger, Token B, new enrolled)  — should PASS
    hash_old / hash_new : SHA3-256 hex digests of the two BioHash templates
    filename          : output PNG filename (saved to SNAPSHOT_DIR)
    subject_label     : optional subject info shown in fingerprint panel title
    """
    dim  = len(bh_old)
    side = int(np.ceil(np.sqrt(dim)))
    pad  = side * side - dim
    grid_a   = np.pad(bh_old, (0, pad)).reshape(side, side).astype(np.float32)
    grid_b   = np.pad(bh_new, (0, pad)).reshape(side, side).astype(np.float32)
    grid_xor = np.pad((bh_old != bh_new).astype(np.float32), (0, pad)).reshape(side, side)

    hamming_sim = 1.0 - np.sum(bh_old != bh_new) / dim
    changed_pct = 100.0 * np.sum(bh_old != bh_new) / dim
    threshold   = 0.818  # BIO_MATCH_THRESHOLD from config.py

    fig = plt.figure(figsize=(18, 10))
    fig.suptitle(
        "Revocability Proof — Cancellable Biometric Template Revocation",
        fontsize=14, fontweight="bold",
    )

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
        f"BioHash — Token A\n(before revocation)\ndim={dim}  ones={int(bh_old.sum())}",
        fontsize=8,
    )
    ax_a.axis("off")

    # Panel 3 — BioHash with Token B (after revocation)
    ax_b.imshow(grid_b, cmap="Oranges", vmin=0, vmax=1, interpolation="nearest")
    ax_b.set_title(
        f"BioHash — Token B\n(after revocation)\ndim={dim}  ones={int(bh_new.sum())}",
        fontsize=8,
    )
    ax_b.axis("off")

    # Panel 4 — XOR difference map (red = bit changed)
    ax_xor.imshow(grid_xor, cmap="Reds", vmin=0, vmax=1, interpolation="nearest")
    ax_xor.set_title(
        f"XOR difference map\nbits changed: {changed_pct:.1f}%\n"
        f"Hamming similarity: {hamming_sim:.4f}",
        fontsize=8,
    )
    ax_xor.axis("off")

    # Panel 5+6 — verification scores bar chart
    ax_scores = fig.add_subplot(2, 4, (5, 6))
    labels_bar = [
        "① Before revocation\nToken A vs old template\n(should PASS)",
        "② After revocation\nToken A vs new template\n(should FAIL — revoked)",
        "③ After revocation\nToken B vs new template\n(should PASS)",
    ]
    scores_bar   = [score_genuine, score_old_revoked, score_new_valid]
    expected_bar = [True, False, True]
    colors_bar   = [
        "#2ecc71" if score >= threshold else "#e74c3c"
        for score in scores_bar
    ]
    bars = ax_scores.barh(labels_bar, scores_bar, color=colors_bar, height=0.5, edgecolor="k")
    ax_scores.axvline(threshold, color="navy", linestyle="--", linewidth=1.5,
                      label=f"Threshold = {threshold}")
    for bar, score, expected in zip(bars, scores_bar, expected_bar):
        outcome   = "PASS ✓" if score >= threshold else "FAIL ✗"
        note      = "" if (score >= threshold) == expected else "  ⚠ UNEXPECTED"
        ax_scores.text(
            max(score + 0.01, 0.02), bar.get_y() + bar.get_height() / 2,
            f"{score:.4f}  {outcome}{note}", va="center", fontsize=8,
        )
    ax_scores.set_xlim(0, 1.1)
    ax_scores.set_xlabel("Hamming similarity score")
    ax_scores.set_title("Verification scores — proof that revocation works",
                         fontsize=9, fontweight="bold")
    ax_scores.legend(fontsize=8)

    # Panel 7+8 — SHA3-256 template hash comparison
    ax_hashes = fig.add_subplot(2, 4, (7, 8))
    ax_hashes.axis("off")
    linked    = hash_old == hash_new
    hash_text = (
        "SHA3-256 Template Hashes\n"
        "──────────────────────────────────────────────────────────────\n"
        f"Token A (old template):\n  {hash_old}\n\n"
        f"Token B (new template):\n  {hash_new}\n\n"
        f"Match: {'YES — templates are LINKED ⚠' if linked else 'NO — templates are UNLINKABLE ✓'}"
    )
    ax_hashes.text(
        0.05, 0.95, hash_text,
        va="top", ha="left", fontsize=7.5,
        transform=ax_hashes.transAxes,
        family="monospace",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#f0f0f0", edgecolor="#999"),
    )
    ax_hashes.set_title("Template unlinkability — SHA3-256 hashes must differ",
                          fontsize=9, fontweight="bold")

    out = SNAPSHOT_DIR / filename
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig(out, dpi=120)
    plt.close(fig)
    print(f"\n  [revocability proof] {out}")


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
    image_paths : list of str  — paths to BMP (Bitmap) fingerprint images
    labels      : list of str  — caption for each image panel
    title       : str          — figure title
    filename    : str          — output filename (saved to SNAPSHOT_DIR)
    extra_info  : str          — optional annotation line below the title
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
        ax.set_title(f"{label}\n{Path(path).name}", fontsize=8)
        ax.axis("off")

    out = SNAPSHOT_DIR / filename
    plt.tight_layout(rect=[0, 0, 1, 0.90])
    plt.savefig(out, dpi=120)
    plt.close(fig)
    print(f"\n  [snapshot] {out}")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def authority():
    """ML-KEM-768 / ML-DSA-65 key pair shared across all tests in this module."""
    return PQKeyPair()


@pytest.fixture(scope="module")
def cb():
    return CancellableBiometric()


@pytest.fixture(scope="module")
def subject_a_images():
    """All BMP images for Subject A (the enrolled genuine voter)."""
    imgs = _images_for_subject(SUBJECT_A)
    if len(imgs) < 2:
        pytest.skip(f"Subject {SUBJECT_A} has fewer than 2 images")
    return [str(p) for p in imgs]


@pytest.fixture(scope="module")
def subject_b_images():
    """All BMP images for Subject B (the impostor)."""
    imgs = _images_for_subject(SUBJECT_B)
    if not imgs:
        pytest.skip(f"Subject {SUBJECT_B} has no images")
    return [str(p) for p in imgs]


TOKEN_A = b"real_token_v1"
TOKEN_B = b"real_token_v2"


# ---------------------------------------------------------------------------
# Feature extraction using Gabor + HOG (Histogram of Oriented Gradients)
# ---------------------------------------------------------------------------


class TestRealFeatureExtraction:
    def test_extract_returns_unit_vector(self, cb, subject_a_images):
        _save_fingerprint_figure(
            [subject_a_images[0]],
            [f"Subject {SUBJECT_A}"],
            title="TestRealFeatureExtraction — HOG feature vector is L2-normalised",
            filename="real_feat_unit_vector.png",
            extra_info="Gabor-enhanced HOG descriptor must have ‖v‖₂ = 1.0",
        )
        feat = cb.extract_features(subject_a_images[0])
        assert feat.dtype == np.float32
        assert abs(np.linalg.norm(feat) - 1.0) < 1e-5

    def test_same_image_deterministic(self, cb, subject_a_images):
        _save_fingerprint_figure(
            [subject_a_images[0], subject_a_images[0]],
            ["Scan 1", "Scan 2 (same BMP)"],
            title="TestRealFeatureExtraction — determinism (same BMP twice)",
            filename="real_feat_determinism.png",
        )
        f1 = cb.extract_features(subject_a_images[0])
        f2 = cb.extract_features(subject_a_images[0])
        np.testing.assert_array_equal(f1, f2)

    def test_different_fingers_different_features(self, cb, subject_a_images):
        """Two different fingers from the same subject must produce different HOG vectors."""
        _save_fingerprint_figure(
            [subject_a_images[0], subject_a_images[1]],
            [f"Subject {SUBJECT_A} — Finger 1", f"Subject {SUBJECT_A} — Finger 2"],
            title="TestRealFeatureExtraction — different fingers of same subject",
            filename="real_feat_diff_fingers.png",
        )
        f1 = cb.extract_features(subject_a_images[0])
        f2 = cb.extract_features(subject_a_images[1])
        assert not np.array_equal(f1, f2)

    def test_different_subjects_different_features(
        self, cb, subject_a_images, subject_b_images
    ):
        _save_fingerprint_figure(
            [subject_a_images[0], subject_b_images[0]],
            [f"Subject {SUBJECT_A} (genuine)", f"Subject {SUBJECT_B} (impostor)"],
            title="TestRealFeatureExtraction — different subjects",
            filename="real_feat_diff_subjects.png",
        )
        f1 = cb.extract_features(subject_a_images[0])
        f2 = cb.extract_features(subject_b_images[0])
        assert not np.array_equal(f1, f2)


# ---------------------------------------------------------------------------
# Genuine match — same finger enrolled and probed with same token
# BIO_MATCH_THRESHOLD = 0.818 (from config.py)
# ---------------------------------------------------------------------------


class TestRealGenuineMatch:
    def test_same_finger_same_token_matches(self, cb, authority, subject_a_images):
        """Enrol then verify with the same BMP image → Hamming similarity must exceed threshold."""
        _save_fingerprint_figure(
            [subject_a_images[0], subject_a_images[0]],
            ["Enrolled", "Probe (same BMP + same token)"],
            title="TestRealGenuineMatch — genuine match",
            filename="real_genuine_match.png",
            extra_info="Hamming similarity must be ≥ 0.818 (BIO_MATCH_THRESHOLD in config.py)",
        )
        enrolled = cb.enroll(subject_a_images[0], TOKEN_A, authority.kem_pk)
        is_match, score = cb.verify(
            subject_a_images[0], TOKEN_A, authority.kem_sk, enrolled
        )
        assert is_match, f"Genuine match failed (score={score:.3f})"
        assert score >= 0.818

    def test_score_in_valid_range(self, cb, authority, subject_a_images):
        _save_fingerprint_figure(
            [subject_a_images[0]], [f"Subject {SUBJECT_A}"],
            title="TestRealGenuineMatch — similarity score range check",
            filename="real_score_range.png",
        )
        enrolled = cb.enroll(subject_a_images[0], TOKEN_A, authority.kem_pk)
        _, score = cb.verify(subject_a_images[0], TOKEN_A, authority.kem_sk, enrolled)
        assert 0.0 <= score <= 1.0


# ---------------------------------------------------------------------------
# Impostor rejection — different subject tries to authenticate
# FAR (False Acceptance Rate) must be 0 for this pair
# ---------------------------------------------------------------------------


class TestRealImpostorRejection:
    def test_different_subject_rejected(
        self, cb, authority, subject_a_images, subject_b_images
    ):
        """Enrol subject A; probe with subject B — impostor must be rejected (FAR = 0 for this pair)."""
        _save_fingerprint_figure(
            [subject_a_images[0], subject_b_images[0]],
            [f"Enrolled: Subject {SUBJECT_A}", f"Impostor probe: Subject {SUBJECT_B}"],
            title="TestRealImpostorRejection — cross-subject impostor",
            filename="real_impostor_rejection.png",
            extra_info="FAR (False Acceptance Rate) must be 0 — different subjects must never match",
        )
        enrolled = cb.enroll(subject_a_images[0], TOKEN_A, authority.kem_pk)
        is_match, score = cb.verify(
            subject_b_images[0], TOKEN_A, authority.kem_sk, enrolled
        )
        assert not is_match, (
            f"Impostor from Subject {SUBJECT_B} should be rejected (score={score:.3f})"
        )

    def test_wrong_token_rejected(self, cb, authority, subject_a_images):
        """Wrong token is caught by SHA3-256 hash check before biometric comparison."""
        _save_fingerprint_figure(
            [subject_a_images[0], subject_a_images[0]],
            ["Enrolled (Token A)", "Probe (Token B — wrong)"],
            title="TestRealImpostorRejection — wrong token rejected at SHA3-256 check",
            filename="real_wrong_token.png",
        )
        enrolled = cb.enroll(subject_a_images[0], TOKEN_A, authority.kem_pk)
        is_match, score = cb.verify(
            subject_a_images[0], TOKEN_B, authority.kem_sk, enrolled
        )
        assert not is_match
        assert score == 0.0


# ---------------------------------------------------------------------------
# Cancellability — token revocation on real SOCOFing fingerprints
#
# Cancellability property: changing the token changes the QR-decomposed
# orthogonal projection matrix, producing a new BioHash that is statistically
# independent of the old one (Hamming similarity ≈ 0.5 between old and new).
# ---------------------------------------------------------------------------


class TestRealCancellability:
    def _revocability_proof(self, cb, authority, image_path, filename, subject_label=""):
        """
        Run the full revocation flow on a real SOCOFing fingerprint, collect all
        three verification scores, and save a _save_revocability_proof snapshot.
        Returns (enrolled, new_enrolled).
        """
        feat     = cb.extract_features(image_path)
        bh_old   = cb.compute_biohash(feat, TOKEN_A)
        bh_new   = cb.compute_biohash(feat, TOKEN_B)
        enrolled = cb.enroll(image_path, TOKEN_A, authority.kem_pk)
        new_enrolled = cb.cancel_and_reenroll(
            image_path, TOKEN_A, TOKEN_B,
            authority.kem_pk, authority.kem_sk, enrolled,
        )
        _, score_genuine      = cb.verify(image_path, TOKEN_A, authority.kem_sk, enrolled)
        _, score_old_revoked  = cb.verify(image_path, TOKEN_A, authority.kem_sk, new_enrolled)
        _, score_new_valid    = cb.verify(image_path, TOKEN_B, authority.kem_sk, new_enrolled)
        _save_revocability_proof(
            image_path        = image_path,
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

    def test_token_change_makes_templates_unlinkable(self, cb, authority, subject_a_images):
        """Same real finger, different tokens → BioHashes must be near-random (similarity < 0.75).
        Cancellability property: changing the token changes the QR-decomposed
        orthogonal projection matrix so old and new BioHashes are statistically independent.
        """
        enrolled, new_enrolled = self._revocability_proof(
            cb, authority, subject_a_images[0],
            filename="real_cancel_unlinkability.png",
            subject_label=f"Subject {SUBJECT_A}  {Path(subject_a_images[0]).name}",
        )
        feat = cb.extract_features(subject_a_images[0])
        bh_a = cb.compute_biohash(feat, TOKEN_A)
        bh_b = cb.compute_biohash(feat, TOKEN_B)
        similarity = 1.0 - np.sum(bh_a != bh_b) / len(bh_a)
        assert similarity < 0.75, (
            f"Templates with different tokens are too similar ({similarity:.3f}); "
            "cancellability is broken."
        )

    def test_revoke_old_token_invalid(self, cb, authority, subject_a_images):
        enrolled, new_enrolled = self._revocability_proof(
            cb, authority, subject_a_images[0],
            filename="real_cancel_old_token.png",
            subject_label=f"Subject {SUBJECT_A}  {Path(subject_a_images[0]).name}",
        )
        is_match, score = cb.verify(
            subject_a_images[0], TOKEN_A, authority.kem_sk, new_enrolled
        )
        assert not is_match
        assert score == 0.0

    def test_revoke_new_token_valid(self, cb, authority, subject_a_images):
        enrolled, new_enrolled = self._revocability_proof(
            cb, authority, subject_a_images[0],
            filename="real_cancel_new_token.png",
            subject_label=f"Subject {SUBJECT_A}  {Path(subject_a_images[0]).name}",
        )
        is_match, score = cb.verify(
            subject_a_images[0], TOKEN_B, authority.kem_sk, new_enrolled
        )
        assert is_match, f"New token should match after revocation (score={score:.3f})"

    def test_revoked_template_hash_differs(self, cb, authority, subject_a_images):
        enrolled, new_enrolled = self._revocability_proof(
            cb, authority, subject_a_images[0],
            filename="real_cancel_hash_diff.png",
            subject_label=f"Subject {SUBJECT_A}  {Path(subject_a_images[0]).name}",
        )
        assert enrolled["template_hash"] != new_enrolled["template_hash"]

    def test_cross_finger_enroll_verify(self, cb, authority, subject_a_images):
        """Enrol with one finger, probe with a different finger of the same subject.
        Real AFIS (Automated Fingerprint Identification System) systems enrol
        multiple fingers; here we verify the pipeline handles the case gracefully
        and returns a score in [0, 1] without error.
        The revocability proof uses the enrolled finger for both Token A and Token B.
        """
        if len(subject_a_images) < 2:
            pytest.skip("Need at least 2 images for cross-finger test")
        # Show the revocability proof for the enrolled finger
        self._revocability_proof(
            cb, authority, subject_a_images[0],
            filename="real_cancel_cross_finger_proof.png",
            subject_label=f"Subject {SUBJECT_A} — enrolled finger",
        )
        # Then test cross-finger verification
        enrolled = cb.enroll(subject_a_images[0], TOKEN_A, authority.kem_pk)
        _save_fingerprint_figure(
            [subject_a_images[0], subject_a_images[1]],
            [
                f"Enrolled: {Path(subject_a_images[0]).name}",
                f"Probe: {Path(subject_a_images[1]).name}",
            ],
            title="TestRealCancellability — cross-finger probe (same subject)",
            filename="real_cancel_cross_finger.png",
            extra_info=(
                f"Subject {SUBJECT_A}: enrol finger 1, probe with finger 2  |  "
                "Score should be in [0, 1]; match depends on inter-finger similarity"
            ),
        )
        is_match, score = cb.verify(
            subject_a_images[1], TOKEN_A, authority.kem_sk, enrolled
        )
        assert 0.0 <= score <= 1.0
