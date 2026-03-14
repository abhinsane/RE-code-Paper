#!/usr/bin/env python3
"""
Biometric FAR/FRR Evaluation Script
=====================================
Measures False Acceptance Rate (FAR), False Rejection Rate (FRR), and
Equal Error Rate (EER) for the BioHashing pipeline.

Evaluation protocol (stolen-token threat model):
  Genuine pair  : same subject, same token, two different impressions
  Impostor pair : subject B's fingerprint presented with subject A's token
                  (worst-case: attacker knows the victim's token)

Usage:
    python eval_biometric.py --dataset ./SOCOFing
    python eval_biometric.py --dataset ./SOCOFing --subjects 100 --plot
"""

import argparse
import hashlib
import random
import sys
from itertools import combinations
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))

from pq_evoting.cancellable_biometric import (
    CancellableBiometric,
    load_socofing_samples,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_token(subject_id: str) -> bytes:
    """Deterministic per-subject token (simulates a hashed PIN)."""
    return hashlib.sha3_256(f"eval_token_{subject_id}".encode()).digest()



def compute_far_frr(genuine_scores, impostor_scores, thresholds):
    """Return (FAR, FRR) arrays aligned with *thresholds*."""
    g = np.array(genuine_scores)
    imp = np.array(impostor_scores)
    far = np.array([float(np.mean(imp >= t)) for t in thresholds])
    frr = np.array([float(np.mean(g  <  t)) for t in thresholds])
    return far, frr


def find_eer(thresholds, far, frr):
    """Linear interpolation to find (eer_threshold, eer_value)."""
    diff = far - frr
    for i in range(len(diff) - 1):
        if diff[i] * diff[i + 1] <= 0:
            span = abs(diff[i]) + abs(diff[i + 1])
            alpha = abs(diff[i]) / span if span > 0 else 0.5
            t = thresholds[i] + alpha * (thresholds[i + 1] - thresholds[i])
            eer = (far[i] * (1 - alpha) + far[i + 1] * alpha +
                   frr[i] * (1 - alpha) + frr[i + 1] * alpha) / 2
            return float(t), float(eer)
    idx = int(np.argmin(np.abs(diff)))
    return float(thresholds[idx]), float((far[idx] + frr[idx]) / 2)


def far_at_frr_target(thresholds, far, frr, target_frr):
    """FAR at the lowest threshold where FRR ≤ target_frr."""
    valid = np.where(frr <= target_frr)[0]
    if len(valid) == 0:
        return float("nan")
    return float(far[valid[0]])


# ---------------------------------------------------------------------------
# Synthetic data generator
# ---------------------------------------------------------------------------

def load_socofing_with_altered(
    dataset_path: str,
    num_subjects: int = 30,
) -> tuple[dict[str, str], dict[str, list[str]], dict[str, str]]:
    """
    Load SOCOFing Real + Altered images grouped by finger key.

    Returns
    -------
    real_by_finger   : {finger_key: real_image_path}
    altered_by_finger: {finger_key: [altered_image_paths]}
    finger_to_subject: {finger_key: subject_id}

    finger_key = "{subject_id}__{gender}_{hand}_{finger}_finger"
    e.g. "1__M_Left_index_finger"

    Genuine pair protocol: real_by_finger[k]  vs  altered_by_finger[k]
    (same finger, same subject, different impression — valid genuine pair)
    """
    root     = Path(dataset_path)
    real_dir = root / "Real"
    if not real_dir.exists():
        raise FileNotFoundError(f"No Real/ folder found under {dataset_path}")

    # Collect all Altered sub-directories
    altered_dirs: list[Path] = []
    for name in ("Altered", "Altered-Easy", "Altered-Medium", "Altered-Hard"):
        d = root / name
        if d.exists():
            altered_dirs.append(d)
    if not altered_dirs:
        raise FileNotFoundError(f"No Altered*/ folder found under {dataset_path}")

    extensions = {".bmp", ".BMP", ".png", ".PNG", ".jpg", ".JPG"}

    # --- Real images ---
    real_by_finger: dict[str, str] = {}
    finger_to_subject: dict[str, str] = {}
    seen_subjects: set[str] = set()

    for img_path in sorted(real_dir.iterdir()):
        if img_path.suffix not in extensions:
            continue
        stem  = img_path.stem                          # e.g. "1__M_Left_index_finger"
        parts = stem.split("__")
        if len(parts) < 2:
            continue
        subj_id    = parts[0]
        finger_key = stem                              # full stem IS the finger key

        if subj_id not in seen_subjects:
            if len(seen_subjects) >= num_subjects:
                continue
            seen_subjects.add(subj_id)

        real_by_finger[finger_key]    = str(img_path)
        finger_to_subject[finger_key] = subj_id

    # --- Altered images (recursive — handles Altered/Easy/, Altered/Medium/ etc.) ---
    altered_by_finger: dict[str, list[str]] = {}
    for alt_dir in altered_dirs:
        for img_path in sorted(alt_dir.rglob("*")):
            if img_path.suffix not in extensions:
                continue
            stem = img_path.stem   # e.g. "1__M_Left_index_finger_Obl"
            matched = None
            for fk in real_by_finger:
                if stem.startswith(fk):
                    matched = fk
                    break
            if matched:
                altered_by_finger.setdefault(matched, []).append(str(img_path))

    print(f"  Found {len(real_by_finger)} real fingers, "
          f"{sum(len(v) for v in altered_by_finger.values())} altered images "
          f"across {len(altered_by_finger)} fingers")

    # Keep only fingers that have both real AND altered images
    valid_keys = [k for k in real_by_finger if k in altered_by_finger]
    real_by_finger    = {k: real_by_finger[k]    for k in valid_keys}
    altered_by_finger = {k: altered_by_finger[k] for k in valid_keys}
    finger_to_subject = {k: finger_to_subject[k] for k in valid_keys}

    return real_by_finger, altered_by_finger, finger_to_subject


# ---------------------------------------------------------------------------
# Main evaluation
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate biometric FAR/FRR/EER for the BioHashing pipeline"
    )
    parser.add_argument("--dataset", required=True,
                        help="Path to SOCOFing dataset root (must contain Real/ sub-folder)")
    parser.add_argument("--subjects", type=int, default=30,
                        help="Number of subjects (default: 30)")
    parser.add_argument("--impostor-multiplier", type=int, default=5,
                        help="Impostor pairs = genuine × this (default: 5)")
    parser.add_argument("--plot", action="store_true",
                        help="Save DET curve and score-distribution plots")
    parser.add_argument("--output", default="bio_eval_results.txt",
                        help="Path for the text results file")
    args = parser.parse_args()

    bio = CancellableBiometric()

    # ------------------------------------------------------------------
    # 1. Load fingerprint data
    # ------------------------------------------------------------------
    print("Loading fingerprint data ...")
    # Tracks whether we're in Real+Altered mode (proper genuine pairs) or
    # legacy mode (multiple images per subject, cross-finger genuine pairs).
    use_altered_mode = False
    real_by_finger:    dict[str, str]       = {}
    altered_by_finger: dict[str, list[str]] = {}
    finger_to_subject: dict[str, str]       = {}
    subjects:          dict[str, list[str]] = {}

    try:
        real_by_finger, altered_by_finger, finger_to_subject = \
            load_socofing_with_altered(args.dataset, num_subjects=args.subjects)
        use_altered_mode = True
        n_fingers = len(real_by_finger)
        n_subjects = len(set(finger_to_subject.values()))
        print(f"  Loaded {n_fingers} fingers from {n_subjects} subjects "
              f"(Real + Altered) from {args.dataset}")
    except FileNotFoundError:
        # No Altered folder — use multi-finger-per-subject mode
        subjects = load_socofing_samples(
            args.dataset,
            num_subjects=args.subjects,
            min_samples_per_subject=2,
        )
        print(f"  Loaded {len(subjects)} subjects (Real only, cross-finger genuine pairs)")
        print("  NOTE: Add Altered/ folder for proper same-finger genuine pairs")

    if not use_altered_mode:
        subjects = {k: v for k, v in subjects.items() if len(v) >= 2}
        print(f"  {len(subjects)} subjects with >=2 impressions available")

    # ------------------------------------------------------------------
    # 2. Pre-compute features for every image once (cached)
    # ------------------------------------------------------------------
    if use_altered_mode:
        all_images = list(real_by_finger.values())
        for paths in altered_by_finger.values():
            all_images.extend(paths)
    else:
        all_images = []
        for paths in subjects.values():
            all_images.extend(paths)

    print(f"\nExtracting features for {len(all_images)} images (once each) ...")
    feature_cache: dict[str, np.ndarray] = {}
    for i, img_path in enumerate(all_images, 1):
        try:
            feature_cache[img_path] = bio.extract_features(img_path)
        except Exception as exc:
            print(f"  Warning: feature extraction failed for {img_path} - {exc}")
        if i % 20 == 0 or i == len(all_images):
            print(f"  {i}/{len(all_images)} done")

    # Cache projection matrices per token (QR decomp once per subject)
    projection_cache: dict[str, np.ndarray] = {}

    def get_projection(token: bytes) -> np.ndarray:
        key = token.hex()
        if key not in projection_cache:
            projection_cache[key] = bio._projection_matrix(token)
        return projection_cache[key]

    biohash_cache: dict[tuple[str, str], np.ndarray] = {}

    def get_biohash(img_path: str, token: bytes) -> np.ndarray:
        key = (img_path, token.hex())
        if key not in biohash_cache:
            P = get_projection(token)
            f = np.asarray(feature_cache[img_path], dtype=np.float32)
            raw_dim = bio._raw_dim
            f = f[:raw_dim] if len(f) >= raw_dim else np.pad(f, (0, raw_dim - len(f)))
            projected = P @ f
            biohash_cache[key] = (projected > np.median(projected)).astype(np.uint8)
        return biohash_cache[key]

    def similarity_cached(img_a: str, img_b: str, token: bytes) -> float:
        ha = get_biohash(img_a, token)
        hb = get_biohash(img_b, token)
        n = min(len(ha), len(hb))
        return 1.0 - int(np.sum(ha[:n] != hb[:n])) / n

    # Pre-warm projection + biohash cache for all subject tokens
    print("Pre-computing projection matrices and BioHashes ...")
    if use_altered_mode:
        unique_subjects = set(finger_to_subject.values())
        for subj_id in unique_subjects:
            get_projection(make_token(subj_id))
        for fk, real_path in real_by_finger.items():
            if real_path in feature_cache:
                get_biohash(real_path, make_token(finger_to_subject[fk]))
    else:
        for subj_id, paths in {k: v for k, v in subjects.items()
                                if any(p in feature_cache for p in v)}.items():
            token = make_token(subj_id)
            get_projection(token)
            for p in paths:
                if p in feature_cache:
                    get_biohash(p, token)
    print(f"  {len(projection_cache)} projection matrices, {len(biohash_cache)} BioHashes cached")

    # ------------------------------------------------------------------
    # 3. Generate genuine pairs
    #    Altered mode : Real[finger] vs Altered[finger]  (same finger, same subject)
    #    Legacy mode  : different images of same subject (cross-finger, less ideal)
    # ------------------------------------------------------------------
    print("\nBuilding genuine pairs ...")
    genuine_scores: list[float] = []

    if use_altered_mode:
        for fk, real_path in real_by_finger.items():
            if real_path not in feature_cache:
                continue
            token = make_token(finger_to_subject[fk])
            for alt_path in altered_by_finger[fk]:
                if alt_path in feature_cache:
                    genuine_scores.append(similarity_cached(real_path, alt_path, token))
    else:
        valid_subjects = {k: [p for p in v if p in feature_cache]
                          for k, v in subjects.items()
                          if any(p in feature_cache for p in v)}
        for subj_id, paths in valid_subjects.items():
            token = make_token(subj_id)
            for img_a, img_b in combinations(paths, 2):
                genuine_scores.append(similarity_cached(img_a, img_b, token))

    n_genuine = len(genuine_scores)
    print(f"  {n_genuine} genuine pairs")

    # ------------------------------------------------------------------
    # 4. Generate impostor pairs (subject B's finger, subject A's token)
    # ------------------------------------------------------------------
    print("Building impostor pairs ...")
    max_impostor = args.impostor_multiplier * n_genuine
    impostor_scores: list[float] = []
    rng = random.Random(42)
    attempts = 0

    if use_altered_mode:
        finger_keys  = [fk for fk in real_by_finger if real_by_finger[fk] in feature_cache]
        valid_altered = {fk: [p for p in altered_by_finger[fk] if p in feature_cache]
                         for fk in finger_keys}
        finger_keys  = [fk for fk in finger_keys if valid_altered[fk]]

        while len(impostor_scores) < max_impostor and attempts < max_impostor * 10:
            attempts += 1
            fk_a, fk_b = rng.sample(finger_keys, 2)
            if finger_to_subject[fk_a] == finger_to_subject[fk_b]:
                continue   # skip same subject
            token_a   = make_token(finger_to_subject[fk_a])
            enroll    = real_by_finger[fk_a]
            probe     = rng.choice(valid_altered[fk_b])
            impostor_scores.append(similarity_cached(enroll, probe, token_a))
    else:
        valid_subjects = {k: [p for p in v if p in feature_cache]
                          for k, v in subjects.items()
                          if any(p in feature_cache for p in v)}
        valid_ids = list(valid_subjects.keys())
        while len(impostor_scores) < max_impostor and attempts < max_impostor * 10:
            attempts += 1
            a, b = rng.sample(valid_ids, 2)
            token_a    = make_token(a)
            img_enroll = rng.choice(valid_subjects[a])
            img_probe  = rng.choice(valid_subjects[b])
            impostor_scores.append(similarity_cached(img_enroll, img_probe, token_a))

    print(f"  {len(impostor_scores)} impostor pairs")

    # ------------------------------------------------------------------
    # 4. Sweep thresholds → FAR / FRR
    # ------------------------------------------------------------------
    print("\nSweeping thresholds …")
    thresholds = np.arange(0.50, 1.001, 0.005)
    far, frr = compute_far_frr(genuine_scores, impostor_scores, thresholds)

    eer_threshold, eer = find_eer(thresholds, far, frr)
    cur_idx = int(np.argmin(np.abs(thresholds - 0.80)))

    g_arr = np.array(genuine_scores)
    i_arr = np.array(impostor_scores)

    # ------------------------------------------------------------------
    # 5. Format and print results
    # ------------------------------------------------------------------
    sep = "=" * 62
    lines = [
        sep,
        "  BIOMETRIC EVALUATION RESULTS",
        sep,
        f"  Subjects        : {n_subjects if use_altered_mode else len(subjects)}",
        f"  Genuine pairs   : {n_genuine}",
        f"  Impostor pairs  : {len(impostor_scores)}",
        "",
        "  Score Distributions",
        "  -------------------",
        f"  Genuine   mean={g_arr.mean():.4f}  std={g_arr.std():.4f}"
        f"  min={g_arr.min():.4f}  max={g_arr.max():.4f}",
        f"  Impostor  mean={i_arr.mean():.4f}  std={i_arr.std():.4f}"
        f"  min={i_arr.min():.4f}  max={i_arr.max():.4f}",
        "",
        "  Performance at Current Threshold (0.80)",
        "  ----------------------------------------",
        f"  FAR  = {far[cur_idx]*100:6.2f}%",
        f"  FRR  = {frr[cur_idx]*100:6.2f}%",
        "",
        "  Equal Error Rate",
        "  ----------------",
        f"  EER           = {eer*100:.2f}%",
        f"  EER threshold = {eer_threshold:.3f}",
        "",
        "  FAR at ISO/IEC 19795-1 Operating Points",
        "  ----------------------------------------",
        f"  FAR @ FRR=0.1% : {far_at_frr_target(thresholds, far, frr, 0.001)*100:.2f}%",
        f"  FAR @ FRR=1%   : {far_at_frr_target(thresholds, far, frr, 0.010)*100:.2f}%",
        f"  FAR @ FRR=5%   : {far_at_frr_target(thresholds, far, frr, 0.050)*100:.2f}%",
        "",
        "  Threshold Sweep",
        "  ---------------",
        f"  {'Threshold':>10}  {'FAR':>8}  {'FRR':>8}",
        "  " + "-" * 34,
    ]

    for t, f_, r_ in zip(thresholds[::10], far[::10], frr[::10]):
        note = ""
        if abs(t - 0.80) < 0.003:
            note = "  <- current"
        elif abs(t - eer_threshold) < 0.003:
            note = f"  <- EER {eer*100:.1f}%"
        lines.append(f"  {t:>10.3f}  {f_*100:>7.2f}%  {r_*100:>7.2f}%{note}")

    lines.append(sep)

    output = "\n".join(lines)
    print("\n" + output)

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(output + "\n")
    print(f"\nResults saved -> {args.output}")

    # ------------------------------------------------------------------
    # 6. Optional plots (requires matplotlib)
    # ------------------------------------------------------------------
    if args.plot:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt

            fig, axes = plt.subplots(1, 3, figsize=(15, 5))
            fig.suptitle("Biometric Evaluation — BioHashing Pipeline", fontsize=13)

            # Score distributions
            ax = axes[0]
            ax.hist(g_arr, bins=40, alpha=0.6, color="green",
                    label=f"Genuine (n={n_genuine})", density=True)
            ax.hist(i_arr, bins=40, alpha=0.6, color="red",
                    label=f"Impostor (n={len(impostor_scores)})", density=True)
            ax.axvline(0.80, color="blue",   linestyle="--", linewidth=1.5,
                       label="Threshold=0.80")
            ax.axvline(eer_threshold, color="orange", linestyle="--", linewidth=1.5,
                       label=f"EER threshold={eer_threshold:.3f}")
            ax.set_xlabel("Hamming Similarity")
            ax.set_ylabel("Density")
            ax.set_title("Score Distributions")
            ax.legend(fontsize=8)

            # DET curve (log-log)
            ax = axes[1]
            fp = np.clip(far * 100, 1e-3, 100)
            fn = np.clip(frr * 100, 1e-3, 100)
            ax.plot(fp, fn, "b-", linewidth=2, label="DET curve")
            ax.plot(eer * 100, eer * 100, "ro", markersize=8,
                    label=f"EER = {eer*100:.2f}%")
            ax.plot(far[cur_idx] * 100, frr[cur_idx] * 100,
                    "gs", markersize=8, label="Threshold=0.80")
            ax.set_xscale("log")
            ax.set_yscale("log")
            ax.set_xlabel("FAR (%)")
            ax.set_ylabel("FRR (%)")
            ax.set_title("DET Curve (log-log)")
            ax.legend(fontsize=8)
            ax.grid(True, which="both", alpha=0.3)

            # FAR & FRR vs threshold
            ax = axes[2]
            ax.plot(thresholds, far * 100, "r-",  linewidth=2, label="FAR")
            ax.plot(thresholds, frr * 100, "b-",  linewidth=2, label="FRR")
            ax.axvline(0.80, color="green",  linestyle="--", linewidth=1.5,
                       label="Current=0.80")
            ax.axvline(eer_threshold, color="orange", linestyle="--", linewidth=1.5,
                       label=f"EER={eer*100:.1f}%")
            ax.set_xlabel("Threshold")
            ax.set_ylabel("Error Rate (%)")
            ax.set_title("FAR & FRR vs Threshold")
            ax.legend(fontsize=8)
            ax.grid(True, alpha=0.3)

            plt.tight_layout()
            plot_path = Path(args.output).with_suffix(".png")
            plt.savefig(plot_path, dpi=150, bbox_inches="tight")
            print(f"Plots saved → {plot_path}")

        except ImportError:
            print("matplotlib not installed — skipping plots.")
            print("Install with: pip install matplotlib")


if __name__ == "__main__":
    main()
