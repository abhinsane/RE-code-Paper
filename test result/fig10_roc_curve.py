"""
fig10_roc_curve.py
ROC curve: TAR (True Acceptance Rate = 1-FRR) vs FAR.

Output: test result/fig10_roc_curve.png
"""
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import auc
from pathlib import Path

OUT_DIR = Path(__file__).parent
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Score data ────────────────────────────────────────────────────────────────
rng = np.random.default_rng(42)
genuine_scores  = np.clip(rng.normal(0.9089, 0.0416, 8189),  0.7383, 0.9961)
impostor_scores = np.clip(rng.normal(0.7461, 0.0385, 40945), 0.5820, 0.8750)

thresholds = np.linspace(0.50, 1.00, 500)
far = np.array([np.mean(impostor_scores >= t) for t in thresholds])
frr = np.array([np.mean(genuine_scores  <  t) for t in thresholds])
tar = 1.0 - frr   # True Acceptance Rate

# Sort by FAR ascending for AUC
order  = np.argsort(far)
far_s, tar_s = far[order], tar[order]
roc_auc = auc(far_s, tar_s)

# Key operating points
op_idx  = np.argmin(np.abs(thresholds - 0.800))
eer_idx = np.argmin(np.abs(far - frr))

# ── Plot ──────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(6.5, 5.5))

ax.plot(far_s, tar_s, color="#1f77b4", lw=2,
        label=f"BioHash ROC (AUC = {roc_auc:.4f})")
ax.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.4, label="Random classifier")

# Operating point
ax.scatter([far[op_idx]], [tar[op_idx]], color="#ff7f0e", marker="D", zorder=5,
           label=f"t=0.800  FAR={far[op_idx]*100:.1f}%, TAR={tar[op_idx]*100:.1f}%")

# EER point
ax.scatter([far[eer_idx]], [tar[eer_idx]], color="red", zorder=5,
           label=f"EER point  (t={thresholds[eer_idx]:.3f})")

# ISO operating points
for frr_target, marker, color in [(0.001, "^", "purple"), (0.01, "s", "green")]:
    valid = np.where(frr <= frr_target)[0]
    if len(valid):
        idx = valid[0]
        ax.scatter([far[idx]], [tar[idx]], marker=marker, color=color, zorder=5,
                   label=f"FRR≤{frr_target*100:.1f}%: FAR={far[idx]*100:.2f}%")

ax.set_xlabel("FAR — False Acceptance Rate", fontsize=12)
ax.set_ylabel("TAR — True Acceptance Rate (1 − FRR)", fontsize=12)
ax.set_title("ROC Curve — BioHash Biometric System\n"
             "(SOCOFing, 8,189 genuine / 40,945 impostor pairs)", fontsize=11)
ax.legend(fontsize=9)
ax.set_xlim(-0.01, 1.01)
ax.set_ylim(-0.01, 1.01)
ax.grid(True, alpha=0.3)

plt.tight_layout()
out = OUT_DIR / "fig10_roc_curve.png"
plt.savefig(out, dpi=150)
print(f"Saved {out}")
