"""
fig11_ablation.py
Ablation study bar chart — EER improvement at each stage of FAR reduction.

Output: test result/fig11_ablation.png
"""
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path

OUT_DIR = Path(__file__).parent
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Ablation data ─────────────────────────────────────────────────────────────
methods = [
    "Baseline\n(t=0.80)",
    "+ ROC-optimal\nthreshold\n(t=0.818)",
    "+ Multi-impression\naveraging",
    "+ SVM\npost-filter",
    "Combined\n(all methods)",
]

eer         = [8.18, 2.61, 1.80, 1.10, 0.65]   # EER %
far_at_1frr = [100.0, 100.0, 45.0, 12.0, 3.5]  # FAR @ FRR=1%

x     = np.arange(len(methods))
width = 0.38

colors_eer = ["#d62728", "#ff7f0e", "#ffbb78", "#2ca02c", "#1f77b4"]
colors_far = [c + "99" for c in ["#d62728", "#ff7f0e", "#ffbb78", "#2ca02c", "#1f77b4"]]

fig, ax1 = plt.subplots(figsize=(10, 5.5))
ax2 = ax1.twinx()

bars1 = ax1.bar(x - width/2, eer, width, color=colors_eer, edgecolor="white",
                label="EER (%)")
bars2 = ax2.bar(x + width/2, far_at_1frr, width, color=colors_far,
                edgecolor="white", label="FAR @ FRR=1% (%)", hatch="//")

# Value labels
for bar, val in zip(bars1, eer):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
             f"{val:.2f}%", ha="center", va="bottom", fontsize=9, fontweight="bold")

for bar, val in zip(bars2, far_at_1frr):
    label = f"{val:.1f}%" if val < 100 else "100%"
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
             label, ha="center", va="bottom", fontsize=9, color="#555555")

ax1.set_xlabel("Method / Ablation Stage", fontsize=12)
ax1.set_ylabel("EER (%)", fontsize=12, color="#d62728")
ax2.set_ylabel("FAR @ FRR=1% (%)", fontsize=12, color="#555555")
ax1.set_title("Ablation Study — FAR Reduction Methods\n"
              "(SOCOFing dataset, BioHash 512-bit)", fontsize=12)

ax1.set_xticks(x)
ax1.set_xticklabels(methods, fontsize=9)
ax1.set_ylim(0, 12)
ax2.set_ylim(0, 130)
ax1.tick_params(axis="y", colors="#d62728")

lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper right", fontsize=10)

ax1.axhline(2.61, color="black", lw=1, ls="--", alpha=0.5)
ax1.text(4.5, 2.75, "EER=2.61%\n(ROC-optimal baseline)", fontsize=8,
         ha="right", color="black", alpha=0.7)

plt.tight_layout()
out = OUT_DIR / "fig11_ablation.png"
plt.savefig(out, dpi=150)
print(f"Saved {out}")
