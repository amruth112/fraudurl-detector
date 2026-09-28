"""Paired bootstrap CI for the cascade (LightGBM decides; fine-tuned Laya re-ranks only the
uncertain band). Pre-registered rule: Laya counts as useful if the cascade gain's CI excludes 0."""
import os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyze_laya import baseline_scores, sig
from common import RESULTS, recall_at_fpr, save_json

if __name__ == "__main__":
    z = np.load(os.path.join(RESULTS, "laya", "finetune_head_multilingual_phreshphish.npz"), allow_pickle=True)
    y, s, urls = z["test_y"], z["test_margin"], z["test_url"]
    lg = baseline_scores("phreshphish", urls)["lgbm"]
    out = {}
    for lo, hi in ((0.2, 0.8), (0.1, 0.9), (0.3, 0.7)):
        band = (lg > lo) & (lg < hi)
        casc = lg.copy(); casc[band] = sig((s[band] - np.median(s)) / (s.std() + 1e-9))
        rng = np.random.default_rng(0); d = []
        for _ in range(2000):
            i = rng.integers(0, len(y), len(y))
            d.append(recall_at_fpr(y[i], casc[i], 0.01) - recall_at_fpr(y[i], lg[i], 0.01))
        out[f"{lo}-{hi}"] = {"share_sent_to_laya": float(band.mean()), "gain_point": float(recall_at_fpr(y, casc, .01) - recall_at_fpr(y, lg, .01)),
                             "gain_ci95": [float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))]}
        print(f"band {lo}-{hi}", out[f"{lo}-{hi}"])
    save_json(out, "laya", "cascade_ci_phreshphish.json")
