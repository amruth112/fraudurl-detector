"""Score of the shipped offline model on the exact 1,500 PhreshPhish test URLs used for the Laya comparison.

Reads the per-URL prediction files (results/final/preds_safe.npz and a Laya run's test split), which are not
published because they contain third-party URL lists, and writes the aggregate numbers to
results/laya/shipped_model_on_laya_test.json, which render_report.py reads.
"""
from __future__ import annotations

import json
import os
import sys

import numpy as np
from sklearn.metrics import roc_auc_score

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import recall_at_fpr  # noqa: E402

R = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")

if __name__ == "__main__":
    z = np.load(os.path.join(R, "final", "preds_safe.npz"), allow_pickle=True)
    test_urls = set(np.load(os.path.join(R, "laya", "finetune_head_multilingual_phreshphish.npz"),
                            allow_pickle=True)["test_url"])
    m = np.array([u in test_urls for u in z["url"]]) & (z["dataset"] == "phreshphish")
    out = {"n": int(m.sum()), "n_phishing": int(z["y"][m].sum()),
           "roc_auc": float(roc_auc_score(z["y"][m], z["prob"][m])),
           "recall_at_fpr_1pct": float(recall_at_fpr(z["y"][m], z["prob"][m], 0.01)),
           "model": "fraudurl/data/model_safe.json"}
    with open(os.path.join(R, "laya", "shipped_model_on_laya_test.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps(out, indent=1))
