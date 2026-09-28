"""Does combining Laya with the tiny model help? Cross-fitted stacking (2 folds, repeated with 5
seeds) of LightGBM's log-odds + the Laya score over all 1,500 test URLs; paired bootstrap CI of the gain."""
import os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyze_laya import baseline_scores
from common import RESULTS, recall_at_fpr, save_json
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

def laya_scores(kind):
    L = os.path.join(RESULTS, "laya")
    if kind == "embed":
        z = np.load(os.path.join(L, "embed_multilingual_phreshphish.npz"), allow_pickle=True)
        best = max((roc_auc_score(z["val_y"], LogisticRegression(C=C, max_iter=3000).fit(z["train_X"], z["train_y"]).predict_proba(z["val_X"])[:, 1]), C) for C in (0.01, 0.1, 1, 10))
        lr = LogisticRegression(C=best[1], max_iter=3000).fit(z["train_X"], z["train_y"])
        return z["test_url"], z["test_y"], lr.decision_function(z["test_X"])
    z = np.load(os.path.join(L, "finetune_head_multilingual_phreshphish.npz"), allow_pickle=True)
    return z["test_url"], z["test_y"], z["test_margin"]

if __name__ == "__main__":
    out = {}
    for kind in ("embed", "finetune"):
        urls, y, s = laya_scores(kind)
        lg = np.clip(baseline_scores("phreshphish", urls)["lgbm"], 1e-6, 1 - 1e-6)
        lg = np.log(lg / (1 - lg))
        Z = np.c_[lg, (s - s.mean()) / (s.std() + 1e-9)]
        oofs = []
        for seed in range(5):
            oof = np.zeros(len(y)); fold = np.random.default_rng(seed).random(len(y)) < 0.5
            for a, b in ((fold, ~fold), (~fold, fold)):
                oof[b] = LogisticRegression(max_iter=1000).fit(Z[a], y[a]).decision_function(Z[b])
            oofs.append(oof)
        st = np.mean(oofs, axis=0)
        rng = np.random.default_rng(0); dA, dR = [], []
        for _ in range(2000):
            i = rng.integers(0, len(y), len(y))
            dA.append(roc_auc_score(y[i], st[i]) - roc_auc_score(y[i], lg[i]))
            dR.append(recall_at_fpr(y[i], st[i], .01) - recall_at_fpr(y[i], lg[i], .01))
        q = lambda v: [round(float(np.percentile(v, 2.5)), 4), round(float(np.percentile(v, 97.5)), 4)]
        out[kind] = {"lgbm": {"roc_auc": roc_auc_score(y, lg), "recall_at_fpr_1pct": recall_at_fpr(y, lg, .01)},
                     "stack": {"roc_auc": roc_auc_score(y, st), "recall_at_fpr_1pct": recall_at_fpr(y, st, .01)},
                     "delta_auc_ci95": q(dA), "delta_recall1_ci95": q(dR)}
        print(kind, out[kind])
    save_json(out, "laya", "stack_ci_phreshphish.json")
