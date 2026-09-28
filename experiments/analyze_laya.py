"""Evaluate every Laya variant against the tiny baselines on the SAME test URLs.

Inputs: results/laya/*.npz (from laya_eval.py / laya_finetune.py) and
        results/baselines/<dataset>_preds.npz (from baselines.py).
Pre-registered decision rule (fixed before looking at test numbers):
  Laya is 'useful' only if a Laya mode beats the best baseline on ROC-AUC AND on recall at
  1% FPR with the paired-bootstrap 95% CI excluding 0, or if a cascade improves recall at
  1% FPR at acceptable latency.
"""
from __future__ import annotations

import glob
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RESULTS, metrics, recall_at_fpr, save_json  # noqa: E402

from scipy.optimize import minimize  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402

sig = lambda z: 1 / (1 + np.exp(-np.clip(z, -60, 60)))  # noqa: E731


def fit_temperature(m, y):
    f = lambda lt: -np.mean(y * np.log(sig(m / np.exp(lt[0])) + 1e-12) + (1 - y) * np.log(1 - sig(m / np.exp(lt[0])) + 1e-12))  # noqa: E731
    return float(np.exp(minimize(f, [0.0], method="Nelder-Mead").x[0]))


def fit_platt(m, y):
    lr = LogisticRegression(C=1e6, max_iter=1000).fit(m.reshape(-1, 1), y)
    return float(lr.coef_[0, 0]), float(lr.intercept_[0])


def paired_boot(y, a, b, n=1000, seed=0):
    """CI of metric(a) - metric(b) for AUC and recall@1%FPR, same resampled rows."""
    rng = np.random.default_rng(seed)
    d_auc, d_r1 = [], []
    for _ in range(n):
        i = rng.integers(0, len(y), len(y))
        if 0 < y[i].sum() < len(i):
            d_auc.append(roc_auc_score(y[i], a[i]) - roc_auc_score(y[i], b[i]))
            d_r1.append(recall_at_fpr(y[i], a[i], 0.01) - recall_at_fpr(y[i], b[i], 0.01))
    q = lambda v: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]  # noqa: E731
    return {"delta_auc_ci": q(d_auc), "delta_recall1_ci": q(d_r1)}


def baseline_scores(dataset, urls):
    df = pd.read_csv(os.path.join(RESULTS, "..", "data", "processed", f"{dataset}.csv"), usecols=["url"])
    pos = pd.Series(np.arange(len(df)), index=df.url.values)
    idx = pos.loc[list(urls)].values
    z = np.load(os.path.join(RESULTS, "baselines", f"{dataset}_preds.npz"), allow_pickle=True)
    return {k: z[k][idx] for k in z.files if k not in ("y", "split")}


def summarize(y, s):
    r = metrics(y, s)
    return {k: r[k] for k in ("roc_auc", "pr_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct")}


def main(dataset):
    out = {"dataset": dataset, "zeroshot": {}, "signals": {}, "embed": {}, "finetune": {}, "comparison": {}}
    L = os.path.join(RESULTS, "laya")
    best_laya = {}
    for fp in sorted(glob.glob(os.path.join(L, f"zeroshot_*_{dataset}.npz"))) + \
            sorted(glob.glob(os.path.join(L, f"signals_*_{dataset}.npz"))):
        z = np.load(fp, allow_pickle=True)
        ckpt = os.path.basename(fp).split("_")[1]
        mode = os.path.basename(fp).split("_")[0]
        yv, yc, yt = z["val_y"], z["cal_y"], z["test_y"]
        prompts = sorted({k[len("val_"):] for k in z.files if k.startswith("val_") and not k.endswith(("_y", "_url", "ms_per_url"))})
        res = {}
        for pn in prompts:
            mv, mc, mt = z[f"val_{pn}"], z[f"cal_{pn}"], z[f"test_{pn}"]
            T = fit_temperature(mc, yc)
            a, b = fit_platt(mc, yc)
            shipped_T = 1.0 if ckpt == "multilingual" else 1.9834
            res[pn] = {"val_auc": float(roc_auc_score(yv, mv)), "test_raw": summarize(yt, mt),
                       "ms_per_url": float(z[f"test_{pn}_ms_per_url"]),
                       "test_shipped_calibration": {k: metrics(yt, sig(mt / shipped_T))[k] for k in ("ece", "brier", "log_loss", "accuracy", "fpr", "fnr")},
                       "fitted_temperature": T,
                       "test_temperature_calibrated": {k: metrics(yt, sig(mt / T))[k] for k in ("ece", "brier", "log_loss", "accuracy", "fpr", "fnr")},
                       "test_platt_calibrated": {k: metrics(yt, sig(a * mt + b))[k] for k in ("ece", "brier", "log_loss", "accuracy", "fpr", "fnr")}}
        best = max(res, key=lambda k: res[k]["val_auc"])
        out[mode if mode == "signals" else "zeroshot"][ckpt] = {"prompts": res, "best_prompt_by_val": best}
        key = f"{mode}_{ckpt}"
        best_laya[key] = (z["test_url"], yt, z[f"test_{best}"], float(z[f"test_{best}_ms_per_url"]))
        print(key, best, res[best]["test_raw"], flush=True)

    for fp in sorted(glob.glob(os.path.join(L, f"embed_*_{dataset}.npz"))):
        z = np.load(fp, allow_pickle=True)
        ckpt = os.path.basename(fp).split("_")[1]
        best = None
        for C in (0.01, 0.1, 1.0, 10.0):
            lr = LogisticRegression(C=C, max_iter=3000).fit(z["train_X"], z["train_y"])
            a = roc_auc_score(z["val_y"], lr.predict_proba(z["val_X"])[:, 1])
            if best is None or a > best[0]:
                best = (a, C, lr)
        pt = best[2].predict_proba(z["test_X"])[:, 1]
        out["embed"][ckpt] = {"C": best[1], "val_auc": best[0], "test": summarize(z["test_y"], pt),
                              "ms_per_url": float(z["test_ms_per_url"]), "n_train": int(len(z["train_y"]))}
        best_laya[f"embed_{ckpt}"] = (z["test_url"], z["test_y"], pt, float(z["test_ms_per_url"]))
        print("embed", ckpt, out["embed"][ckpt]["test"], flush=True)

    for fp in sorted(glob.glob(os.path.join(L, f"finetune_*_{dataset}.npz"))):
        z = np.load(fp, allow_pickle=True)
        tag = "_".join(os.path.basename(fp).split("_")[1:3])
        log = json.load(open(fp.replace(".npz", ".json")))
        out["finetune"][tag] = {"test": summarize(z["test_y"], z["test_margin"]), "train_secs": log["train_secs"],
                                "epochs": log["epochs"], "best_epoch": log["best_epoch"],
                                "ms_per_url": log["infer_ms_per_url"], "rss_MB": log["rss_MB"]}
        best_laya[f"finetune_{tag}"] = (z["test_url"], z["test_y"], z["test_margin"], float(log["infer_ms_per_url"]))
        print("finetune", tag, out["finetune"][tag]["test"], flush=True)

    # paired comparison vs baselines on identical URLs
    for key, (urls, y, s, ms) in best_laya.items():
        b = baseline_scores(dataset, urls)
        comp = {"laya": summarize(y, s), "laya_ms_per_url": ms, "n": int(len(y))}
        for bn in ("lgbm", "logreg", "char_ngram_lr"):
            if bn in b:
                comp[bn] = summarize(y, b[bn])
                comp[f"laya_minus_{bn}"] = paired_boot(y, s, b[bn])
        # hybrid: does adding the Laya score to the LightGBM score help? (fit on half, test on other half)
        if "lgbm" in b:
            lg = np.log(np.clip(b["lgbm"], 1e-6, 1 - 1e-6) / (1 - np.clip(b["lgbm"], 1e-6, 1 - 1e-6)))
            Z = np.c_[lg, (s - s.mean()) / (s.std() + 1e-9)]
            rng = np.random.default_rng(0)
            half = rng.random(len(y)) < 0.5
            st = LogisticRegression(max_iter=1000).fit(Z[half], y[half])
            ph = st.predict_proba(Z[~half])[:, 1]
            comp["stack_lgbm_plus_laya_heldout_half"] = {"stack": summarize(y[~half], ph),
                                                         "lgbm_alone": summarize(y[~half], b["lgbm"][~half]),
                                                         "stack_coefs": st.coef_.tolist()}
            # cascade: LightGBM decides confident cases, Laya only for the uncertain band
            for lo, hi in ((0.2, 0.8), (0.1, 0.9)):
                band = (b["lgbm"] > lo) & (b["lgbm"] < hi)
                casc = b["lgbm"].copy()
                casc[band] = sig((s[band] - np.median(s)) / (s.std() + 1e-9))  # Laya rank within band
                comp[f"cascade_{lo}_{hi}"] = {"frac_sent_to_laya": float(band.mean()),
                                              "mean_ms_per_url": float(band.mean() * ms),
                                              "cascade": summarize(y, casc), "lgbm_alone": summarize(y, b["lgbm"])}
        out["comparison"][key] = comp
        print(key, "vs lgbm", comp.get("laya_minus_lgbm"), flush=True)
    save_json(out, "laya", f"analysis_{dataset}.json")


if __name__ == "__main__":
    main(sys.argv[1])
