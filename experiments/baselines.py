"""Compare small models on lexical features with leakage-safe (domain-grouped) splits.

Splits (by hashing the registrable domain): train 60 / val 10 / cal 10 / test 20.
  val  - model selection (hyper-parameters, early stopping)
  cal  - probability calibration + threshold choice (never used for fitting the model)
  test - touched once for the reported numbers
"""
from __future__ import annotations

import argparse
import json
import os
import pickle
import sys
import time

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RESULTS, metrics, save_json  # noqa: E402
from features import TldEncoder, cached_lexical, canon_text  # noqa: E402

import lightgbm as lgb  # noqa: E402
from sklearn.feature_extraction.text import HashingVectorizer  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sklearn.tree import DecisionTreeClassifier  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402

EXCLUDE_DEFAULT = {"popular_rank_log", "is_popular", "popular_typo",  # circular with legit labelling
                   "parse_error"}  # constant for valid URLs (unparseable rows are reported as ERROR)


def load(dataset):
    df = pd.read_csv(os.path.join(RESULTS, "..", "data", "processed", f"{dataset}.csv"), dtype={"url": str})
    return df


def design(df, name, exclude=()):
    lex = cached_lexical(name, df.url.values)
    cols = [c for c in lex.columns if not c.startswith("_") and c not in exclude and c not in EXCLUDE_DEFAULT]
    X = lex[cols].copy()
    tr = (df.split == "train").values
    enc = TldEncoder().fit(lex["_tld"][tr], df.label[tr])
    X["tld_logit"] = enc.logit(lex["_tld"])
    return X, lex, enc


def fit_lgbm(Xtr, ytr, Xva, yva, params=None, rounds=2000):
    p = dict(objective="binary", learning_rate=0.05, num_leaves=31, min_data_in_leaf=40,
             feature_fraction=0.8, bagging_fraction=0.8, bagging_freq=1, lambda_l2=1.0,
             verbose=-1, num_threads=4, seed=0)
    p.update(params or {})
    dtr = lgb.Dataset(Xtr, ytr, free_raw_data=False)
    dva = lgb.Dataset(Xva, yva, reference=dtr)
    m = lgb.train(p, dtr, rounds, valid_sets=[dva], callbacks=[lgb.early_stopping(100, verbose=False)])
    return m


def time_per_url(fn, X, reps=3):
    best = 1e9
    for _ in range(reps):
        t = time.perf_counter()
        fn(X)
        best = min(best, time.perf_counter() - t)
    return best / len(X) * 1e6  # microseconds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--skip-char", action="store_true")
    args = ap.parse_args()
    df = load(args.dataset)
    X, lex, enc = design(df, args.dataset)
    y = df.label.values.astype(int)
    S = {s: (df.split == s).values for s in ("train", "val", "cal", "test")}
    print({s: int(m.sum()) for s, m in S.items()}, "features", X.shape[1], flush=True)
    out = {"dataset": args.dataset, "n_features": X.shape[1], "splits": {s: int(m.sum()) for s, m in S.items()},
           "models": {}}
    preds = {}

    # --- Logistic regression on standardised lexical features
    sc = StandardScaler().fit(X[S["train"]])
    Z = sc.transform(X).astype(np.float32)
    best = None
    for C in (0.01, 0.1, 1.0, 10.0):
        m = LogisticRegression(C=C, max_iter=3000).fit(Z[S["train"]], y[S["train"]])
        auc = roc_auc_score(y[S["val"]], m.predict_proba(Z[S["val"]])[:, 1])
        if best is None or auc > best[0]:
            best = (auc, C, m)
    lr = best[2]
    preds["logreg"] = lr.predict_proba(Z)[:, 1]
    out["models"]["logreg"] = {"C": best[1], "val_auc": best[0],
                               "us_per_url_predict": time_per_url(lambda a: lr.predict_proba(a), Z[S["test"]])}

    # --- Decision tree (depth chosen on val)
    best = None
    for d in (3, 4, 5, 6, 8, 10, 12):
        m = DecisionTreeClassifier(max_depth=d, min_samples_leaf=20, random_state=0).fit(X[S["train"]], y[S["train"]])
        auc = roc_auc_score(y[S["val"]], m.predict_proba(X[S["val"]])[:, 1])
        if best is None or auc > best[0]:
            best = (auc, d, m)
    dt = best[2]
    preds["tree"] = dt.predict_proba(X)[:, 1]
    out["models"]["tree"] = {"max_depth": best[1], "val_auc": best[0], "n_leaves": int(dt.get_n_leaves())}

    # --- LightGBM (small)
    for name, params in (("lgbm_small", dict(num_leaves=15)), ("lgbm", dict(num_leaves=31))):
        m = fit_lgbm(X[S["train"]], y[S["train"]], X[S["val"]], y[S["val"]], params)
        preds[name] = m.predict(X, num_iteration=m.best_iteration)
        fp = os.path.join(RESULTS, "models", f"{args.dataset}_{name}.txt")
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        m.save_model(fp, num_iteration=m.best_iteration)
        out["models"][name] = {"best_iteration": m.best_iteration, "val_auc": float(roc_auc_score(y[S["val"]], preds[name][S["val"]])),
                               "model_bytes": os.path.getsize(fp),
                               "us_per_url_predict": time_per_url(lambda a: m.predict(a, num_iteration=m.best_iteration), X[S["test"]].values)}
        if name == "lgbm":
            imp = pd.Series(m.feature_importance("gain"), index=X.columns).sort_values(ascending=False)
            out["lgbm_gain_importance"] = {k: float(v) for k, v in imp.items()}

    # --- Character n-gram hashing + logistic regression (a "tiny text model" baseline)
    if not args.skip_char:
        hv = HashingVectorizer(analyzer="char", ngram_range=(3, 5), n_features=2 ** 20, alternate_sign=False,
                               norm="l2", lowercase=True)
        t = time.perf_counter()
        H = hv.transform([canon_text(u) for u in df.url.values])
        hash_s = time.perf_counter() - t
        best = None
        for C in (1.0, 4.0, 16.0):
            m = LogisticRegression(C=C, max_iter=2000, solver="liblinear").fit(H[S["train"]], y[S["train"]])
            auc = roc_auc_score(y[S["val"]], m.predict_proba(H[S["val"]])[:, 1])
            if best is None or auc > best[0]:
                best = (auc, C, m)
        cm = best[2]
        preds["char_ngram_lr"] = cm.predict_proba(H)[:, 1]
        nnz = int((cm.coef_ != 0).sum())
        out["models"]["char_ngram_lr"] = {"C": best[1], "val_auc": best[0], "nonzero_weights": nnz,
                                          "hash_us_per_url": hash_s / len(df) * 1e6}

    # --- metrics on val / test (uncalibrated scores, threshold 0.5)
    for name, p in preds.items():
        out["models"][name]["val"] = metrics(y[S["val"]], p[S["val"]])
        out["models"][name]["test"] = metrics(y[S["test"]], p[S["test"]])
        print(f"{name:14s} val_auc={out['models'][name]['val']['roc_auc']:.4f} test_auc={out['models'][name]['test']['roc_auc']:.4f} "
              f"test_pr_auc={out['models'][name]['test']['pr_auc']:.4f} R@1%FPR={out['models'][name]['test']['recall_at_fpr_1pct']:.3f}", flush=True)
    save_json(out, "baselines", f"{args.dataset}.json")
    np.savez_compressed(os.path.join(RESULTS, "baselines", f"{args.dataset}_preds.npz"), y=y,
                        split=df.split.values, **preds)
    with open(os.path.join(RESULTS, "baselines", f"{args.dataset}_tld_encoder.pkl"), "wb") as fh:
        pickle.dump(enc, fh)


if __name__ == "__main__":
    main()
