"""Which lexical features matter? Category ablations, importance, greedy forward selection.

All selection decisions use the VAL split only; TEST is scored once at the end for the
chosen compact sets. Train is subsampled for the (many) selection fits to keep this fast.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from baselines import design, fit_lgbm, load  # noqa: E402
from common import RESULTS, metrics, recall_at_fpr, save_json  # noqa: E402

import lightgbm as lgb  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402

GROUPS = {
    "scheme": ["scheme_http"],
    "lengths_counts": ["url_len", "n_dot", "n_hyphen", "n_underscore", "n_slash", "n_qmark", "n_equal", "n_amp",
                       "n_semicolon", "n_tilde", "n_percent", "n_plus", "n_hash", "n_comma", "n_exclaim", "n_star",
                       "n_dollar", "host_len", "path_len", "query_len", "n_params", "path_depth",
                       "path_max_seg_len"],
    "char_composition": ["digit_ratio", "letter_ratio", "upper_ratio", "special_ratio", "url_entropy",
                         "n_pct_encoded", "non_ascii", "host_entropy", "path_entropy", "path_digit_ratio",
                         "host_digit_ratio"],
    "host_structure": ["host_n_labels", "n_sub_labels", "sub_len", "www_prefix", "host_n_hyphens", "host_n_digits",
                       "host_is_ip", "host_is_ipv6", "host_punycode", "host_invalid_chars", "host_max_label_len",
                       "sub_has_digit", "sub_has_hyphen", "has_port", "port_nonstd", "has_userinfo", "n_at"],
    "domain_shape": ["sld_len", "sld_entropy", "sld_n_digits", "sld_n_hyphens", "sld_vowel_ratio",
                     "sld_max_consonant_run", "sld_max_digit_run", "sld_digit_letter_switches", "tld_len",
                     "suffix_n_labels", "tld_logit", "suffix_gov_edu"],
    "hosting_platform": ["private_suffix", "user_content_host", "shortener"],
    "path_semantics": ["ext_server", "ext_page", "ext_risky", "is_homepage", "double_slash_in_path",
                       "embedded_url", "redirect_param", "wp_path"],
    "brand_keywords": ["sus_words_host", "sus_words_path", "brand_is_sld", "brand_in_sld_not_equal", "brand_in_sub",
                       "brand_in_path", "brand_typo", "n_host_tokens"],
}
FORMAT_SENSITIVE = ["scheme_http", "www_prefix", "is_homepage"]

P_FAST = dict(num_leaves=15, learning_rate=0.1, min_data_in_leaf=40)


def score(y, p):
    return roc_auc_score(y, p), recall_at_fpr(y, p, 0.01)


def quick_fit(X, y, S, cols, rounds=300):
    m = fit_lgbm(X.loc[S["tr_sub"], cols], y[S["tr_sub"]], X.loc[S["val"], cols], y[S["val"]], P_FAST, rounds)
    return m, m.predict(X.loc[S["val"], cols], num_iteration=m.best_iteration)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--train-sub", type=int, default=60000)
    ap.add_argument("--max-k", type=int, default=20)
    args = ap.parse_args()
    df = load(args.dataset)
    X, lex, enc = design(df, args.dataset)
    y = df.label.values.astype(int)
    rng = np.random.default_rng(0)
    tr_idx = np.where(df.split == "train")[0]
    sub = rng.choice(tr_idx, min(args.train_sub, len(tr_idx)), replace=False)
    S = {"tr_sub": np.zeros(len(df), bool), "val": (df.split == "val").values,
         "train": (df.split == "train").values, "test": (df.split == "test").values}
    S["tr_sub"][sub] = True
    all_cols = [c for c in X.columns]
    known = {c for g in GROUPS.values() for c in g}
    missing = [c for c in all_cols if c not in known]
    assert not missing, f"features without a group: {missing}"
    out = {"dataset": args.dataset, "n_features": len(all_cols)}
    t0 = time.time()

    _, p = quick_fit(X, y, S, all_cols)
    base_auc, base_r1 = score(y[S["val"]], p)
    out["all_features_val"] = {"auc": base_auc, "recall_at_1pct_fpr": base_r1}
    print("all", base_auc, base_r1, flush=True)

    # (a) each group alone, (b) all minus group
    out["group_alone"], out["group_removed"] = {}, {}
    for g, cols in GROUPS.items():
        _, p = quick_fit(X, y, S, cols)
        a, r = score(y[S["val"]], p)
        out["group_alone"][g] = {"n": len(cols), "auc": a, "recall_at_1pct_fpr": r}
        rest = [c for c in all_cols if c not in cols]
        _, p = quick_fit(X, y, S, rest)
        a2, r2 = score(y[S["val"]], p)
        out["group_removed"][g] = {"auc": a2, "delta_auc": a2 - base_auc, "recall_at_1pct_fpr": r2,
                                   "delta_recall": r2 - base_r1}
        print(f"{g:18s} alone auc={a:.4f} | removed auc={a2:.4f} (Δ{a2 - base_auc:+.4f}) R1 {r2:.3f}", flush=True)
    rest = [c for c in all_cols if c not in FORMAT_SENSITIVE]
    _, p = quick_fit(X, y, S, rest)
    a, r = score(y[S["val"]], p)
    out["without_format_sensitive"] = {"removed": FORMAT_SENSITIVE, "auc": a, "recall_at_1pct_fpr": r}

    # (c) permutation importance on val (AUC drop), using a full-feature model
    m, p = quick_fit(X, y, S, all_cols)
    Xv = X.loc[S["val"], all_cols].copy()
    perm = {}
    for c in all_cols:
        saved = Xv[c].values.copy()
        Xv[c] = rng.permutation(saved)
        perm[c] = base_auc - roc_auc_score(y[S["val"]], m.predict(Xv, num_iteration=m.best_iteration))
        Xv[c] = saved
    out["permutation_importance_auc_drop"] = dict(sorted(perm.items(), key=lambda kv: -kv[1]))
    gain = pd.Series(m.feature_importance("gain"), index=all_cols)
    out["gain_importance_share"] = (gain / gain.sum()).sort_values(ascending=False).to_dict()

    # (d) greedy forward selection on val AUC (candidates restricted to top-40 by gain for speed)
    cands = list(gain.sort_values(ascending=False).index[:32])
    chosen, curve = [], []
    while len(chosen) < args.max_k:
        best = None
        for c in cands:
            if c in chosen:
                continue
            _, p = quick_fit(X, y, S, chosen + [c], rounds=200)
            a, r = score(y[S["val"]], p)
            if best is None or a > best[1]:
                best = (c, a, r)
        chosen.append(best[0])
        curve.append({"k": len(chosen), "added": best[0], "val_auc": best[1], "val_recall_at_1pct_fpr": best[2]})
        print(f"k={len(chosen):2d} +{best[0]:24s} auc={best[1]:.4f} R1={best[2]:.3f}  ({time.time() - t0:.0f}s)", flush=True)
    out["forward_selection"] = curve

    # (e) redundancy among the top-30 by gain
    top = list(gain.sort_values(ascending=False).index[:30])
    corr = X.loc[S["tr_sub"], top].corr(method="spearman").abs()
    pairs = [(a, b, float(corr.loc[a, b])) for i, a in enumerate(top) for b in top[i + 1:] if corr.loc[a, b] > 0.9]
    out["redundant_pairs_spearman_gt_0.9"] = pairs

    # (f) score compact sets on TEST once (full train, early stopping on val)
    def test_eval(cols):
        m = fit_lgbm(X.loc[S["train"], cols], y[S["train"]], X.loc[S["val"], cols], y[S["val"]], dict(num_leaves=31))
        p = m.predict(X.loc[S["test"], cols], num_iteration=m.best_iteration)
        r = metrics(y[S["test"]], p)
        return {"n_features": len(cols), "features": cols, "roc_auc": r["roc_auc"], "pr_auc": r["pr_auc"],
                "recall_at_fpr_1pct": r["recall_at_fpr_1pct"], "recall_at_fpr_0_1pct": r["recall_at_fpr_0_1pct"],
                "best_iteration": m.best_iteration}
    out["test_compact"] = {}
    for k in sorted({1, 2, 3, 5, 8, 10, 12, 16, args.max_k}):
        if k <= len(chosen):
            out["test_compact"][f"forward_top{k}"] = test_eval(chosen[:k])
            print("TEST", k, {kk: round(v, 4) for kk, v in out["test_compact"][f"forward_top{k}"].items()
                              if isinstance(v, float)}, flush=True)
    out["test_compact"]["all"] = test_eval(all_cols)
    out["seconds"] = time.time() - t0
    save_json(out, "features", f"{args.dataset}_feature_study.json")


if __name__ == "__main__":
    main()
