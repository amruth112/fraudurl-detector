"""Train the optional ENRICHED model: residual boosting on top of the shipped safe model.

  enriched_raw = safe_raw(URL features) + residual_raw(DNS/RDAP features)

* The residual model sees only 12 DNS/RDAP features and is trained with LightGBM init_score =
  the safe model's OUT-OF-FOLD raw score (cross-fitting: 5 safe models, each trained without one
  fold of the fresh26e domains), so it learns only what enrichment adds.
* Existence signals (NXDOMAIN, registry not-found, registry hold) are deliberately excluded:
  they mostly measure takedowns between first-seen and lookup and would flag dead legit links.
* If enrichment is unavailable for a URL at run time, the CLI uses the safe model alone.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RESULTS, ROOT, metrics, save_json  # noqa: E402
from enrich_model_study import ENRICH, enrich_frame  # noqa: E402
from export_model import booster_to_trees  # noqa: E402
from train_final import DATASETS, REASON_TEXT, build, fit  # noqa: E402
from baselines import load  # noqa: E402
from features import cached_lexical  # noqa: E402

import lightgbm as lgb  # noqa: E402
from sklearn.isotonic import IsotonicRegression  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.model_selection import GroupKFold  # noqa: E402

# Domain knowledge as constraints: all else equal, an older domain, a longer registration period and
# a later expiry must never RAISE risk (keeps the model and its explanations sensible).
_MONO = {"domain_age_days_log": -1, "reg_period_years": -1, "days_to_expiry_log": -1}
PR = dict(objective="binary", learning_rate=0.05, num_leaves=7, min_data_in_leaf=40, feature_fraction=0.9,
          bagging_fraction=0.8, bagging_freq=1, lambda_l2=5.0, verbose=-1, num_threads=4, seed=0,
          monotone_constraints=[_MONO.get(f, 0) for f in ENRICH], monotone_constraints_method="advanced")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", help="JSON list of safe-model features (same as train_final)")
    ap.add_argument("--rounds", type=int, default=400)
    ap.add_argument("--leaves", type=int, default=15)
    ap.add_argument("--resid-rounds", type=int, default=150)
    ap.add_argument("--target-fpr", type=float, default=0.01)
    ap.add_argument("--target-fnr", type=float, default=0.02)
    args = ap.parse_args()
    feats = json.load(open(args.features)) if args.features else None
    allx, X, enc, w = build(feats)
    y_all = allx._y.values.astype(int)
    S = {s: (allx._split == s).values for s in ("train", "val")}
    fe = load("fresh26e").reset_index(drop=True)
    E = enrich_frame("fresh26e", fe)
    y, g = fe.label.values, fe.group.values
    # map fresh26e rows to rows of the union frame (fresh26e urls are a subset of fresh26)
    fr_mask = (allx._dataset == "fresh26").values
    pos = pd.Series(np.where(fr_mask)[0], index=allx._url.values[fr_mask])
    rows = pos.loc[fe.url.values].values
    folds = list(GroupKFold(5).split(fe, y, g))
    oof_base = np.zeros(len(fe))
    # registrable domain of every training row (build() concatenates datasets in DATASETS order)
    grp_all = np.concatenate([load(name).group.values for name in DATASETS])
    assert len(grp_all) == len(allx)
    for k, (_, te) in enumerate(folds):
        held = set(g[te])
        # the fold's domains are removed from the training rows of EVERY dataset, not only fresh26
        tr = S["train"] & ~pd.Series(grp_all).isin(held).values
        b = fit(X.values, y_all, w, tr, S["val"], dict(num_leaves=args.leaves), args.rounds, names=X.columns)
        oof_base[te] = b.predict(X.values[rows[te]], raw_score=True)
        print(f"cross-fit fold {k}: base trained without {len(held)} held-out domains", flush=True)
    # Only domains that currently resolve: a dead domain says nothing about a live site and
    # "0 addresses" would smuggle the takedown signal back in. Dead domains -> safe model at run time.
    live = (E.dns_resolves == 1).values
    # ...and not on shared platforms (the CLI never enriches those: domain data describes the platform)
    lx = cached_lexical("fresh26e", fe.url.values)
    platform = ((lx.private_suffix > 0) | (lx.user_content_host > 0) | (lx.shortener > 0)).values
    keep = live & ~platform
    rep_counts = {"live": int(live.sum()), "platform_excluded": int((live & platform).sum()), "kept": int(keep.sum())}
    print("rows", rep_counts, flush=True)
    fe, E, y, g, oof_base = fe[keep].reset_index(drop=True), E[keep].reset_index(drop=True), y[keep], g[keep], oof_base[keep]
    Z = E[ENRICH].astype(float)
    folds = list(GroupKFold(5).split(Z, y, g))
    oof_comb = np.zeros(len(fe))
    for tr, te in folds:
        m = lgb.train(PR, lgb.Dataset(Z.iloc[tr], y[tr], init_score=oof_base[tr]), args.resid_rounds)
        oof_comb[te] = oof_base[te] + m.predict(Z.iloc[te], raw_score=True)
    rep = {"n_live_non_platform": len(fe), "phish_share": float(y.mean()), "row_counts": rep_counts}
    a, c = metrics(y, oof_base), metrics(y, oof_comb)
    keys = ("roc_auc", "pr_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct", "log_loss")
    rep["live_only"] = {"safe_only_uncalibrated": {k: a[k] for k in keys[:4]},
                        "safe+enrichment_uncalibrated": {k: c[k] for k in keys[:4]}}
    print("live_only", rep["live_only"], flush=True)
    # final residual model on all fresh26e, calibration + thresholds from OOF combined scores
    final = lgb.train(PR, lgb.Dataset(Z, y, init_score=oof_base, feature_name=list(ENRICH)), args.resid_rounds)
    iso = IsotonicRegression(out_of_bounds="clip", y_min=1e-4, y_max=1 - 1e-4).fit(oof_comb, y)
    pl = LogisticRegression(C=1e6).fit(oof_comb[:, None], y)
    # choose by 5-fold CV log loss on the OOF scores
    from train_final import choose_calibration
    cmp = choose_calibration(oof_comb, y)
    kind = min(cmp, key=cmp.get)
    prob = iso.predict(oof_comb) if kind == "isotonic" else pl.predict_proba(oof_comb[:, None])[:, 1]
    calib = ({"type": "isotonic", "x": iso.X_thresholds_.tolist(), "y": iso.y_thresholds_.tolist()} if kind == "isotonic"
             else {"type": "platt", "a": float(pl.coef_[0, 0]), "b": float(pl.intercept_[0])})
    # Report enriched probabilities at the SAME reference prevalence as the safe model (its calibration
    # data is ~17% phishing vs ~47%): shift the calibrated log-odds. Monotone -> error rates unchanged.
    pi_e = float(y.mean())
    pi_s = json.load(open(os.path.join(ROOT, "fraudurl", "data", "model_safe.json")))["meta"]["calibration_base_rate"]
    shift = float(np.log(pi_s / (1 - pi_s)) - np.log(pi_e / (1 - pi_e)))
    if kind == "platt":
        calib["b"] += shift
    else:
        calib["y"] = [float(1 / (1 + np.exp(-(np.log(v / (1 - v)) + shift)))) for v in calib["y"]]
    prob = 1 / (1 + np.exp(-(np.log(np.clip(prob, 1e-9, 1 - 1e-9) / (1 - np.clip(prob, 1e-9, 1 - 1e-9))) + shift)))
    neg = np.sort(prob[y == 0])[::-1]
    t_fraud = float(neg[int(np.floor(args.target_fpr * len(neg)))]) + 1e-9
    pos_ = np.sort(prob[y == 1])
    t_legit = min(float(pos_[int(np.floor(args.target_fnr * len(pos_)))]) - 1e-9, t_fraud)
    names, trees = booster_to_trees(final)
    obj = {"meta": {"version": 1, "tag": "enrich", "kind": "residual_on_safe", "base_model": "model_safe.json",
                    "trained_on": "fresh26e URLs whose domain resolved and that are not on shared platforms (live DNS/RDAP 2026-09-25)", "calibration": kind,
                    "calibration_cv_logloss": cmp, "calibration_base_rate": pi_s,
                    "calibration_prior_shift": {"from_base_rate": pi_e, "to_base_rate": pi_s, "logit_shift": shift},
                    "threshold_targets": {"fpr": args.target_fpr, "fnr": args.target_fnr}},
           "features": names, "init_score": 0.0, "trees": trees, "calibration": calib,
           "thresholds": {"fraud": t_fraud, "legit": t_legit}, "tld_table": {}, "tld_prior": 0.5,
           "reason_text": {k: v for k, v in REASON_TEXT.items() if k in names}}
    fp = os.path.join(ROOT, "fraudurl", "data", "model_enrich.json")
    with open(fp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, separators=(",", ":"))
    rep.update({"model_file": os.path.relpath(fp, ROOT).replace(os.sep, "/"), "model_bytes": os.path.getsize(fp), "calibration": kind,
                "thresholds": obj["thresholds"], "n_trees": final.num_trees()})
    save_json(rep, "final", "final_enrich.json")
    print("wrote", fp, os.path.getsize(fp) // 1024, "KB", kind, obj["thresholds"], flush=True)


if __name__ == "__main__":
    main()
