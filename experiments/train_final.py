"""Train, calibrate, threshold and export the shipped model.

Training data: union of the TRAIN splits of phreshphish (2024-25), fresh26 (2026) and
hannousse (2020), with dataset weights so the huge 2024-25 set does not drown the 2026 one.
Early stopping: union of VAL splits. Calibration + thresholds: union of CAL splits.
Reported: each dataset's TEST split (never used above) + OpenPhish (live, phishing-only).
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import time

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from baselines import EXCLUDE_DEFAULT, load  # noqa: E402
from common import RESULTS, ROOT, metrics, save_json  # noqa: E402
from export_model import export, verify  # noqa: E402
from features import TldEncoder, cached_lexical  # noqa: E402

import lightgbm as lgb  # noqa: E402
from sklearn.isotonic import IsotonicRegression  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.model_selection import StratifiedKFold  # noqa: E402

DATASETS = {"phreshphish": 0.55, "fresh26": 0.35, "hannousse": 0.10}  # share of total training weight

B = lambda yes, no: {"1": yes, "0": no}  # noqa: E731  wording for binary signals (present / absent)
N = lambda tmpl: {"num": tmpl}           # noqa: E731  wording for numeric signals
REASON_TEXT = {
    "tld_logit": N("top-level domain's phishing rate (log-odds {v:.1f})"),
    "private_suffix": B("hosted as a subdomain of a free hosting platform", "not on a free-subdomain hosting platform"),
    "user_content_host": B("on a user-content platform (sites/forms/file sharing)", "not on a user-content platform"),
    "scheme_http": B("uses unencrypted http://", "uses https:// (or no scheme given)"),
    "www_prefix": B("has a 'www.' prefix", "no 'www.' prefix"),
    "is_homepage": B("bare landing page with no path", "has a specific path"),
    "path_len": N("path length {iv} characters"),
    "url_len": N("URL length {iv} characters"),
    "n_slash": N("{iv} slashes in URL"),
    "n_dot": N("{iv} dots in URL"),
    "n_hyphen": N("{iv} hyphens in URL"),
    "host_n_hyphens": N("{iv} hyphens in hostname"),
    "n_sub_labels": N("{iv} subdomain level(s)"),
    "sub_len": N("subdomain length {iv}"),
    "host_len": N("hostname length {iv}"),
    "host_entropy": N("hostname randomness {v:.2f} bits/char"),
    "sld_entropy": N("domain-name randomness {v:.2f} bits/char"),
    "url_entropy": N("URL randomness {v:.2f} bits/char"),
    "path_entropy": N("path randomness {v:.2f} bits/char"),
    "sld_n_digits": N("{iv} digit(s) in domain name"),
    "host_digit_ratio": N("{v:.0%} digits in hostname"),
    "digit_ratio": N("{v:.0%} digits in URL"),
    "special_ratio": N("{v:.0%} special characters"),
    "upper_ratio": N("{v:.0%} upper-case characters"),
    "letter_ratio": N("{v:.0%} letters"),
    "brand_in_sub": B("well-known brand name in the subdomain (impersonation pattern)", "no brand name in subdomain"),
    "brand_in_path": B("well-known brand name in the path", "no brand name in path"),
    "brand_typo": B("look-alike spelling of a well-known brand", "not a brand look-alike"),
    "brand_in_sld_not_equal": B("brand name embedded in an unrelated domain", "no brand embedded in domain"),
    "brand_is_sld": B("domain is a well-known brand's own domain", "not a major brand's own domain"),
    "sus_words_host": N("{iv} credential/payment word(s) in hostname"),
    "sus_words_path": N("{iv} credential/payment word(s) in path"),
    "host_is_ip": B("raw IP address instead of a domain name", "uses a domain name"),
    "shortener": B("URL shortener hides the real destination", "not a URL shortener"),
    "ext_server": B("server-script page (.php/.asp)", "not a .php/.asp page"),
    "ext_page": B("static .html page", "not a static .html page"),
    "n_qmark": N("{iv} '?' in URL"),
    "query_len": N("query string length {iv}"),
    "n_equal": N("{iv} '=' (query parameters)"),
    "n_params": N("{iv} query parameter(s)"),
    "path_depth": N("path depth {iv}"),
    "path_max_seg_len": N("longest path segment {iv} chars"),
    "tld_len": N("top-level domain length {iv}"),
    "host_n_labels": N("{iv} labels in hostname"),
    "sld_len": N("domain-name length {iv}"),
    "domain_age_days_log": N("domain registered about {days} days ago"),
    "days_to_expiry_log": N("domain registration expires in about {days} days"),
    "reg_period_years": N("registered for {v:.1f} year(s)"),
    "days_since_changed_log": N("registration last changed about {days} days ago"),
    "rdap_not_found": B("domain not found in the registry (RDAP)", "domain found in the registry"),
    "rdap_ok": B("registry (RDAP) data available", "registry (RDAP) data unavailable"),
    "dns_resolves": B("domain resolves in DNS", "domain does not resolve in DNS"),
    "dns_nxdomain": B("domain does not exist in DNS (NXDOMAIN)", "domain exists in DNS"),
    "dns_has_mx": B("domain has mail (MX) records", "domain has no mail (MX) records"),
    "dns_n_ns": N("{iv} nameserver(s)"),
    "dns_n_a": N("{iv} IPv4 address(es)"),
    "dns_ttl_a_log": N("DNS TTL about {days} seconds"),
    "status_hold": B("registry has put the domain on hold", "no registry hold"),
}


def publishable_tld_table(table, tlds, groups):
    """Drop domain-ending keys that stand for a single site before they are used or shipped.

    Public Suffix List wildcard rules (e.g. '*.code.run') make a whole deployment host its own 'public
    suffix', so a raw table would carry training hostnames inside the published model. Kept: bare TLDs,
    the IP key '', literal PSL rules, and wildcard-derived suffixes seen on at least two registrable
    domains in training. Applied before the feature is computed, so training and serving stay identical."""
    from fraudurl.psl import _load as psl_rules
    literal = {k.split(":", 1)[1] for k, (kind, _) in psl_rules().items() if kind == "normal"}
    sites = collections.defaultdict(set)
    for t, g in zip(tlds, groups):
        sites[str(t)].add(g)
    return {k: v for k, v in table.items() if "." not in k or k in literal or len(sites.get(k, ())) >= 2}


def build(feature_list=None, extra=None):
    frames = []
    for name, share in DATASETS.items():
        df = load(name)
        lex = cached_lexical(name, df.url.values)
        lex["_dataset"] = name
        lex["_y"] = df.label.values
        lex["_split"] = df.split.values
        lex["_url"] = df.url.values
        lex["_group"] = df.group.values  # registrable domain (the split unit)
        frames.append(lex)
    allx = pd.concat(frames, ignore_index=True)
    cols = feature_list or [c for c in allx.columns if not c.startswith("_") and c not in EXCLUDE_DEFAULT]
    tr = (allx._split == "train").values
    enc = TldEncoder().fit(allx["_tld"][tr], allx["_y"][tr])
    enc.table = publishable_tld_table(enc.table, allx["_tld"][tr], allx["_group"][tr])
    X = allx[[c for c in cols if c != "tld_logit"]].copy()
    if "tld_logit" in cols or feature_list is None:
        X["tld_logit"] = enc.logit(allx["_tld"])
    w = np.zeros(len(allx))
    for name, share in DATASETS.items():
        m = (allx._dataset == name).values & tr
        w[m] = share / m.sum() * tr.sum()
    return allx, X, enc, w


def fit(X, y, w, tr, va, params, rounds, names=None):
    p = dict(objective="binary", learning_rate=0.08, num_leaves=15, min_data_in_leaf=50, feature_fraction=0.9,
             bagging_fraction=0.8, bagging_freq=1, lambda_l2=1.0, verbose=-1, num_threads=4, seed=0)
    p.update(params)
    # feature names are REQUIRED: the shipped runtime looks features up by name
    dtr = lgb.Dataset(X[tr], y[tr], weight=w[tr], feature_name=list(names), free_raw_data=False)
    dva = lgb.Dataset(X[va], y[va], reference=dtr)
    return lgb.train(p, dtr, rounds, valid_sets=[dva], callbacks=[lgb.early_stopping(50, verbose=False)])


def choose_calibration(raw_cal, y_cal):
    """Platt vs isotonic, compared by 5-fold CV log loss on the CAL split only."""
    res = {"platt": [], "isotonic": []}
    for a, b in StratifiedKFold(5, shuffle=True, random_state=0).split(raw_cal, y_cal):
        pl = LogisticRegression(C=1e6).fit(raw_cal[a, None], y_cal[a])
        p = np.clip(pl.predict_proba(raw_cal[b, None])[:, 1], 1e-6, 1 - 1e-6)
        res["platt"].append(-np.mean(y_cal[b] * np.log(p) + (1 - y_cal[b]) * np.log(1 - p)))
        iso = IsotonicRegression(out_of_bounds="clip", y_min=1e-4, y_max=1 - 1e-4).fit(raw_cal[a], y_cal[a])
        p = np.clip(iso.predict(raw_cal[b]), 1e-6, 1 - 1e-6)
        res["isotonic"].append(-np.mean(y_cal[b] * np.log(p) + (1 - y_cal[b]) * np.log(1 - p)))
    return {k: float(np.mean(v)) for k, v in res.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", help="JSON list of feature names (default: all lexical)")
    ap.add_argument("--rounds", type=int, default=400)
    ap.add_argument("--leaves", type=int, default=15)
    ap.add_argument("--tag", default="safe")
    ap.add_argument("--target-fpr", type=float, default=0.01, help="max share of legit URLs labelled FRAUD (cal)")
    ap.add_argument("--target-fnr", type=float, default=0.02, help="max share of phishing labelled LEGITIMATE (cal)")
    args = ap.parse_args()
    feats = json.load(open(args.features)) if args.features else None
    allx, X, enc, w = build(feats)
    y = allx._y.values.astype(int)
    S = {s: (allx._split == s).values for s in ("train", "val", "cal", "test")}
    t = time.time()
    booster = fit(X.values, y, w, S["train"], S["val"], dict(num_leaves=args.leaves), args.rounds, names=X.columns)
    assert booster.feature_name() == list(X.columns)
    train_s = time.time() - t
    raw = booster.predict(X.values, raw_score=True)
    # CAL rows are weighted like training (each dataset contributes its share), otherwise the huge
    # 2024-25 set would decide calibration and thresholds alone.
    wc = np.zeros(len(allx))
    for name, share in DATASETS.items():
        mm = (allx._dataset == name).values & S["cal"]
        wc[mm] = share / mm.sum()
    cal_cmp = choose_calibration(raw[S["cal"]], y[S["cal"]])
    kind = min(cal_cmp, key=cal_cmp.get)
    if kind == "platt":
        pl = LogisticRegression(C=1e6).fit(raw[S["cal"], None], y[S["cal"]], sample_weight=wc[S["cal"]])
        calib = {"type": "platt", "a": float(pl.coef_[0, 0]), "b": float(pl.intercept_[0])}
        prob = pl.predict_proba(raw[:, None])[:, 1]
    else:
        iso = IsotonicRegression(out_of_bounds="clip", y_min=1e-4, y_max=1 - 1e-4).fit(
            raw[S["cal"]], y[S["cal"]], sample_weight=wc[S["cal"]])
        xs, ys = iso.X_thresholds_.tolist(), iso.y_thresholds_.tolist()
        calib = {"type": "isotonic", "x": xs, "y": ys}
        prob = iso.predict(raw)

    # dataset-weighted error rates on CAL for every candidate threshold (vectorised: sorted scores + binary search)
    grid = np.unique(prob[S["cal"]])
    fpr_w, fnr_w = np.zeros(len(grid)), np.zeros(len(grid))
    for name, share in DATASETS.items():
        dm = (allx._dataset == name).values & S["cal"]
        neg, pos = np.sort(prob[dm & (y == 0)]), np.sort(prob[dm & (y == 1)])
        fpr_w += share * (1 - np.searchsorted(neg, grid, side="left") / len(neg))   # legit with p >= t
        fnr_w += share * (np.searchsorted(pos, grid, side="right") / len(pos))      # phishing with p <= t
    t_fraud = float(grid[np.argmax(fpr_w <= args.target_fpr)])
    t_legit = float(grid[np.where(fnr_w <= args.target_fnr)[0].max()])
    t_legit = min(t_legit, t_fraud)
    base_rate = float(np.sum(wc[S["cal"]] * y[S["cal"]]) / np.sum(wc[S["cal"]]))
    meta = {"version": 1, "tag": args.tag, "trained_on": {k: v for k, v in DATASETS.items()},
            "n_train": int(S["train"].sum()), "n_trees": booster.num_trees(), "leaves": args.leaves,
            "calibration": kind, "calibration_cv_logloss": cal_cmp, "calibration_base_rate": base_rate,
            "calibration_and_thresholds": "CAL splits weighted by dataset share (same as training)",
            "threshold_targets": {"fpr": args.target_fpr, "fnr": args.target_fnr},
            "created": time.strftime("%Y-%m-%d")}
    fp = os.path.join(ROOT, "fraudurl", "data", f"model_{args.tag}.json")
    tld_table = dict(enc.table)  # full precision (rounding caused train/serve skew)
    export(booster, fp, calib, {"fraud": t_fraud, "legit": t_legit}, meta, tld_table, enc.prior,
           {k: v for k, v in REASON_TEXT.items() if k in X.columns})
    diff = verify(booster, fp, X.values[S["test"]][:3000])
    # END-TO-END check through the shipped code path: raw URL -> extract() -> Model -> probability
    from fraudurl.lexical import extract as _extract
    from fraudurl.model import Model as _Model
    _m = _Model(fp)
    idx = np.where(S["test"])[0][:: max(1, S["test"].sum() // 3000)][:3000]
    e2e = np.array([_m.calibrate(_m.raw(_m.vector(_extract(u)))) for u in allx._url.values[idx]])
    e2e_diff = float(np.max(np.abs(e2e - prob[idx])))
    print("end-to-end max |p diff| (shipped runtime vs training pipeline):", e2e_diff, flush=True)
    assert e2e_diff < 1e-3, "shipped runtime disagrees with the training pipeline"
    # ---- evaluation on each dataset's untouched TEST split
    rep = {"meta": meta, "model_file": os.path.relpath(fp, ROOT).replace(os.sep, "/"), "model_bytes": os.path.getsize(fp), "train_seconds": train_s,
           "pure_python_max_abs_diff": diff, "end_to_end_max_abs_prob_diff": e2e_diff, "thresholds": {"fraud": t_fraud, "legit": t_legit}, "test": {}}
    for name in DATASETS:
        m = S["test"] & (allx._dataset == name).values
        yy, pp = y[m], prob[m]
        r = metrics(yy, pp, 0.5)
        three = {"FRAUD": pp >= t_fraud, "LEGITIMATE": pp <= t_legit}
        three["REVIEW"] = ~(three["FRAUD"] | three["LEGITIMATE"])
        tri = {k: {"n": int(v.sum()), "share": float(v.mean()),
                   "phishing_share_within": float(yy[v].mean()) if v.any() else None} for k, v in three.items()}
        tri["legit_flagged_FRAUD_rate"] = float(three["FRAUD"][yy == 0].mean())
        tri["phish_called_LEGITIMATE_rate"] = float(three["LEGITIMATE"][yy == 1].mean())
        rep["test"][name] = {"metrics_at_0.5": r, "three_way": tri}
        print(name, {k: round(r[k], 4) for k in ("roc_auc", "pr_auc", "recall_at_fpr_1pct", "fpr", "fnr", "ece", "brier")},
              "| FRAUD/REVIEW/LEGIT shares", {k: round(v["share"], 3) for k, v in tri.items() if isinstance(v, dict)},
              "| legit->FRAUD", round(tri["legit_flagged_FRAUD_rate"], 4), "phish->LEGIT", round(tri["phish_called_LEGITIMATE_rate"], 4),
              flush=True)
    # ---- external test sets (different collections; never used for training or calibration)
    seen_groups = set()
    for name in DATASETS:
        d = load(name)
        seen_groups |= set(d.group[d.split.isin(["train", "val", "cal"])])
    to_prob = (lambda r: pl.predict_proba(r[:, None])[:, 1]) if kind == "platt" else (lambda r: iso.predict(r))
    rep["external"] = {}
    for name in ("ariyadasa", "jpcert_recent", "openphish26", "tranco_home"):
        fpx = os.path.join(ROOT, "data", "processed", f"{name}.csv")
        if not os.path.exists(fpx):
            continue
        d = pd.read_csv(fpx, dtype={"url": str})
        lx = cached_lexical(name, d.url.values)
        Xe = lx[[c for c in X.columns if c != "tld_logit"]].copy()
        if "tld_logit" in X.columns:
            Xe["tld_logit"] = enc.logit(lx["_tld"])
        Xe = Xe[X.columns]
        pe = to_prob(booster.predict(Xe.values, raw_score=True))
        unseen = ~d.group.isin(seen_groups).values
        ye = d.label.values
        v = {"n": int(len(d)), "n_unseen_domains": int(unseen.sum()),
             "FRAUD_share": float((pe[unseen] >= t_fraud).mean()),
             "LEGITIMATE_share": float((pe[unseen] <= t_legit).mean())}
        v["REVIEW_share"] = 1 - v["FRAUD_share"] - v["LEGITIMATE_share"]
        if ye.min() != ye.max():
            r = metrics(ye[unseen], pe[unseen])
            v["metrics_at_0.5"] = r
            v["legit_flagged_FRAUD_rate"] = float((pe[unseen & (ye == 0)] >= t_fraud).mean())
            v["phish_called_LEGITIMATE_rate"] = float((pe[unseen & (ye == 1)] <= t_legit).mean())
        rep["external"][name] = v
        print("EXTERNAL", name, {k: (round(x, 4) if isinstance(x, float) else x) for k, x in v.items() if k != "metrics_at_0.5"},
              {k: round(v["metrics_at_0.5"][k], 4) for k in ("roc_auc", "recall_at_fpr_1pct", "ece")} if "metrics_at_0.5" in v else "", flush=True)
    os.makedirs(os.path.join(RESULTS, "final"), exist_ok=True)
    np.savez_compressed(os.path.join(RESULTS, "final", f"preds_{args.tag}.npz"),
                        prob=prob, raw=raw, y=y, split=allx._split.values, dataset=allx._dataset.values, url=allx._url.values)
    save_json(rep, "final", f"final_{args.tag}.json")
    print("model", fp, os.path.getsize(fp) / 1024, "KB", "trees", booster.num_trees(), "calibration", kind, cal_cmp,
          "thresholds", t_legit, t_fraud, "verify", diff, flush=True)


if __name__ == "__main__":
    main()
