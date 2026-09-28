"""How should DNS/RDAP be combined with the URL model? (fresh26e, grouped 5-fold CV)

A) single LightGBM on lexical + enrichment, trained on the 8k enriched URLs only
B) stacker: base = URL model trained on PhreshPhish + Hannousse (never saw fresh26), its raw
   score + enrichment features -> small LightGBM
Existence features (NXDOMAIN, registry not-found, registry hold) are excluded: they mostly
reflect takedowns between first-seen and lookup, and would flag dead-but-legit links.
"""
from __future__ import annotations

import math
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from baselines import EXCLUDE_DEFAULT, load  # noqa: E402
from common import DATA, metrics, save_json  # noqa: E402
from features import TldEncoder, cached_lexical  # noqa: E402

import lightgbm as lgb  # noqa: E402
from sklearn.model_selection import GroupKFold  # noqa: E402

# 'days since last registry change' and the registry status count are measured at lookup time and
# partly record takedown actions against phishing domains (leakage) -> not used.
ENRICH = ["dns_n_a", "dns_has_aaaa", "dns_has_cname", "dns_ttl_a_log", "dns_private_ip", "dns_n_ns", "dns_has_mx",
          "domain_age_days_log", "days_to_expiry_log", "reg_period_years"]


def base_model(cols):
    frames, ys = [], []
    for name in ("phreshphish", "hannousse"):
        df = load(name)
        lx = cached_lexical(name, df.url.values)
        lx["_y"], lx["_s"] = df.label.values, df.split.values
        frames.append(lx)
    a = pd.concat(frames, ignore_index=True)
    tr, va = (a._s == "train").values, (a._s == "val").values
    enc = TldEncoder().fit(a["_tld"][tr], a["_y"][tr])
    X = a[cols].copy(); X["tld_logit"] = enc.logit(a["_tld"])
    p = dict(objective="binary", learning_rate=0.08, num_leaves=15, min_data_in_leaf=50, feature_fraction=0.9,
             bagging_fraction=0.8, bagging_freq=1, lambda_l2=1.0, verbose=-1, num_threads=4, seed=0)
    dtr = lgb.Dataset(X[tr], a._y[tr]); dva = lgb.Dataset(X[va], a._y[va], reference=dtr)
    m = lgb.train(p, dtr, 400, valid_sets=[dva], callbacks=[lgb.early_stopping(50, verbose=False)])
    return m, enc


def enrich_frame(name, df):
    from fraudurl.enrich import _parse_dt
    E = pd.read_pickle(os.path.join(DATA, "processed", f"enrich_{name}.pkl")).reset_index(drop=True)
    seen = pd.to_datetime(df.date, errors="coerce", utc=True)
    ages = []
    for c, d in zip([_parse_dt(c) for c in E.rdap_created], seen):
        ages.append(np.nan if (c is None or pd.isna(d)) else math.log10(1 + max(0, (d.to_pydatetime() - c).days)))
    E["domain_age_days_log"] = ages  # age when the URL was seen (= "now" at deployment)
    # expiry, like age, measured from the day the URL was seen
    exp = []
    for c, d in zip(E.get("rdap_expires", [None] * len(E)), seen):
        c = _parse_dt(c)
        exp.append(np.nan if (c is None or pd.isna(d)) else math.log10(1 + max(0, (c - d.to_pydatetime()).days)))
    E["days_to_expiry_log"] = exp
    return E


def cv(X, y, g, params, rounds):
    oof = np.zeros(len(y))
    for tr, te in GroupKFold(5).split(X, y, g):
        m = lgb.train(params, lgb.Dataset(X.iloc[tr], y[tr]), rounds)
        oof[te] = m.predict(X.iloc[te])
    r = metrics(y, oof)
    return {k: r[k] for k in ("roc_auc", "pr_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct", "log_loss")}, oof


def main():
    df = load("fresh26e").reset_index(drop=True)
    y, g = df.label.values, df.group.values
    lx = cached_lexical("fresh26e", df.url.values)
    cols = [c for c in lx.columns if not c.startswith("_") and c not in EXCLUDE_DEFAULT]
    E = enrich_frame("fresh26e", df)
    bm, enc = base_model(cols)
    Xb = lx[cols].copy(); Xb["tld_logit"] = enc.logit(lx["_tld"])
    base_raw = bm.predict(Xb, raw_score=True)
    live = (E.dns_resolves == 1).values
    P = dict(objective="binary", learning_rate=0.05, num_leaves=15, min_data_in_leaf=20, feature_fraction=0.8,
             bagging_fraction=0.8, bagging_freq=1, verbose=-1, num_threads=4, seed=0)
    PS = dict(P, num_leaves=7, min_data_in_leaf=40)
    out = {}
    for view, m in (("all", np.ones(len(y), bool)), ("live_only", live)):
        Xl = Xb[m].reset_index(drop=True)
        XA = pd.concat([Xl, E.loc[m, ENRICH].reset_index(drop=True)], axis=1)
        XB = pd.concat([pd.DataFrame({"base_raw": base_raw[m]}), E.loc[m, ENRICH].reset_index(drop=True)], axis=1)
        r = {"base_url_model_alone": {k: v for k, v in metrics(y[m], base_raw[m]).items()
                                      if k in ("roc_auc", "pr_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct")},
             "A_single_lgbm_lexical+enrich": cv(XA, y[m], g[m], P, 400)[0],
             "A0_single_lgbm_lexical_only": cv(Xl, y[m], g[m], P, 400)[0],
             "B_stack_base+enrich": cv(XB, y[m], g[m], PS, 300)[0]}
        out[view] = r
        for k, v in r.items():
            print(view, k, {a: round(b, 4) for a, b in v.items()}, flush=True)
    save_json(out, "enrichment", "enrich_model_study.json")


if __name__ == "__main__":
    main()
