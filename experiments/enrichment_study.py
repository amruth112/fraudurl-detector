"""Does domain/DNS/page information add anything over the URL string?

(1) Hannousse 2020: the authors' own external + page features, captured while the phishing
    pages were live (so no dead-domain leakage). Popularity features (web_traffic, page_rank)
    are reported separately: the legitimate class was drawn from popularity lists (circular).
(2) fresh26e (2026): our live DNS + RDAP lookups, taken the same day for both classes.
All comparisons: LightGBM, 5-fold cross-validation grouped by registrable domain.
"""
from __future__ import annotations

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

P = dict(objective="binary", learning_rate=0.05, num_leaves=15, min_data_in_leaf=20, feature_fraction=0.8,
         bagging_fraction=0.8, bagging_freq=1, verbose=-1, num_threads=4, seed=0)


def cv_eval(X, y, groups, rounds=400, drop_at_test=None):
    """Grouped 5-fold CV. The TLD reputation column (if present) is re-fitted on each training fold
    only. drop_at_test: columns set to NaN at prediction time (enrichment unavailable)."""
    oof = np.zeros(len(y))
    X = X.reset_index(drop=True)
    for tr, te in GroupKFold(5).split(X, y, groups):
        X = X.copy()
        if "_tld_key" in X:
            enc = TldEncoder().fit(X["_tld_key"].iloc[tr], y[tr])
            X["tld_logit"] = enc.logit(X["_tld_key"])
        Xf = X.drop(columns=["_tld_key"], errors="ignore")
        m = lgb.train(P, lgb.Dataset(Xf.iloc[tr], y[tr]), rounds)
        Xt = Xf.iloc[te].copy()
        if drop_at_test:
            Xt[drop_at_test] = np.nan
        oof[te] = m.predict(Xt)
    r = metrics(y, oof)
    return {k: r[k] for k in ("roc_auc", "pr_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct", "log_loss")}


def lexical_block(df, name):
    lex = cached_lexical(name, df.url.values)
    cols = [c for c in lex.columns if not c.startswith("_") and c not in EXCLUDE_DEFAULT]
    X = lex[cols].copy()
    X["tld_logit"] = 0.0          # placeholder, re-fitted per training fold in cv_eval
    X["_tld_key"] = lex["_tld"].values
    return X


def hannousse():
    df = load("hannousse")
    y = df.label.values
    X = lexical_block(df, "hannousse")
    h = lambda cols: df[["h_" + c for c in cols]].astype(float).rename(columns=lambda c: c)  # noqa: E731
    domain = ["domain_age", "domain_registration_length", "whois_registered_domain", "dns_record"]
    page = ["nb_hyperlinks", "ratio_intHyperlinks", "ratio_extHyperlinks", "ratio_nullHyperlinks", "nb_extCSS",
            "ratio_intRedirection", "ratio_extRedirection", "ratio_intErrors", "ratio_extErrors", "login_form",
            "external_favicon", "links_in_tags", "submit_email", "ratio_intMedia", "ratio_extMedia", "sfh",
            "iframe", "popup_window", "safe_anchor", "onmouseover", "right_clic", "empty_title",
            "domain_in_title", "domain_with_copyright"]
    reput = ["web_traffic", "page_rank", "google_index"]
    Dm = h(domain).replace({-1: np.nan, -2: np.nan})
    Dm.loc[Dm["h_domain_age"] < 0, "h_domain_age"] = np.nan
    variants = {
        "lexical_only": X,
        "lexical+domain(whois,dns)": pd.concat([X, Dm], axis=1),
        "lexical+page_content": pd.concat([X, h(page)], axis=1),
        "lexical+domain+page": pd.concat([X, Dm, h(page)], axis=1),
        "domain_only": Dm, "page_only": h(page),
        "lexical+domain+page+reputation(CIRCULAR)": pd.concat([X, Dm, h(page), h(reput)], axis=1),
    }
    out = {}
    for k, V in variants.items():
        out[k] = cv_eval(V.reset_index(drop=True), y, df.group.values)
        print("hannousse", k, {a: round(b, 4) for a, b in out[k].items()}, flush=True)
    return out


def fresh(name="fresh26e"):
    df = load(name)
    y = df.label.values
    X = lexical_block(df, name)
    E = pd.read_pickle(os.path.join(DATA, "processed", f"enrich_{name}.pkl"))
    # Age and expiry measured from the day the URL was seen (same code as the shipped model training).
    from enrich_model_study import enrich_frame
    E = enrich_frame(name, df)
    dns_cols = [c for c in E.columns if c.startswith("dns_") and c != "dns_status"]
    # takedown-sensitive registry fields (last-changed date, status flags/count) are excluded (leakage)
    rdap_cols = [c for c in E.columns if c not in dns_cols and c not in (
        "dns_status", "rdap_status", "rdap_created", "rdap_expires", "days_since_changed_log", "status_n", "status_hold")]
    E = E.reset_index(drop=True)
    X = X.reset_index(drop=True)
    variants = {"lexical_only": X, "lexical+dns": pd.concat([X, E[dns_cols]], axis=1),
                "lexical+rdap": pd.concat([X, E[rdap_cols]], axis=1),
                "lexical+dns+rdap": pd.concat([X, E[dns_cols + rdap_cols]], axis=1),
                "dns+rdap_only": E[dns_cols + rdap_cols]}
    out = {}
    for k, V in variants.items():
        out[k] = cv_eval(V, y, df.group.values)
        print(name, k, {a: round(b, 4) for a, b in out[k].items()}, flush=True)
    out["lexical+dns+rdap__but_unavailable_at_test"] = cv_eval(variants["lexical+dns+rdap"], y, df.group.values,
                                                               drop_at_test=dns_cols + rdap_cols)
    # Stricter views. Phishing domains get taken down over time, so 'does not resolve today'
    # partly measures the delay between first-seen and our lookup (stale leakage), not phishing.
    existence = ["dns_resolves", "dns_nxdomain", "dns_ok", "rdap_not_found", "rdap_ok", "status_hold"]
    keep_dns = [c for c in dns_cols if c not in existence]
    keep_rdap = [c for c in rdap_cols if c not in existence]
    live = (E["dns_resolves"] == 1).values
    out["live_only"] = {"n": int(live.sum()), "phish_share": float(y[live].mean()), "removed_features": existence}
    for k, V in (("lexical_only", X), ("lexical+dns+rdap_no_existence", pd.concat([X, E[keep_dns + keep_rdap]], axis=1))):
        out["live_only"][k] = cv_eval(V[live].reset_index(drop=True), y[live], df.group.values[live])
        print(name, "LIVE-ONLY", k, {a: round(b, 4) for a, b in out["live_only"][k].items()}, flush=True)
    recent = ((df.label == 0) | (df.date >= "2026-09-18")).values
    out["recent_phish_7d"] = {"n": int(recent.sum()), "n_phish": int(y[recent].sum())}
    for k in ("lexical_only", "lexical+dns+rdap"):
        out["recent_phish_7d"][k] = cv_eval(variants[k][recent].reset_index(drop=True), y[recent], df.group.values[recent])
        print(name, "RECENT-7D", k, {a: round(b, 4) for a, b in out["recent_phish_7d"][k].items()}, flush=True)
    out["recent_phish_7d"]["dns_status_of_recent_phish"] = E.dns_status[recent & (y == 1)].value_counts(normalize=True).to_dict()
    out["coverage"] = {"rdap_ok_by_label": pd.crosstab(E.rdap_status, df.label).to_dict(),
                       "dns_status_by_label": pd.crosstab(E.dns_status, df.label).to_dict()}
    # per-feature class-conditional summaries (medians) for the report
    desc = {}
    for c in dns_cols + rdap_cols:
        desc[c] = {"legit_median": float(np.nanmedian(E[c][y == 0])) if np.isfinite(E[c][y == 0]).any() else None,
                   "phish_median": float(np.nanmedian(E[c][y == 1])) if np.isfinite(E[c][y == 1]).any() else None,
                   "legit_missing": float(E[c][y == 0].isna().mean()), "phish_missing": float(E[c][y == 1].isna().mean())}
    out["feature_summary"] = desc
    return out


if __name__ == "__main__":
    which = sys.argv[1:] or ["hannousse", "fresh26e"]
    res = {}
    if "hannousse" in which:
        res["hannousse"] = hannousse()
    if "fresh26e" in which:
        res["fresh26e"] = fresh("fresh26e")
    save_json(res, "enrichment", "enrichment_study_" + "_".join(which) + ".json")
