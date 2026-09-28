"""Does a domain-popularity signal (Tranco rank of the registrable domain) help, measured only
where it is NOT circular?

Circular: any set whose legitimate URLs were *selected* from Tranco (fresh26's Common Crawl
part, tranco_home). Non-circular evaluations used here:
  * PhreshPhish (benign = Webroot browsing telemetry), domain-grouped test split
  * fresh26 Hacker-News-only legitimate rows vs fresh26 phishing (test split)
  * Ariyadasa 2021 (legit = Google search results), external
Tenants of hosting platforms (x.github.io) have their own registrable domain and are simply
unranked, so they do not inherit the platform's popularity.
"""
from __future__ import annotations

import math
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from baselines import EXCLUDE_DEFAULT, fit_lgbm, load  # noqa: E402
from common import DATA, metrics, save_json  # noqa: E402
from features import TldEncoder, cached_lexical  # noqa: E402
from fraudurl.lexical import ParsedURL  # noqa: E402


def tranco_ranks(max_rank):
    r = {}
    with open(os.path.join(DATA, "raw", "tranco", "top-1m.csv"), encoding="utf-8") as fh:
        for line in fh:
            k, d = line.strip().split(",", 1)
            k = int(k)
            if k > max_rank:
                break
            reg = ParsedURL("http://" + d).reg
            if reg and reg not in r:
                r[reg] = k
    return r


def pop_feats(urls, ranks, max_rank):
    regs = [ParsedURL(u).reg for u in urls]
    rk = np.array([ranks.get(g, 0) for g in regs], float)
    return pd.DataFrame({"pop_rank_log": np.where(rk > 0, np.log10(np.maximum(rk, 1)), math.log10(max_rank) + 1)})


def frame(name, enc=None):
    df = load(name)
    lex = cached_lexical(name, df.url.values)
    cols = [c for c in lex.columns if not c.startswith("_") and c not in EXCLUDE_DEFAULT]
    return df, lex, cols


def main():
    out = {}
    ph, lph, cols = frame("phreshphish")
    tr, va, te = [(ph.split == s).values for s in ("train", "val", "test")]
    enc = TldEncoder().fit(lph["_tld"][tr], ph.label[tr])
    fr, lfr, _ = frame("fresh26")
    ar, lar, _ = frame("ariyadasa")
    hn = (fr.split == "test").values & ((fr.label == 1) | (fr.source == "hackernews_30d")).values
    seen = set(ph.group[tr | va])
    ar_unseen = ~ar.group.isin(seen).values
    for max_rank in (0, 10_000, 100_000, 1_000_000):
        ranks = tranco_ranks(max_rank) if max_rank else {}

        def X(df, lex):
            x = lex[cols].copy()
            x["tld_logit"] = enc.logit(lex["_tld"])
            if max_rank:
                x["pop_rank_log"] = pop_feats(df.url.values, ranks, max_rank).values[:, 0]
            return x
        Xp = X(ph, lph)
        m = fit_lgbm(Xp[tr], ph.label.values[tr], Xp[va], ph.label.values[va], dict(num_leaves=31))
        res = {}
        for nm, df, lex, mask in (("phreshphish_test", ph, lph, te), ("fresh26_test_HN_legit_only", fr, lfr, hn),
                                  ("ariyadasa_unseen", ar, lar, ar_unseen)):
            p = m.predict(X(df, lex)[mask], num_iteration=m.best_iteration)
            r = metrics(df.label.values[mask], p)
            res[nm] = {k: r[k] for k in ("roc_auc", "pr_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct", "ece")}
            res[nm]["n"] = int(mask.sum())
        # how many phishing URLs sit on a ranked (popular) registrable domain?
        if max_rank:
            res["phish_on_ranked_domain_share"] = {
                "phreshphish": float((pop_feats(ph.url[ph.label == 1].values, ranks, max_rank).pop_rank_log <= math.log10(max_rank)).mean()),
                "fresh26": float((pop_feats(fr.url[fr.label == 1].values, ranks, max_rank).pop_rank_log <= math.log10(max_rank)).mean())}
        key = f"tranco_top{max_rank}" if max_rank else "no_popularity"
        out[key] = res
        print(key, {k: (v if not isinstance(v, dict) else {a: round(b, 4) for a, b in v.items()}) for k, v in res.items()}, flush=True)
    save_json(out, "features", "popularity_study.json")


if __name__ == "__main__":
    main()
