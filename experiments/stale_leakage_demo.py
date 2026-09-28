"""Demonstrate why DNS/RDAP enrichment must NOT be evaluated on old datasets.

Resolve (today) a random sample of hosts from PhreshPhish (collected 2024-25). Phishing
domains get taken down within days/weeks, benign ones keep resolving, so "does not resolve
today" would look like a superb phishing signal while telling us nothing about new URLs.
"""
from __future__ import annotations

import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import DATA, metrics, save_json  # noqa: E402
from fraudurl.enrich import Enricher, dns_features  # noqa: E402
from fraudurl.lexical import ParsedURL  # noqa: E402


def main(n=500):
    df = pd.read_csv(os.path.join(DATA, "processed", "phreshphish.csv"), usecols=["url", "label", "tsplit", "date"])
    df = df[df.tsplit == "test"]  # the newest part (Sep-Dec 2025)
    s = pd.concat([g.sample(n, random_state=1) for _, g in df.groupby("label")])
    ps = [ParsedURL(u) for u in s.url]
    e = Enricher(os.path.join(DATA, "cache"), rdap=False, workers=32)
    dns_r, _ = e.run([(p.host, p.reg, p.ip, p.private_suffix) for p in ps])
    e.close()
    s["a_status"] = [(dns_r.get(p.host) or {}).get("a_status", "skip") for p in ps]
    s["resolves"] = [dns_features(dns_r.get(p.host)).get("dns_resolves", float("nan")) for p in ps]
    tab = pd.crosstab(s.a_status, s.label, normalize="columns").round(3)
    ok = s.resolves.notna()
    auc = metrics(s.label[ok].values, 1 - s.resolves[ok].values)["roc_auc"]
    out = {"n_per_class": n, "status_share_by_label": tab.to_dict(),
           "roc_auc_of_single_feature_does_not_resolve_today": auc}
    print(tab.to_string(), "\nAUC of 'does not resolve today' alone:", round(auc, 3))
    save_json(out, "enrichment", "stale_leakage_demo_phreshphish.json")


if __name__ == "__main__":
    main()
