"""Vectorise lexical features for a dataset (parallel, cached) + train-only TLD encoding."""
from __future__ import annotations

import math
import os
import sys
from concurrent.futures import ProcessPoolExecutor

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from fraudurl import lexical as lx  # noqa: E402

PROC = os.path.join(ROOT, "data", "processed")


def _chunk(urls):
    out = []
    for u in urls:
        f = lx.extract(u)
        out.append(f)
    return out


def lexical_frame(urls, workers=4, chunk=5000) -> pd.DataFrame:
    urls = list(urls)
    parts = [urls[i:i + chunk] for i in range(0, len(urls), chunk)]
    rows = []
    if workers > 1 and len(parts) > 1:
        with ProcessPoolExecutor(workers) as ex:
            for r in ex.map(_chunk, parts):
                rows.extend(r)
    else:
        for p in parts:
            rows.extend(_chunk(p))
    df = pd.DataFrame(rows)
    df["_tld"] = df["_tld"].fillna("")
    num = [c for c in df.columns if not c.startswith("_")]
    df[num] = df[num].astype(np.float64)  # float64: identical to the runtime (float32 caused skew)
    return df


def _feature_code_hash() -> str:
    import hashlib
    h = hashlib.sha1()
    for f in ("lexical.py", "psl.py"):
        h.update(open(os.path.join(ROOT, "fraudurl", f), "rb").read())
    return h.hexdigest()[:10]


def cached_lexical(name: str, urls, workers=4) -> pd.DataFrame:
    """Features are cached per dataset AND per version of the feature code, so a stale cache can
    never be reused after the parser/features change."""
    os.makedirs(PROC, exist_ok=True)
    fp = os.path.join(PROC, f"lex_{name}_{_feature_code_hash()}.pkl")
    if os.path.exists(fp):
        df = pd.read_pickle(fp)
        if len(df) == len(urls):
            return df
    df = lexical_frame(urls, workers)
    df.to_pickle(fp)
    return df


def canon_text(u: str) -> str:
    """Text given to character-level models: fragment dropped, missing scheme -> https://
    (the same artifact-neutralising rules the lexical features use)."""
    u = str(u).strip().split("#", 1)[0]
    if "://" not in u[:12]:
        u = "https://" + u.lstrip("/")
    return u


class TldEncoder:
    """Hierarchically smoothed phishing rate per public suffix, fitted on TRAINING rows only.

    rate(suffix) is shrunk toward rate(last label of the suffix), which is shrunk toward the
    global rate (m pseudo-counts at each level). ``table`` holds both levels, keyed by the full
    suffix ("gov.br") and by the bare TLD ("br"); lookups fall back suffix -> TLD -> prior.
    The shipped runtime (fraudurl.model) uses exactly the same table and fallback."""

    def __init__(self, m: float = 20.0):
        self.m, self.table, self.prior = m, {}, 0.5

    def fit(self, tlds, y):
        s = pd.DataFrame({"t": [str(t) for t in tlds], "y": np.asarray(y, float)})
        s["top"] = s.t.str.rsplit(".", n=1).str[-1]
        self.prior = float(s.y.mean())
        g1 = s.groupby("top").y.agg(["sum", "count"])
        top = {t: float((r["sum"] + self.m * self.prior) / (r["count"] + self.m)) for t, r in g1.iterrows()}
        g2 = s.groupby("t").y.agg(["sum", "count"])
        full = {}
        for t, r in g2.iterrows():
            parent = top.get(t.rsplit(".", 1)[-1], self.prior)
            full[t] = float((r["sum"] + self.m * parent) / (r["count"] + self.m))
        self.table = {**top, **full}  # full-suffix entries override same-named TLD entries
        return self

    def rate(self, t):
        t = str(t)
        v = self.table.get(t)
        if v is None:
            v = self.table.get(t.rsplit(".", 1)[-1], self.prior)
        return v

    def transform(self, tlds):
        return np.array([self.rate(t) for t in tlds], dtype=np.float64)

    def logit(self, tlds):
        p = np.clip(self.transform(tlds), 1e-4, 1 - 1e-4)
        return np.log(p / (1 - p))  # float64, identical to fraudurl.model
