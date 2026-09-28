"""Cross-dataset generalisation: train on dataset A, test on dataset B (different collection
process, different time), restricted to B-domains never seen in A's training data."""
from __future__ import annotations

import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from baselines import EXCLUDE_DEFAULT, fit_lgbm, load  # noqa: E402
from common import metrics, save_json  # noqa: E402
from features import TldEncoder, cached_lexical, canon_text  # noqa: E402

from sklearn.feature_extraction.text import HashingVectorizer  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402


def frame(name, cols=None):
    df = load(name)
    lex = cached_lexical(name, df.url.values)
    return df, lex


def run(a, b, feature_sets, char=True, max_train=150000):
    da, la = frame(a)
    db, lb = frame(b)
    tr = (da.split == "train").values
    va = (da.split == "val").values
    if tr.sum() > max_train:
        idx = np.where(tr)[0]
        keep = np.random.default_rng(0).choice(idx, max_train, replace=False)
        tr = np.zeros(len(da), bool); tr[keep] = True
    seen = set(da.group[tr | va])
    unseen = ~db.group.isin(seen).values
    enc = TldEncoder().fit(la["_tld"][tr], da.label[tr])
    res = {"train": a, "test": b, "n_train": int(tr.sum()), "n_test_all": len(db), "n_test_unseen_domains": int(unseen.sum())}
    for fs_name, cols in feature_sets.items():
        cols = [c for c in cols if c != "tld_logit"] if cols else [c for c in la.columns if not c.startswith("_") and c not in EXCLUDE_DEFAULT]
        Xa = la[cols].copy(); Xa["tld_logit"] = enc.logit(la["_tld"])
        Xb = lb[cols].copy(); Xb["tld_logit"] = enc.logit(lb["_tld"])
        m = fit_lgbm(Xa[tr], da.label.values[tr], Xa[va], da.label.values[va], dict(num_leaves=31))
        p = m.predict(Xb, num_iteration=m.best_iteration)
        yb = db.label.values
        if yb.min() == yb.max():  # phishing-only feed: recall at thresholds fixed on A's val split
            pv = m.predict(Xa[va], num_iteration=m.best_iteration)
            neg = np.sort(pv[da.label.values[va] == 0])[::-1]
            thr1 = neg[int(0.01 * len(neg))]
            res[fs_name] = {"recall_at_0.5": float((p[unseen] >= 0.5).mean()),
                            "recall_at_val_fpr1pct_threshold": float((p[unseen] >= thr1).mean())}
        else:
            res[fs_name] = {"unseen_domains": metrics(yb[unseen], p[unseen]), "all": metrics(yb, p)}
        print(a, "->", b, fs_name, {k: round(v, 4) for k, v in (res[fs_name].get("unseen_domains") or res[fs_name]).items()
                                     if k in ("roc_auc", "pr_auc", "recall_at_fpr_1pct", "fpr", "recall", "recall_at_0.5",
                                              "recall_at_val_fpr1pct_threshold")}, flush=True)
    if char:
        hv = HashingVectorizer(analyzer="char", ngram_range=(3, 5), n_features=2 ** 20, alternate_sign=False)
        lr = LogisticRegression(C=4.0, max_iter=2000, solver="liblinear").fit(hv.transform([canon_text(u) for u in da.url[tr]]), da.label[tr])
        p = lr.predict_proba(hv.transform([canon_text(u) for u in db.url]))[:, 1]
        yb = db.label.values
        if yb.min() == yb.max():
            res["char_ngram_lr"] = {"recall_at_0.5": float((p[unseen] >= 0.5).mean())}
        else:
            res["char_ngram_lr"] = {"unseen_domains": metrics(yb[unseen], p[unseen])}
        print(a, "->", b, "char", res["char_ngram_lr"].get("unseen_domains", res["char_ngram_lr"]).get("roc_auc",
              res["char_ngram_lr"].get("recall_at_0.5")), flush=True)
    return res


if __name__ == "__main__":
    import json
    fs = {"all_lexical": None}
    extra = sys.argv[3] if len(sys.argv) > 3 else None
    if extra:  # compact feature list from the feature study
        fs["compact"] = json.load(open(extra))
    r = run(sys.argv[1], sys.argv[2], fs)
    save_json(r, "cross", f"{sys.argv[1]}__to__{sys.argv[2]}.json")
