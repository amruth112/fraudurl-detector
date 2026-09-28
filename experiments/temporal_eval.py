"""Strictest in-collection test: PhreshPhish's official TIME split (train <= 2025-09-08, test after)
combined with domain-disjointness (test rows whose registrable domain appears in train are dropped).
Uses the same recipe as the shipped model (all lexical features, 400 trees x 15 leaves)."""
from __future__ import annotations

import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from baselines import EXCLUDE_DEFAULT, load  # noqa: E402
from common import metrics, save_json  # noqa: E402
from features import TldEncoder, cached_lexical  # noqa: E402

import lightgbm as lgb  # noqa: E402

if __name__ == "__main__":
    df = load("phreshphish")
    lx = cached_lexical("phreshphish", df.url.values)
    cols = [c for c in lx.columns if not c.startswith("_") and c not in EXCLUDE_DEFAULT]
    tr_all = (df.tsplit == "train").values
    # hold out 10% of train *domains* for early stopping
    va = tr_all & (df.split == "val").values
    tr = tr_all & ~va
    te = (df.tsplit == "test").values & ~df.group.isin(set(df.group[tr_all])).values
    enc = TldEncoder().fit(lx["_tld"][tr], df.label[tr])
    X = lx[cols].copy(); X["tld_logit"] = enc.logit(lx["_tld"])
    p = dict(objective="binary", learning_rate=0.08, num_leaves=15, min_data_in_leaf=50, feature_fraction=0.9,
             bagging_fraction=0.8, bagging_freq=1, lambda_l2=1.0, verbose=-1, num_threads=4, seed=0)
    m = lgb.train(p, lgb.Dataset(X[tr], df.label[tr]), 400, valid_sets=[lgb.Dataset(X[va], df.label[va])],
                  callbacks=[lgb.early_stopping(50, verbose=False)])
    pr = m.predict(X[te], num_iteration=m.best_iteration)
    r = metrics(df.label.values[te], pr)
    out = {"train_period": [str(df.date[tr_all].min()), str(df.date[tr_all].max())],
           "test_period": [str(df.date[(df.tsplit == "test").values].min()), str(df.date[(df.tsplit == "test").values].max())],
           "n_train": int(tr.sum()), "n_test_unseen_domains": int(te.sum()),
           "n_test_dropped_seen_domain": int(((df.tsplit == "test").values & ~te).sum()),
           "metrics": {k: r[k] for k in ("roc_auc", "pr_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct",
                                         "fpr", "fnr", "ece", "n", "n_pos")}}
    print(out, flush=True)
    save_json(out, "final", "phreshphish_temporal_domain_disjoint.json")
