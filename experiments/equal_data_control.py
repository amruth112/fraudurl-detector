"""Fair control: every representation trained on the SAME 6,000 URLs Laya's embedding
classifier used, tuned on the same val URLs, scored on the same 1,500 test URLs."""
import os, sys
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RESULTS, metrics, save_json
from features import TldEncoder, cached_lexical, canon_text
from baselines import EXCLUDE_DEFAULT
import lightgbm as lgb
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.metrics import roc_auc_score

def S(y, p):
    r = metrics(y, p); return {k: round(r[k], 4) for k in ("roc_auc", "pr_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct")}

if __name__ == "__main__":
    z = np.load(os.path.join(RESULTS, "laya", "embed_multilingual_phreshphish.npz"), allow_pickle=True)
    out = {}
    lr = LogisticRegression(C=0.01, max_iter=3000).fit(z["train_X"], z["train_y"])
    out["laya_embedding_LR"] = S(z["test_y"], lr.predict_proba(z["test_X"])[:, 1])
    tr_u, va_u, te_u = list(z["train_url"]), list(z["val_url"]), list(z["test_url"])
    L = {k: cached_lexical(f"eq_{k}", u, workers=1) for k, u in (("tr", tr_u), ("va", va_u), ("te", te_u))}
    cols = [c for c in L["tr"].columns if not c.startswith("_") and c not in EXCLUDE_DEFAULT]
    enc = TldEncoder().fit(L["tr"]["_tld"], z["train_y"])
    X = {k: v[cols].assign(tld_logit=enc.logit(v["_tld"])) for k, v in L.items()}
    p = dict(objective="binary", learning_rate=0.05, num_leaves=15, min_data_in_leaf=20, verbose=-1, num_threads=4, seed=0)
    m = lgb.train(p, lgb.Dataset(X["tr"], z["train_y"]), 2000, valid_sets=[lgb.Dataset(X["va"], z["val_y"])],
                  callbacks=[lgb.early_stopping(100, verbose=False)])
    out["lightgbm_lexical_same_6k"] = S(z["test_y"], m.predict(X["te"], num_iteration=m.best_iteration))
    hv = HashingVectorizer(analyzer="char", ngram_range=(3, 5), n_features=2 ** 20, alternate_sign=False)
    Htr, Hva, Hte = (hv.transform([canon_text(u) for u in U]) for U in (tr_u, va_u, te_u))
    best = max(((roc_auc_score(z["val_y"], LogisticRegression(C=C, max_iter=2000, solver="liblinear").fit(Htr, z["train_y"]).predict_proba(Hva)[:, 1]), C) for C in (1, 4, 16)))
    cm = LogisticRegression(C=best[1], max_iter=2000, solver="liblinear").fit(Htr, z["train_y"])
    out["char_ngram_LR_same_6k"] = S(z["test_y"], cm.predict_proba(Hte)[:, 1])
    Xc = np.c_[z["train_X"], (X["tr"] - X["tr"].mean()) / (X["tr"].std() + 1e-9)]
    Xt = np.c_[z["test_X"], (X["te"] - X["tr"].mean()) / (X["tr"].std() + 1e-9)]
    out["laya_embedding+lexical_LR_same_6k"] = S(z["test_y"], LogisticRegression(C=0.01, max_iter=5000).fit(np.nan_to_num(Xc), z["train_y"]).predict_proba(np.nan_to_num(Xt))[:, 1])
    for k, v in out.items(): print(f"{k:38s}", v)
    save_json(out, "laya", "equal_data_control_phreshphish.json")
