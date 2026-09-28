"""Export a LightGBM booster (+ calibration, thresholds, TLD table) to the portable JSON
format read by fraudurl.model.Model, and verify the pure-Python scorer reproduces LightGBM."""
from __future__ import annotations

import json
import math
import os
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def booster_to_trees(booster):
    dump = booster.dump_model()
    names = dump["feature_names"]
    trees = []
    for ti in dump["tree_info"]:
        root = ti["tree_structure"]
        f, t, l, r, d, m, v, lv = [], [], [], [], [], [], [], []
        if "leaf_value" in root and "split_index" not in root:
            trees.append({"f": [], "t": [], "l": [], "r": [], "d": [], "m": [], "v": [], "lv": [root["leaf_value"]]})
            continue

        def walk(node):
            if "split_index" not in node:
                lv.append(node["leaf_value"])
                return ~(len(lv) - 1)
            i = len(f)
            f.append(node["split_feature"]); t.append(node["threshold"])
            assert node["decision_type"] == "<=", node["decision_type"]
            d.append(bool(node["default_left"]))
            m.append({"None": 0, "Zero": 1, "NaN": 2}[node["missing_type"]])
            v.append(node["internal_value"])
            l.append(None); r.append(None)
            l[i] = walk(node["left_child"])
            r[i] = walk(node["right_child"])
            return i

        walk(root)
        trees.append({"f": f, "t": t, "l": l, "r": r, "d": d, "m": m, "v": v, "lv": lv})
    return names, trees


def export(booster, path, calibration, thresholds, meta, tld_table=None, tld_prior=0.5, reason_text=None):
    names, trees = booster_to_trees(booster)
    obj = {"meta": meta, "features": names, "init_score": 0.0, "trees": trees,
           "calibration": calibration, "thresholds": thresholds,
           "tld_table": tld_table or {}, "tld_prior": tld_prior, "reason_text": reason_text or {}}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, separators=(",", ":"))
    return path


def verify(booster, path, X):
    from fraudurl.model import Model
    m = Model(path)
    ref = booster.predict(X, raw_score=True)
    got = np.array([m.raw(list(map(float, row))) for row in np.asarray(X, dtype=float)])
    got_c = np.array([m.raw_with_contrib(list(map(float, row)))[0] for row in np.asarray(X, dtype=float)[:200]])
    return float(np.max(np.abs(ref - got))), float(np.max(np.abs(ref[:200] - got_c)))


if __name__ == "__main__":
    import lightgbm as lgb
    import pandas as pd
    sys.path.insert(0, os.path.join(ROOT, "experiments"))
    from baselines import design, load
    name = sys.argv[1] if len(sys.argv) > 1 else "hannousse"
    b = lgb.Booster(model_file=os.path.join(ROOT, "results", "models", f"{name}_lgbm.txt"))
    df = load(name)
    X, lex, enc = design(df, name)
    Xt = X[df.split == "test"].copy()
    Xt.iloc[:50, 3] = np.nan  # exercise the missing-value path
    fp = export(b, os.path.join(ROOT, ".cache", "tmp", f"{name}_export_test.json"), {"type": "none"},
                {"fraud": 0.5, "legit": 0.5}, {"calibration_base_rate": 0.5})
    print("max |raw diff| predict, contrib-sum:", verify(b, fp, Xt.values), "size KB", os.path.getsize(fp) / 1024)
