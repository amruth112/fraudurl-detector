"""Is the shipped probability a probability? Reliability tables per test set, ECE, and what
the numbers mean at realistic fraud base rates."""
from __future__ import annotations

import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RESULTS, ROOT, ece_score, save_json  # noqa: E402
from features import cached_lexical  # noqa: E402


def reliability(y, p, bins=(0, .05, .1, .2, .3, .4, .5, .6, .7, .8, .9, .95, 1.0001)):
    rows = []
    idx = np.digitize(p, bins[1:-1])
    for b in range(len(bins) - 1):
        m = idx == b
        if m.sum():
            rows.append({"bin": f"{bins[b]:.2f}-{min(bins[b + 1], 1):.2f}", "n": int(m.sum()),
                         "mean_predicted": float(p[m].mean()), "observed_phishing_rate": float(y[m].mean())})
    return rows


def main(tag="safe"):
    from fraudurl.model import Model
    from fraudurl.lexical import extract
    z = np.load(os.path.join(RESULTS, "final", f"preds_{tag}.npz"), allow_pickle=True)
    out = {"tag": tag, "sets": {}}
    te = z["split"] == "test"
    for ds in np.unique(z["dataset"]):
        m = te & (z["dataset"] == ds)
        y, p = z["y"][m].astype(int), z["prob"][m]
        out["sets"][str(ds)] = {"n": int(m.sum()), "base_rate": float(y.mean()), "ece": ece_score(y, p),
                                "reliability": reliability(y, p)}
    # external two-class set scored through the SHIPPED runtime
    model = Model(os.path.join(ROOT, "fraudurl", "data", f"model_{tag}.json"))
    ar = pd.read_csv(os.path.join(ROOT, "data", "processed", "ariyadasa.csv"), usecols=["url", "label", "group"])
    seen = set()
    for name in ("phreshphish", "fresh26", "hannousse"):
        d = pd.read_csv(os.path.join(ROOT, "data", "processed", f"{name}.csv"), usecols=["group", "split"])
        seen |= set(d.group[d.split.isin(["train", "val", "cal"])])
    ar = ar[~ar.group.isin(seen)].sample(20000, random_state=0)  # domains never used for training/calibration
    pa = np.array([model.calibrate(model.raw(model.vector(extract(u)))) for u in ar.url])
    out["sets"]["ariyadasa_external_20k"] = {"n": len(ar), "base_rate": float(ar.label.mean()),
                                             "ece": ece_score(ar.label.values, pa), "reliability": reliability(ar.label.values, pa)}
    # meaning at other base rates: posterior for a few shipped probabilities
    pi = model.meta["calibration_base_rate"]
    out["calibration_base_rate"] = pi
    out["prior_shift_examples"] = {f"p={q}": {f"base_rate={br}": round(model.adjust_prior(q, br), 4)
                                              for br in (0.5, 0.1, 0.01, 0.001)} for q in (0.5, 0.8, 0.9, 0.97, 0.99)}
    for k, v in out["sets"].items():
        print(k, "n", v["n"], "base", round(v["base_rate"], 3), "ECE", round(v["ece"], 4))
        for r in v["reliability"]:
            print(f"   {r['bin']:>10s} n={r['n']:6d} predicted={r['mean_predicted']:.3f} observed={r['observed_phishing_rate']:.3f}")
    print(json.dumps(out["prior_shift_examples"], indent=1))
    save_json(out, "final", f"calibration_{tag}.json")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "safe")
