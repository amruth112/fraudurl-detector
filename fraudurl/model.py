"""Dependency-free runtime for the exported model (gradient-boosted trees + calibration).

The model file is plain JSON produced by ``experiments/export_model.py`` from a trained
LightGBM booster. Scoring needs only the Python standard library.

Per-feature contributions use path attribution (Saabas): walking a tree from the root,
each split credits the change in the node's expected value to the feature it tested.
The contributions of all trees sum exactly to the raw score, so the "reasons" we report
are the features that actually moved this URL's score, not a separate heuristic.
"""
from __future__ import annotations

import json
import math

_NAN = float("nan")


class Tree:
    __slots__ = ("feat", "thr", "left", "right", "default_left", "miss", "value", "leaf")

    def __init__(self, t: dict):
        self.feat, self.thr = t["f"], t["t"]
        self.left, self.right = t["l"], t["r"]
        self.default_left, self.miss = t["d"], t["m"]
        self.value, self.leaf = t["v"], t["lv"]  # internal-node expected values, leaf values

    def _go_left(self, i, x):
        v = x[self.feat[i]]
        m = self.miss[i]
        if v != v:  # NaN
            if m == 2:  # missing_type NaN -> default direction
                return self.default_left[i]
            v = 0.0
        if m == 1 and -1e-35 <= v <= 1e-35:  # missing_type Zero (LightGBM kZeroThreshold)
            return self.default_left[i]
        return v <= self.thr[i]

    def predict(self, x) -> float:
        if not self.feat:  # single-leaf tree
            return self.leaf[0]
        i = 0
        while True:
            nxt = self.left[i] if self._go_left(i, x) else self.right[i]
            if nxt < 0:
                return self.leaf[~nxt]
            i = nxt

    def contrib(self, x, out: list) -> float:
        i = 0
        cur = self.value[0]
        while True:
            nxt = self.left[i] if self._go_left(i, x) else self.right[i]
            f = self.feat[i]
            nv = self.leaf[~nxt] if nxt < 0 else self.value[nxt]
            out[f] += nv - cur
            cur = nv
            if nxt < 0:
                return cur
            i = nxt


class Model:
    def __init__(self, path: str):
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        self.meta = d["meta"]
        self.features: list[str] = d["features"]
        self.trees = [Tree(t) for t in d["trees"]]
        self.base = d.get("init_score", 0.0)
        self.cal = d["calibration"]            # {"type": "platt"|"isotonic"|"none", ...}
        self.thresholds = d["thresholds"]      # {"fraud": p_hi, "legit": p_lo}
        self.tld_table = d.get("tld_table", {})
        self.tld_prior = d.get("tld_prior", 0.5)
        self.reason_text = d.get("reason_text", {})

    def vector(self, feats: dict) -> list:
        x = []
        for name in self.features:
            if name == "tld_logit":  # full public suffix -> bare TLD -> global rate
                key = feats.get("_tld", "") or ""
                r = self.tld_table.get(key)
                if r is None:
                    r = self.tld_table.get(key.rsplit(".", 1)[-1], self.tld_prior)
                p = min(max(r, 1e-4), 1 - 1e-4)
                x.append(math.log(p / (1 - p)))
            else:
                v = feats.get(name, _NAN)
                x.append(_NAN if v is None else float(v))
        return x

    def raw(self, x) -> float:
        return self.base + sum(t.predict(x) for t in self.trees)

    def raw_with_contrib(self, x):
        """Raw score and per-feature contributions; raw == bias + sum(contributions)."""
        out = [0.0] * len(self.features)
        s = self.base
        for t in self.trees:
            s += t.value[0] if t.feat else t.leaf[0]  # root expectation (or constant tree)
            if t.feat:
                t.contrib(x, out)
        return s + sum(out), out

    def calibrate(self, raw: float) -> float:
        c = self.cal
        if c["type"] == "platt":
            z = c["a"] * raw + c["b"]
            return 1.0 / (1.0 + math.exp(-z)) if z > -700 else 0.0
        if c["type"] == "isotonic":
            xs, ys = c["x"], c["y"]
            if raw <= xs[0]:
                return ys[0]
            if raw >= xs[-1]:
                return ys[-1]
            lo, hi = 0, len(xs) - 1
            while hi - lo > 1:
                mid = (lo + hi) // 2
                if xs[mid] <= raw:
                    lo = mid
                else:
                    hi = mid
            w = (raw - xs[lo]) / (xs[hi] - xs[lo]) if xs[hi] > xs[lo] else 0.0
            return ys[lo] + w * (ys[hi] - ys[lo])
        return 1.0 / (1.0 + math.exp(-raw))

    def adjust_prior(self, p: float, base_rate: float | None) -> float:
        """Re-weight a probability calibrated at the training class balance to another base rate."""
        if base_rate is None:
            return p
        pi = self.meta["calibration_base_rate"]
        p = min(max(p, 1e-9), 1 - 1e-9)
        odds = p / (1 - p) * (base_rate / (1 - base_rate)) / (pi / (1 - pi))
        return odds / (1 + odds)

    def predict(self, feats: dict, want_reasons: bool = True):
        x = self.vector(feats)
        if want_reasons:
            raw, contrib = self.raw_with_contrib(x)
        else:
            raw, contrib = self.raw(x), None
        return raw, self.calibrate(raw), contrib, x
