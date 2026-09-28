"""Shared experiment utilities: leakage-safe splits, metrics, calibration helpers."""
from __future__ import annotations

import hashlib
import json
import os
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
DATA = os.path.join(ROOT, "data")
RESULTS = os.path.join(ROOT, "results")
os.makedirs(RESULTS, exist_ok=True)


def group_bucket(group: str, salt: str = "fraudurl-v1") -> int:
    """Deterministic 0..99 bucket for a group key (registrable domain)."""
    return int(hashlib.md5((salt + "|" + group).encode("utf-8")).hexdigest()[:8], 16) % 100


def grouped_split(groups, cuts=(60, 70, 80), salt="fraudurl-v1"):
    """Assign each row to train/val/cal/test by hashing its group (registrable domain),
    so no domain ever appears in more than one split. Default 60/10/10/20."""
    out = []
    for g in groups:
        b = group_bucket(str(g), salt)
        out.append("train" if b < cuts[0] else "val" if b < cuts[1] else "cal" if b < cuts[2] else "test")
    return np.array(out)


def ece_score(y, p, bins=15):
    y, p = np.asarray(y, float), np.asarray(p, float)
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    e = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            e += m.mean() * abs(y[m].mean() - p[m].mean())
    return float(e)


def recall_at_fpr(y, p, max_fpr):
    from sklearn.metrics import roc_curve
    fpr, tpr, thr = roc_curve(y, p)
    ok = fpr <= max_fpr
    return float(tpr[ok].max()) if ok.any() else 0.0


def metrics(y, p, thr=0.5):
    from sklearn.metrics import (average_precision_score, brier_score_loss, log_loss,
                                 roc_auc_score)
    y = np.asarray(y).astype(int)
    s = np.asarray(p, float)                 # raw score: ranking metrics must not be clipped
    p = np.clip(s, 1e-7, 1 - 1e-7)           # (clipping saturated scores would create ties)
    pred = (s >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    out = dict(
        n=int(len(y)), n_pos=int(y.sum()), n_neg=int((1 - y).sum()), threshold=float(thr),
        tp=tp, fp=fp, tn=tn, fn=fn,
        precision=prec, recall=rec, f1=(2 * prec * rec / (prec + rec)) if prec + rec else 0.0,
        fpr=fp / (fp + tn) if fp + tn else 0.0, fnr=fn / (fn + tp) if fn + tp else 0.0,
        accuracy=(tp + tn) / len(y) if len(y) else 0.0,
    )
    if 0 < y.sum() < len(y):
        out.update(
            roc_auc=float(roc_auc_score(y, s)), pr_auc=float(average_precision_score(y, s)),
            brier=float(brier_score_loss(y, p)), log_loss=float(log_loss(y, p)),
            ece=ece_score(y, p),
            recall_at_fpr_1pct=recall_at_fpr(y, s, 0.01),
            recall_at_fpr_0_1pct=recall_at_fpr(y, s, 0.001),
        )
    return out


def bootstrap_ci(y, p, fn, n=500, seed=0, groups=None):
    """Percentile CI of fn(y, p). If groups given, resamples whole groups (domains)."""
    rng = np.random.default_rng(seed)
    y, p = np.asarray(y), np.asarray(p)
    vals = []
    if groups is None:
        for _ in range(n):
            i = rng.integers(0, len(y), len(y))
            if 0 < y[i].sum() < len(i):
                vals.append(fn(y[i], p[i]))
    else:
        groups = np.asarray(groups)
        uniq, inv = np.unique(groups, return_inverse=True)
        members = [[] for _ in range(len(uniq))]
        for r, g in enumerate(inv):
            members[g].append(r)
        members = [np.array(m) for m in members]
        for _ in range(n):
            pick = rng.integers(0, len(uniq), len(uniq))
            i = np.concatenate([members[g] for g in pick])
            if 0 < y[i].sum() < len(i):
                vals.append(fn(y[i], p[i]))
    return float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))


def threshold_for_fpr(y, p, target_fpr):
    """Smallest threshold whose FPR on (y, p) is <= target_fpr."""
    y, p = np.asarray(y), np.asarray(p)
    neg = np.sort(p[y == 0])[::-1]
    k = int(np.floor(target_fpr * len(neg)))
    return float(neg[k] + 1e-9) if k < len(neg) else 0.0


def save_json(obj, *path):
    fp = os.path.join(RESULTS, *path)
    os.makedirs(os.path.dirname(fp), exist_ok=True)
    with open(fp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=float)
    return fp
