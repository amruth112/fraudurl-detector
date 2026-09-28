"""What verdict mix should a user expect from 1,000,000 URLs, as a function of how many are really phishing?

Per-class verdict rates are MEASURED on URLs from registrable domains the shipped safe model never saw in
training, validation or calibration, then projected to N = 1,000,000 URLs at several prevalences:

  rate sets (legitimate side / phishing side)
    phreshphish_test   PhreshPhish TEST split (2024-25; Webroot browsing telemetry vs PhishTank/APWG/Netcraft)
    fresh26_test       fresh26 TEST split (Jun-Sep 2026; Hacker News links + Common Crawl pages on Tranco
                       top-1M domains vs OpenPhish/PhishTank)
    hannousse_test     Hannousse & Yahiouche TEST split (2020)
    ariyadasa_unseen   Ariyadasa 2021, fully external collection, restricted to unseen registrable domains
                       exactly as experiments/train_final.py does (-> n_unseen_domains)
    homepages_tranco   legitimate side = bare homepages of Tranco top-10k sites (unseen domains; a
                       homepage-heavy legitimate mix); phishing side = fresh26 TEST phishing
  supplementary phishing-only sets (per-class rates only): jpcert_recent_unseen, openphish26_unseen

Every URL is re-scored with the SHIPPED runtime (fraudurl.lexical.extract + fraudurl.model.Model, with the
same "ERROR" pre-checks as fraudurl.cli.score_rows). The verdict rule of fraudurl.cli.score_rows is applied
here from the full-precision probability so it can be evaluated at several --base-rate values from one
scoring pass; that re-implementation is checked against the real CLI (python -m fraudurl, default and every
--base-rate used) on ~2,000 URLs, a third of them the rows nearest each decision boundary.

Projection: expected count = (number of URLs of that class) x (measured per-class verdict share).
(a) default settings; (b) --base-rate equal to the true prevalence (rates re-measured with that rule).
95% intervals: cluster bootstrap over registrable domains (1,000 replicates) of the per-class shares.

No network access. Output: results/benchmark/projection_1m.json
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from multiprocessing import Pool

import numpy as np
import pandas as pd
from scipy.stats import beta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from fraudurl.cli import MODEL_SAFE  # noqa: E402
from fraudurl.lexical import extract  # noqa: E402
from fraudurl.model import Model  # noqa: E402

PROC = os.path.join(ROOT, "data", "processed")
TMP = os.path.join(ROOT, ".cache", "tmp", "project_1m")
OUT = os.path.join(ROOT, "results", "benchmark", "projection_1m.json")
N_TOTAL = 1_000_000
PREVALENCES = (0.001, 0.01, 0.05, 0.2, 0.5)
BASE_RATES = (None,) + PREVALENCES          # None = default (no --base-rate)
TRAIN_SETS = ("phreshphish", "fresh26", "hannousse")
V = ("FRAUD", "REVIEW", "LEGITIMATE", "ERROR")
N_BOOT = 1000
SEED = 0


def bkey(b):
    return "default" if b is None else f"{b:g}"


# ----------------------------------------------------------------------------- scoring (shipped runtime)
_M = None


def _init():
    global _M
    _M = Model(MODEL_SAFE)


def _score(urls):
    """Calibrated probability exactly as fraudurl.cli.score_rows computes it (NaN where the CLI says ERROR),
    plus the is_homepage flag of the parsed URL."""
    p = np.full(len(urls), np.nan)
    home = np.zeros(len(urls), dtype=bool)
    for i, url in enumerate(urls):
        if url is None or not str(url).strip():
            continue
        f = extract(str(url))
        if f.get("parse_error"):
            continue
        if any(ch.isspace() for ch in str(url).strip()) or (not f.get("host_is_ip") and f.get("host_n_labels", 0) < 2):
            continue
        home[i] = f.get("is_homepage", 0.0) == 1.0
        try:
            _raw, p[i], _c, _x = _M.predict(f, want_reasons=True)
        except Exception:  # noqa: BLE001 - the CLI turns this into ERROR too
            p[i] = np.nan
    return p, home


def score_all(urls, workers=4, chunk=2000):
    parts = [list(urls[i:i + chunk]) for i in range(0, len(urls), chunk)]
    with Pool(workers, initializer=_init) as pool:
        res = pool.map(_score, parts)
    return np.concatenate([r[0] for r in res]), np.concatenate([r[1] for r in res])


def verdict_codes(p, base_rate, m):
    """fraudurl.cli.score_rows verdict rule (safe model): 0 FRAUD, 1 REVIEW, 2 LEGITIMATE, 3 ERROR (p is NaN).
    Uses the shipped Model.adjust_prior for p_adj."""
    th_f, th_l = m.thresholds["fraud"], m.thresholds["legit"]
    out = np.full(len(p), 3, dtype=np.int8)
    for i, pi in enumerate(p.tolist()):
        if pi != pi:
            continue
        pa = m.adjust_prior(pi, base_rate)
        if pi >= th_f and pa >= 0.5:
            out[i] = 0
        elif pi <= th_l and pa <= 0.5:
            out[i] = 2
        else:
            out[i] = 1
    return out


def fraud_cut(m, b):
    """Smallest calibrated p that can still be FRAUD at --base-rate b (max of the threshold and p_adj = 0.5)."""
    if b is None:
        return m.thresholds["fraud"]
    pi = m.meta["calibration_base_rate"]
    odds = (pi / (1 - pi)) / (b / (1 - b))
    return max(m.thresholds["fraud"], odds / (1 + odds))


# ----------------------------------------------------------------------------- data
def _describe(d):
    """Collection period and label sources of the rows actually used (from the processed CSV)."""
    return {"date_range": [str(d.date.min()), str(d.date.max())],
            "sources": {("phishing" if lab == 1 else "legitimate"): {str(k): int(v) for k, v in g.source.value_counts().items()}
                        for lab, g in d.groupby("label")}}


def load_sets():
    z = np.load(os.path.join(ROOT, "results", "final", "preds_safe.npz"), allow_pickle=True)
    sets, seen, checks = {}, set(), {}
    for name in TRAIN_SETS:
        d = pd.read_csv(os.path.join(PROC, f"{name}.csv"), dtype={"url": str})   # as experiments/baselines.load
        seen |= set(d.group[d.split.isin(["train", "val", "cal"])])
        m = (z["dataset"] == name) & (z["split"] == "test")
        dt = d[d.split == "test"]
        # train_final.py concatenates each dataset's CSV in file order -> npz rows align with CSV rows
        assert len(dt) == int(m.sum()), name
        assert (dt.url.astype(str).values == z["url"][m].astype(str)).all(), f"npz/CSV misaligned for {name}"
        assert (dt.label.values == z["y"][m]).all(), name
        sets[f"{name}_test"] = {"url": z["url"][m].astype(str), "y": z["y"][m].astype(int),
                                "group": dt.group.values, "npz_prob": z["prob"][m].astype(float), "desc": _describe(dt)}
    for name in ("ariyadasa", "tranco_home", "jpcert_recent", "openphish26"):
        d = pd.read_csv(os.path.join(PROC, f"{name}.csv"), dtype={"url": str})
        unseen = ~d.group.isin(seen).values                       # train_final.py: n_unseen_domains
        checks[name] = {"n": int(len(d)), "n_unseen_domains": int(unseen.sum())}
        d = d[unseen]
        sets[f"{name}_unseen"] = {"url": d.url.fillna("").astype(str).values, "y": d.label.values.astype(int),
                                  "group": d.group.values, "desc": _describe(d)}
    return sets, checks


# ----------------------------------------------------------------------------- CLI validation
def validate_cli(pool_url, pool_p, m, rng, n_random=1400, n_per_edge=120):
    ok = np.array(["\n" not in u and "\r" not in u and "\x00" not in u for u in pool_url])
    cand = np.where(ok)[0]
    pick = set(rng.choice(cand, n_random, replace=False).tolist())
    edges = {"th_fraud": m.thresholds["fraud"], "th_legit": m.thresholds["legit"]}
    for b in PREVALENCES:
        c = fraud_cut(m, b)
        if c > m.thresholds["fraud"]:
            edges[f"fraud_cut_base_rate_{b:g}"] = c
    finite = cand[np.isfinite(pool_p[cand])]
    for c in edges.values():
        order = finite[np.argsort(np.abs(pool_p[finite] - c))]
        k = 0
        for j in order:
            if j not in pick:
                pick.add(int(j)); k += 1
            if k >= n_per_edge:
                break
    pick.update(cand[~np.isfinite(pool_p[cand])][:50].tolist())  # any rows the CLI calls ERROR
    idx = np.array(sorted(pick))
    os.makedirs(TMP, exist_ok=True)
    inp = os.path.join(TMP, "validate_in.csv")
    pd.DataFrame({"id": np.arange(len(idx)), "url": pool_url[idx]}).to_csv(inp, index=False, encoding="utf-8")
    res = {"n_urls": int(len(idx)), "n_random": n_random, "boundary_rows_per_cut": n_per_edge,
           "cuts": {k: float(v) for k, v in edges.items()}, "runs": {}}
    p_sel = pool_p[idx]
    for b in BASE_RATES:
        outp = os.path.join(TMP, f"validate_out_{bkey(b)}.csv")
        cmd = [sys.executable, "-m", "fraudurl", inp, "-o", outp] + ([] if b is None else ["--base-rate", repr(b)])
        t = time.time()
        subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True)
        r = pd.read_csv(outp, encoding="utf-8-sig", dtype=str, keep_default_na=False)
        assert len(r) == len(idx) and (r.id.astype(int).values == np.arange(len(idx))).all()
        mine = np.array(V)[verdict_codes(p_sel, b, m)]
        agree = mine == r.fraud_verdict.values
        # the CLI prints p_adj to 3 decimals: compare that too (ERROR rows have no probability)
        pa = np.array(["" if not np.isfinite(x) else f"{m.adjust_prior(float(x), b):.3f}" for x in p_sel])
        prob_agree = pa == r.fraud_probability.values
        res["runs"][bkey(b)] = {"cli_args": "default" if b is None else f"--base-rate {b:g}",
                                "seconds": round(time.time() - t, 1),
                                "verdict_agreement": float(agree.mean()), "n_disagree": int((~agree).sum()),
                                "probability_string_agreement": float(prob_agree.mean()),
                                "cli_verdicts": r.fraud_verdict.value_counts().to_dict()}
        print(f"CLI validation {bkey(b):>8}: verdict agreement {agree.mean():.4%} ({(~agree).sum()} differ), "
              f"probability text agreement {prob_agree.mean():.4%}", flush=True)
    return res


# ----------------------------------------------------------------------------- rates + bootstrap
def class_counts(codes_by_b, y, group):
    """G x 2 x nB x 4 count tensor (group, class, base-rate setting, verdict)."""
    g, _ = pd.factorize(group)
    C = np.zeros((g.max() + 1, 2, len(BASE_RATES), 4))
    for bi, codes in enumerate(codes_by_b):
        np.add.at(C, (g, y, bi, codes.astype(int)), 1)
    return C


def shares_from_counts(tot):
    s = tot.sum(-1, keepdims=True)
    with np.errstate(invalid="ignore", divide="ignore"):
        return np.where(s > 0, tot / np.where(s > 0, s, 1), np.nan)


def bootstrap_shares(C, rng, n_boot=N_BOOT, batch=50):
    G = C.shape[0]
    flat = C.reshape(G, -1)
    outs = []
    for s in range(0, n_boot, batch):
        k = min(batch, n_boot - s)
        W = np.stack([np.bincount(rng.integers(0, G, G), minlength=G) for _ in range(k)]).astype(float)
        outs.append((W @ flat).reshape((k,) + C.shape[1:]))
    return shares_from_counts(np.concatenate(outs))             # R x 2 x nB x 4


def clopper_pearson(k, n, a=0.05):
    """Exact binomial 95% interval for k events in n rows (rows treated as independent)."""
    lo = 0.0 if k == 0 else float(beta.ppf(a / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1 - a / 2, k + 1, n - k))
    return lo, hi


def project(sp, sl, prev, n=N_TOTAL):
    """sp / sl: per-class verdict shares (..., 4) for phishing / legitimate. Expected counts at this prevalence."""
    n_p, n_l = prev * n, (1 - prev) * n
    tp, fp = n_p * sp[..., 0], n_l * sl[..., 0]
    rv_p, rv_l = n_p * sp[..., 1], n_l * sl[..., 1]
    tn, fn = n_l * sl[..., 2], n_p * sp[..., 2]
    er = n_p * sp[..., 3] + n_l * sl[..., 3]
    with np.errstate(invalid="ignore", divide="ignore"):
        return {
            "FRAUD_total": tp + fp, "FRAUD_true_phishing": tp, "FRAUD_false_alarms": fp,
            "REVIEW_total": rv_p + rv_l, "REVIEW_phishing": rv_p, "REVIEW_legitimate": rv_l,
            "LEGITIMATE_total": tn + fn, "LEGITIMATE_legitimate": tn, "LEGITIMATE_missed_phishing": fn,
            "ERROR_total": er,
            "FRAUD_precision": tp / (tp + fp),
            "REVIEW_phishing_share": rv_p / (rv_p + rv_l),
            "LEGITIMATE_rows_that_are_phishing": fn / (tn + fn),
            "phishing_share_in_FRAUD": sp[..., 0], "phishing_share_in_REVIEW": sp[..., 1],
            "phishing_share_in_LEGITIMATE": sp[..., 2],
            "legit_share_in_FRAUD": sl[..., 0], "legit_share_in_REVIEW": sl[..., 1],
            "legit_share_in_LEGITIMATE": sl[..., 2],
        }


COUNT_KEYS = {"FRAUD_total", "FRAUD_true_phishing", "FRAUD_false_alarms", "REVIEW_total", "REVIEW_phishing",
              "REVIEW_legitimate", "LEGITIMATE_total", "LEGITIMATE_legitimate", "LEGITIMATE_missed_phishing",
              "ERROR_total"}


def fmt(k, v):
    """Counts -> int, ratios -> 5 decimals, undefined (e.g. precision with no FRAUD rows) -> None."""
    v = float(v)
    if v != v:
        return None
    return int(round(v)) if k in COUNT_KEYS else round(v, 5)


# ----------------------------------------------------------------------------- main
def main():
    t0 = time.time()
    m = Model(MODEL_SAFE)
    rng = np.random.default_rng(SEED)
    sets, ext_checks = load_sets()
    final = json.load(open(os.path.join(ROOT, "results", "final", "final_safe.json")))

    # ---- score every URL once with the shipped runtime
    names = list(sets)
    allu = np.concatenate([sets[k]["url"] for k in names])
    print(f"scoring {len(allu):,} URLs with the shipped runtime ...", flush=True)
    ts = time.time()
    p_all, home_all = score_all(allu)
    print(f"  done in {time.time() - ts:.1f}s", flush=True)
    o = 0
    for k in names:
        n = len(sets[k]["url"])
        sets[k]["p"], sets[k]["home"] = p_all[o:o + n], home_all[o:o + n]
        o += n
        sets[k]["codes"] = [verdict_codes(sets[k]["p"], b, m) for b in BASE_RATES]

    # ---- sanity checks against the training pipeline's own numbers (results/final/final_safe.json)
    sanity = {"test_splits": {}, "external": {}}
    th_f, th_l = m.thresholds["fraud"], m.thresholds["legit"]
    for name in TRAIN_SETS:
        s = sets[f"{name}_test"]
        fin = np.isfinite(s["p"])
        dp = np.abs(s["p"][fin] - s["npz_prob"][fin])
        v_npz = np.where(s["npz_prob"] >= th_f, 0, np.where(s["npz_prob"] <= th_l, 2, 1))
        dis = int((v_npz[fin] != s["codes"][0][fin]).sum())
        ref = final["test"][name]["three_way"]
        mine = {v: float((s["codes"][0] == i).mean()) for i, v in enumerate(V)}
        sanity["test_splits"][name] = {
            "n": int(len(s["p"])), "n_cli_ERROR": int((~fin).sum()),
            "max_abs_prob_diff_runtime_vs_npz": float(dp.max()),
            "verdict_disagreements_runtime_vs_npz_prob": dis,
            "shares_runtime_cli_rule": mine,
            "shares_final_safe_json": {v: ref[v]["share"] for v in ("FRAUD", "REVIEW", "LEGITIMATE")},
        }
        print(f"sanity {name}: max|p_runtime - p_npz| = {dp.max():.2e}, verdict disagreements {dis}, "
              f"ERROR rows {(~fin).sum()}", flush=True)
    for name in ("ariyadasa", "tranco_home", "jpcert_recent", "openphish26"):
        s = sets[f"{name}_unseen"]
        ref = final["external"][name]
        c0 = s["codes"][0]
        e = {"n": ext_checks[name]["n"], "n_unseen_domains": ext_checks[name]["n_unseen_domains"],
             "n_unseen_domains_final_safe_json": ref["n_unseen_domains"],
             "n_cli_ERROR": int((c0 == 3).sum()),
             "shares_runtime_cli_rule": {v: float((c0 == i).mean()) for i, v in enumerate(V)},
             "shares_final_safe_json": {v: ref[f"{v}_share"] for v in ("FRAUD", "REVIEW", "LEGITIMATE")}}
        if "legit_flagged_FRAUD_rate" in ref:
            y = s["y"]
            e["legit_flagged_FRAUD_rate"] = float((c0[y == 0] == 0).mean())
            e["phish_called_LEGITIMATE_rate"] = float((c0[y == 1] == 2).mean())
            e["legit_flagged_FRAUD_rate_final_safe_json"] = ref["legit_flagged_FRAUD_rate"]
            e["phish_called_LEGITIMATE_rate_final_safe_json"] = ref["phish_called_LEGITIMATE_rate"]
        assert e["n_unseen_domains"] == e["n_unseen_domains_final_safe_json"], name
        sanity["external"][name] = e
        print(f"sanity {name}: n_unseen {e['n_unseen_domains']:,} (final_safe {ref['n_unseen_domains']:,}); shares "
              + ", ".join(f"{v} {e['shares_runtime_cli_rule'][v]:.4f}/{e['shares_final_safe_json'][v]:.4f}"
                          for v in ("FRAUD", "REVIEW", "LEGITIMATE"))
              + (f"; legit->FRAUD {e['legit_flagged_FRAUD_rate']:.5f}/{e['legit_flagged_FRAUD_rate_final_safe_json']:.5f}"
                 f", phish->LEGIT {e['phish_called_LEGITIMATE_rate']:.5f}/{e['phish_called_LEGITIMATE_rate_final_safe_json']:.5f}"
                 if "legit_flagged_FRAUD_rate" in e else ""), flush=True)

    # ---- the rule re-implementation vs the real CLI
    cli_val = validate_cli(allu, p_all, m, rng)
    assert all(r["n_disagree"] == 0 for r in cli_val["runs"].values()), "rule re-implementation disagrees with CLI"

    # ---- per-class rates (point + domain-cluster bootstrap)
    point, boot, cnt = {}, {}, {}
    for k in names:
        s = sets[k]
        C = class_counts(s["codes"], s["y"], s["group"])
        cnt[k] = C.sum(0)                                       # 2 x nB x 4 row counts
        point[k] = shares_from_counts(cnt[k])                   # 2 x nB x 4
        boot[k] = bootstrap_shares(C, rng)                      # R x 2 x nB x 4
        s["n_groups"] = int(C.shape[0])

    def rates_block(k, cls):
        ci = cls
        out = {}
        for bi, b in enumerate(BASE_RATES):
            if np.isnan(point[k][ci, bi, 0]):
                return None
            n_cls = int(cnt[k][ci, bi].sum())
            out[bkey(b)] = {v: {"count": int(cnt[k][ci, bi, j]), "share": round(float(point[k][ci, bi, j]), 6),
                                "ci95": [round(float(np.nanpercentile(boot[k][:, ci, bi, j], 2.5)), 6),
                                         round(float(np.nanpercentile(boot[k][:, ci, bi, j], 97.5)), 6)],
                                "ci95_exact_binomial": [round(x, 6) for x in
                                                        clopper_pearson(int(cnt[k][ci, bi, j]), n_cls)]}
                            for j, v in enumerate(V)}
        return out

    per_class = {}
    for k in names:
        s = sets[k]
        y = s["y"]
        per_class[k] = {
            "n_phishing": int((y == 1).sum()), "n_legitimate": int((y == 0).sum()), "n_domains": s["n_groups"],
            **s["desc"],
            "bare_homepage_share": {"phishing": float(s["home"][y == 1].mean()) if (y == 1).any() else None,
                                    "legitimate": float(s["home"][y == 0].mean()) if (y == 0).any() else None},
            "phishing": rates_block(k, 1), "legitimate": rates_block(k, 0),
        }

    # ---- rate sets used for the projection: (legit source, phishing source)
    RATE_SETS = {
        "phreshphish_test": ("phreshphish_test", "phreshphish_test"),
        "fresh26_test": ("fresh26_test", "fresh26_test"),
        "hannousse_test": ("hannousse_test", "hannousse_test"),
        "ariyadasa_unseen": ("ariyadasa_unseen", "ariyadasa_unseen"),
        "homepages_tranco": ("tranco_home_unseen", "fresh26_test"),
    }
    proj = {}
    metric_keys = None
    for rs, (lsrc, psrc) in RATE_SETS.items():
        proj[rs] = {"legitimate_rates_from": lsrc, "phishing_rates_from": psrc,
                    "default": {}, "base_rate_equals_prevalence": {}}
        for prev in PREVALENCES:
            for mode, b in (("default", None), ("base_rate_equals_prevalence", prev)):
                bi = BASE_RATES.index(b)
                pt = project(point[psrc][1, bi], point[lsrc][0, bi], prev)
                bt = project(boot[psrc][:, 1, bi], boot[lsrc][:, 0, bi], prev)
                metric_keys = list(pt)
                row = {k2: fmt(k2, v2) for k2, v2 in pt.items()}
                row["ci95"] = {k2: [fmt(k2, np.nanpercentile(bt[k2], 2.5)), fmt(k2, np.nanpercentile(bt[k2], 97.5))]
                               for k2 in ("FRAUD_total", "FRAUD_false_alarms", "FRAUD_true_phishing", "FRAUD_precision",
                                          "REVIEW_total", "LEGITIMATE_missed_phishing", "phishing_share_in_FRAUD",
                                          "phishing_share_in_LEGITIMATE")}
                # exact binomial limits (rows independent) - informative where the bootstrap degenerates
                # (e.g. zero legitimate URLs reached FRAUD in the sample: the bootstrap says [0, 0])
                n_p, n_l = prev * N_TOTAL, (1 - prev) * N_TOTAL
                npc, nlc = int(cnt[psrc][1, bi].sum()), int(cnt[lsrc][0, bi].sum())
                tp_lo, tp_hi = (n_p * x for x in clopper_pearson(int(cnt[psrc][1, bi, 0]), npc))
                fp_lo, fp_hi = (n_l * x for x in clopper_pearson(int(cnt[lsrc][0, bi, 0]), nlc))
                fn_lo, fn_hi = (n_p * x for x in clopper_pearson(int(cnt[psrc][1, bi, 2]), npc))
                row["ci95_exact_binomial"] = {
                    "FRAUD_total": [fmt("FRAUD_total", tp_lo + fp_lo), fmt("FRAUD_total", tp_hi + fp_hi)],
                    "FRAUD_true_phishing": [fmt("FRAUD_true_phishing", tp_lo), fmt("FRAUD_true_phishing", tp_hi)],
                    "FRAUD_false_alarms": [fmt("FRAUD_false_alarms", fp_lo), fmt("FRAUD_false_alarms", fp_hi)],
                    "FRAUD_precision": [fmt("FRAUD_precision", tp_lo / (tp_lo + fp_hi)) if tp_lo + fp_hi > 0 else None,
                                        fmt("FRAUD_precision", tp_hi / (tp_hi + fp_lo)) if tp_hi + fp_lo > 0 else None],
                    "LEGITIMATE_missed_phishing": [fmt("LEGITIMATE_missed_phishing", fn_lo),
                                                   fmt("LEGITIMATE_missed_phishing", fn_hi)],
                }
                cons = {}
                for k2, (blo, bhi) in row["ci95"].items():
                    lo, hi = blo, bhi
                    if k2 in row["ci95_exact_binomial"]:
                        elo, ehi = row["ci95_exact_binomial"][k2]
                        lo = elo if lo is None else (lo if elo is None else min(lo, elo))
                        hi = ehi if hi is None else (hi if ehi is None else max(hi, ehi))
                    cons[k2] = [lo, hi]
                row["ci95_conservative"] = cons
                row["cli_args"] = "default" if b is None else f"--base-rate {b:g}"
                proj[rs][mode][f"{prev:g}"] = row

    # ---- realistic range across rate sets (all five, and mixed batches only = without the homepage-only mix)
    def range_block(members):
        res = {}
        for mode in ("default", "base_rate_equals_prevalence"):
            res[mode] = {}
            for prev in PREVALENCES:
                pk = f"{prev:g}"
                res[mode][pk] = {}
                for k2 in ("FRAUD_total", "FRAUD_false_alarms", "FRAUD_precision", "REVIEW_total",
                           "LEGITIMATE_missed_phishing", "phishing_share_in_FRAUD", "phishing_share_in_LEGITIMATE"):
                    vals = {rs: proj[rs][mode][pk][k2] for rs in members if proj[rs][mode][pk][k2] is not None}
                    lo, hi = min(vals, key=vals.get), max(vals, key=vals.get)
                    res[mode][pk][k2] = {"min": vals[lo], "min_set": lo, "max": vals[hi], "max_set": hi}
        return res

    rng_out = {"all_rate_sets": range_block(list(RATE_SETS)),
               "mixed_batches_only": range_block([r for r in RATE_SETS if r != "homepages_tranco"])}

    # ---- which rate set is most representative (numbers filled from the computations above)
    def lf(k, b="default"):
        return per_class[k]["legitimate"][b]["FRAUD"]

    def pf(k, v, b="default"):
        return per_class[k]["phishing"][b][v]["share"]

    trained_on = final["meta"]["trained_on"]
    f26, ari, phr, tra, han = "fresh26_test", "ariyadasa_unseen", "phreshphish_test", "tranco_home_unseen", "hannousse_test"
    summary = {
        "central_rate_set": f26,
        "why_central": [
            f"newest data ({per_class[f26]['date_range'][0]} to {per_class[f26]['date_range'][1]}), i.e. the phishing "
            f"and web of the year the tool is used; phishing from {', '.join(per_class[f26]['sources']['phishing'])}",
            f"mixed legitimate side ({', '.join(per_class[f26]['sources']['legitimate'])}) with "
            f"{per_class[f26]['bare_homepage_share']['legitimate']:.1%} bare homepages, between PhreshPhish "
            f"({per_class[phr]['bare_homepage_share']['legitimate']:.1%}) and a homepage list (100%)",
            f"its legitimate->FRAUD rate {lf(f26)['share']:.2%} (domain-bootstrap 95% CI {lf(f26)['ci95'][0]:.2%}-"
            f"{lf(f26)['ci95'][1]:.2%}) agrees with the fully external Ariyadasa collection ({lf(ari)['share']:.2%}, "
            f"CI {lf(ari)['ci95'][0]:.2%}-{lf(ari)['ci95'][1]:.2%}), which never contributed training data",
        ],
        "caveats_central": [
            f"small: {per_class[f26]['n_legitimate']:,} legitimate and {per_class[f26]['n_phishing']:,} phishing test URLs "
            f"({per_class[f26]['n_domains']:,} domains), so the false-alarm count at low prevalence is uncertain by about "
            f"+-{(lf(f26)['ci95'][1] - lf(f26)['ci95'][0]) / 2 / lf(f26)['share']:.0%}",
            f"fresh26 carries {trained_on['fresh26']:.0%} of the training weight (other domains, same collection method), so "
            "its rates may be slightly optimistic for a batch collected in a different way",
            "its legitimate side is links posted to Hacker News and Common Crawl pages of popular domains - more "
            "tech/blog content than e.g. an e-mail gateway log",
        ],
        "best_case": {
            "rate_set": phr,
            "why": f"lowest legitimate->FRAUD rate ({lf(phr)['share']:.2%}) and REVIEW share of legitimate URLs "
                   f"({per_class[phr]['legitimate']['default']['REVIEW']['share']:.1%}); real browsing telemetry, but "
                   f"PhreshPhish is {trained_on['phreshphish']:.0%} of the training weight, so this is the model's home "
                   "distribution and an optimistic bound",
        },
        "worst_case": {
            "false_alarms_and_REVIEW": {"rate_set": "homepages_tranco",
                                        "why": f"bare homepages of popular sites: {lf(tra)['share']:.2%} of them FRAUD and "
                                               f"{per_class[tra]['legitimate']['default']['REVIEW']['share']:.1%} REVIEW"},
            "missed_phishing_and_FRAUD_capture": {
                "rate_set": han,
                "why": f"2020-era data: {pf(han, 'LEGITIMATE'):.1%} of phishing called LEGITIMATE and only "
                       f"{pf(han, 'FRAUD'):.1%} reaches FRAUD; among 2026-era external phishing, JPCERT "
                       f"({pf('jpcert_recent_unseen', 'FRAUD'):.1%} to FRAUD, {pf('jpcert_recent_unseen', 'LEGITIMATE'):.1%} "
                       "to LEGITIMATE) is the weakest"},
        },
    }

    out = {
        "what": "Expected verdict mix for 1,000,000 URLs vs true phishing prevalence, default vs --base-rate=prevalence "
                "(safe mode). Counts are expectations: N_class x measured per-class verdict share.",
        "created": time.strftime("%Y-%m-%d"),
        "script": "experiments/project_1m.py",
        "n_total": N_TOTAL, "prevalences": list(PREVALENCES),
        "model": {"file": "fraudurl/data/model_safe.json", "thresholds": m.thresholds,
                  "calibration_base_rate": m.meta["calibration_base_rate"],
                  "min_p_for_FRAUD_by_setting": {bkey(b): fraud_cut(m, b) for b in BASE_RATES},
                  "rule": "FRAUD if p >= th_fraud and p_adj >= 0.5; LEGITIMATE if p <= th_legit and p_adj <= 0.5; "
                          "else REVIEW (fraudurl/cli.py score_rows); p_adj = Model.adjust_prior(p, base_rate)"},
        "bootstrap": {"replicates": N_BOOT, "unit": "registrable domain (the datasets' group column)", "seed": SEED},
        "sanity_checks": sanity,
        "cli_validation": cli_val,
        "per_class_rates": per_class,
        "projection": proj,
        "range_across_rate_sets": rng_out,
        "summary": summary,
        "seconds": round(time.time() - t0, 1),
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, allow_nan=False)
    print("wrote", OUT, flush=True)

    # ---- console tables
    for mode in ("default", "base_rate_equals_prevalence"):
        print(f"\n=== {mode} ===")
        print(f"{'rate set':18} {'prev':>6} {'FRAUD':>8} {'(phish':>8} {'false)':>8} {'prec':>6} {'REVIEW':>8} "
              f"{'(phish':>7} {'legit)':>8} {'LEGIT':>8} {'missed':>7} {'ph->F':>6} {'ph->R':>6} {'ph->L':>6}")
        for rs in RATE_SETS:
            for prev in PREVALENCES:
                r = proj[rs][mode][f"{prev:g}"]
                print(f"{rs:18} {prev:6.3f} {r['FRAUD_total']:8d} {r['FRAUD_true_phishing']:8d} {r['FRAUD_false_alarms']:8d} "
                      f"{r['FRAUD_precision']:6.3f} {r['REVIEW_total']:8d} {r['REVIEW_phishing']:7d} {r['REVIEW_legitimate']:8d} "
                      f"{r['LEGITIMATE_total']:8d} {r['LEGITIMATE_missed_phishing']:7d} {r['phishing_share_in_FRAUD']:6.3f} "
                      f"{r['phishing_share_in_REVIEW']:6.3f} {r['phishing_share_in_LEGITIMATE']:6.3f}")
    shutil.rmtree(TMP, ignore_errors=True)
    print(f"\ntotal {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
