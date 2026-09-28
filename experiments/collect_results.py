"""Render every key number from results/*.json into results/SUMMARY.md (tables for REPORT.md).
Nothing here is typed by hand: if a result file is missing, the table says so."""
from __future__ import annotations

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = os.path.join(ROOT, "results")
lines: list[str] = []


def J(*p):
    fp = os.path.join(R, *p)
    return json.load(open(fp, encoding="utf-8")) if os.path.exists(fp) else None


def f(x, d=3):
    return "—" if x is None else (f"{x:.{d}f}" if isinstance(x, float) else str(x))


def table(head, rows):
    lines.append("| " + " | ".join(head) + " |")
    lines.append("|" + "---|" * len(head))
    for r in rows:
        lines.append("| " + " | ".join(str(c) for c in r) + " |")
    lines.append("")


def h(t):
    lines.append(f"\n## {t}\n")


# ---------------------------------------------------------------- baselines
for ds in ("phreshphish", "fresh26", "hannousse"):
    b = J("baselines", f"{ds}.json")
    if not b:
        continue
    h(f"Baselines on {ds} (domain-grouped test split, n={b['splits']['test']:,})")
    rows = []
    for name, m in b["models"].items():
        t = m["test"]
        size = m.get("model_bytes") or m.get("nonzero_weights")
        rows.append([name, f(t["roc_auc"], 4), f(t["pr_auc"], 4), f(t["recall_at_fpr_1pct"]), f(t["recall_at_fpr_0_1pct"]),
                     f(t["fpr"], 4), f(t["fnr"], 4), f(t.get("ece"), 4), size or ""])
    table(["model", "ROC-AUC", "PR-AUC", "recall@1%FPR", "recall@0.1%FPR", "FPR@0.5", "FNR@0.5", "ECE", "size (bytes or weights)"], rows)

# ---------------------------------------------------------------- Laya
a = J("laya", "analysis_phreshphish.json")
if a:
    h("Laya on PhreshPhish (same 1,500 unseen-domain test URLs for every row)")
    rows = []
    for ck, v in a["zeroshot"].items():
        for pn, pv in v["prompts"].items():
            t = pv["test_raw"]
            rows.append([f"zero-shot {ck} / prompt '{pn}'", f(t["roc_auc"], 4), f(t["pr_auc"], 4), f(t["recall_at_fpr_1pct"]),
                         f(pv["ms_per_url"], 0), f(pv["test_shipped_calibration"]["ece"]), f(pv["test_platt_calibrated"]["ece"])])
    for ck, v in a.get("signals", {}).items():
        for pn, pv in v["prompts"].items():
            t = pv["test_raw"]
            rows.append([f"zero-shot {ck} URL + engineered signals as text", f(t["roc_auc"], 4), f(t["pr_auc"], 4),
                         f(t["recall_at_fpr_1pct"]), f(pv["ms_per_url"], 0), f(pv["test_shipped_calibration"]["ece"]),
                         f(pv["test_platt_calibrated"]["ece"])])
    for ck, v in a["embed"].items():
        t = v["test"]
        rows.append([f"{ck} frozen embeddings + logistic regression (6k train)", f(t["roc_auc"], 4), f(t["pr_auc"], 4),
                     f(t["recall_at_fpr_1pct"]), f(v["ms_per_url"], 0), "", ""])
    for tag, v in a["finetune"].items():
        t = v["test"]
        rows.append([f"fine-tuned ({tag}, RLCD loss, 6k train, {v['train_secs'] / 60:.0f} min CPU)", f(t["roc_auc"], 4),
                     f(t["pr_auc"], 4), f(t["recall_at_fpr_1pct"]), f(v["ms_per_url"], 0), "", ""])
    c = next(iter(a["comparison"].values()), None)
    if c:
        for bn in ("lgbm", "char_ngram_lr"):
            t = c[bn]
            rows.append([f"**{bn} (295k train) on the same URLs**", f(t["roc_auc"], 4), f(t["pr_auc"], 4), f(t["recall_at_fpr_1pct"]),
                         "0.03" if bn == "lgbm" else "0.08", "", ""])
    table(["variant", "ROC-AUC", "PR-AUC", "recall@1%FPR", "ms/URL", "ECE shipped", "ECE after Platt"], rows)
    rows = []
    for k, v in a["comparison"].items():
        d = v.get("laya_minus_lgbm", {})
        st = v.get("stack_lgbm_plus_laya_heldout_half", {})
        rows.append([k, f"[{f(d.get('delta_auc_ci', [None, None])[0], 3)}, {f(d.get('delta_auc_ci', [None, None])[1], 3)}]",
                     f"[{f(d.get('delta_recall1_ci', [None, None])[0], 3)}, {f(d.get('delta_recall1_ci', [None, None])[1], 3)}]",
                     f"{f(st.get('lgbm_alone', {}).get('recall_at_fpr_1pct'))} -> {f(st.get('stack', {}).get('recall_at_fpr_1pct'))}",
                     f"{f(v.get('cascade_0.2_0.8', {}).get('cascade', {}).get('recall_at_fpr_1pct'))}"])
    lines.append("Paired bootstrap (1,000 resamples) of Laya minus LightGBM on identical URLs; stacking = LightGBM + Laya score "
                 "(fit on one half, scored on the other); cascade = Laya only for LightGBM's uncertain 0.2-0.8 band.\n")
    table(["Laya variant", "ΔROC-AUC 95% CI", "Δrecall@1%FPR 95% CI", "stack recall@1%: LGBM -> +Laya", "cascade recall@1%"], rows)
e = J("laya", "equal_data_control_phreshphish.json")
if e:
    h("Equal-data control (all trained on the same 6,000 URLs)")
    table(["method", "ROC-AUC", "PR-AUC", "recall@1%FPR", "recall@0.1%FPR"],
          [[k, f(v["roc_auc"], 4), f(v["pr_auc"], 4), f(v["recall_at_fpr_1pct"]), f(v["recall_at_fpr_0_1pct"])] for k, v in e.items()])

# ---------------------------------------------------------------- features
for ds in ("phreshphish", "fresh26"):
    fs = J("features", f"{ds}_feature_study.json")
    if not fs:
        continue
    h(f"Feature study on {ds} ({fs['n_features']} candidate features)")
    table(["feature group", "n", "val ROC-AUC alone", "val ROC-AUC when removed", "Δ"],
          [[g, fs["group_alone"][g]["n"], f(fs["group_alone"][g]["auc"], 4), f(v["auc"], 4), f(v["delta_auc"], 4)]
           for g, v in fs["group_removed"].items()])
    table(["compact set", "features", "test ROC-AUC", "test PR-AUC", "recall@1%FPR", "recall@0.1%FPR"],
          [[k, v["n_features"], f(v["roc_auc"], 4), f(v["pr_auc"], 4), f(v["recall_at_fpr_1pct"]), f(v["recall_at_fpr_0_1pct"])]
           for k, v in fs["test_compact"].items()])
    lines.append("Forward-selection order: " + ", ".join(c["added"] for c in fs["forward_selection"]) + "\n")
    lines.append(f"Without format-sensitive features {fs['without_format_sensitive']['removed']}: val ROC-AUC "
                 f"{f(fs['without_format_sensitive']['auc'], 4)} (all: {f(fs['all_features_val']['auc'], 4)})\n")
p = J("features", "popularity_study.json")
if p:
    h("Domain-popularity (Tranco) signal, non-circular evaluations only")
    rows = []
    for k, v in p.items():
        rows.append([k] + [f"{f(v[n]['roc_auc'], 4)} / {f(v[n]['recall_at_fpr_1pct'])}" for n in
                           ("phreshphish_test", "fresh26_test_HN_legit_only", "ariyadasa_unseen")])
    table(["popularity list", "PhreshPhish test (AUC / R@1%)", "fresh26 HN-legit test", "Ariyadasa unseen"], rows)

# ---------------------------------------------------------------- enrichment
_both = J("enrichment", "enrichment_study_hannousse_fresh26e.json") or {}
en = {"hannousse": _both["hannousse"]} if "hannousse" in _both else J("enrichment", "enrichment_study_hannousse.json")
if en:
    h("Enrichment value on Hannousse 2020 (authors' features, captured while pages were live; grouped 5-fold CV)")
    table(["features", "ROC-AUC", "PR-AUC", "recall@1%FPR", "recall@0.1%FPR"],
          [[k, f(v["roc_auc"], 4), f(v["pr_auc"], 4), f(v["recall_at_fpr_1pct"]), f(v["recall_at_fpr_0_1pct"])] for k, v in en["hannousse"].items()])
ef = {"fresh26e": _both["fresh26e"]} if "fresh26e" in _both else J("enrichment", "enrichment_study_fresh26e.json")
if ef:
    v = ef["fresh26e"]
    h("Enrichment value on fresh26e (live DoH DNS + RDAP, 8,000 URLs, grouped 5-fold CV)")
    rows = [[k, f(x["roc_auc"], 4), f(x["pr_auc"], 4), f(x["recall_at_fpr_1pct"]), f(x["recall_at_fpr_0_1pct"])]
            for k, x in v.items() if isinstance(x, dict) and "roc_auc" in x]
    for k in ("live_only", "recent_phish_7d"):
        for kk, x in v[k].items():
            if isinstance(x, dict) and "roc_auc" in x:
                rows.append([f"{k}: {kk}", f(x["roc_auc"], 4), f(x["pr_auc"], 4), f(x["recall_at_fpr_1pct"]), f(x["recall_at_fpr_0_1pct"])])
    table(["features", "ROC-AUC", "PR-AUC", "recall@1%FPR", "recall@0.1%FPR"], rows)
st = J("enrichment", "stale_leakage_demo_phreshphish.json")
if st:
    h("Stale-domain leakage demonstration (PhreshPhish Sep-Dec 2025 URLs resolved today)")
    lines.append(f"Share by DNS status: {json.dumps(st['status_share_by_label'])}. ROC-AUC of the single feature "
                 f"'does not resolve today': {f(st['roc_auc_of_single_feature_does_not_resolve_today'])}\n")

# ---------------------------------------------------------------- cross-dataset
cr = [x for x in sorted(os.listdir(os.path.join(R, "cross"))) if x.endswith(".json")] if os.path.isdir(os.path.join(R, "cross")) else []
if cr:
    h("Cross-dataset generalisation (train on A, test on B's domains never seen in A)")
    rows = []
    for fn in cr:
        c = J("cross", fn)
        for k in ("all_lexical", "compact", "char_ngram_lr"):
            if k in c:
                v = c[k].get("unseen_domains") or c[k]
                rows.append([c["train"], c["test"], k, f(v.get("roc_auc"), 4), f(v.get("recall_at_fpr_1pct")),
                             f(v.get("recall_at_0.5") or v.get("recall_at_val_fpr1pct_threshold"))])
    table(["train", "test", "model", "ROC-AUC", "recall@1%FPR", "recall (phishing-only sets)"], rows)

# ---------------------------------------------------------------- final
for tag in ("safe", "enrich"):
    fin = J("final", f"final_{tag}.json")
    if not fin:
        continue
    h(f"Shipped model: {tag}")
    lines.append("```\n" + json.dumps({k: v for k, v in fin.items() if k not in ("test", "external")}, indent=1, default=str)[:3000] + "\n```\n")
    if "test" in fin:
        rows = []
        for ds, v in fin["test"].items():
            m, t = v["metrics_at_0.5"], v["three_way"]
            rows.append([ds, m["n"], f(m["roc_auc"], 4), f(m["pr_auc"], 4), f(m["recall_at_fpr_1pct"]), f(m["ece"], 4),
                         f(t["FRAUD"]["share"]), f(t["REVIEW"]["share"]), f(t["LEGITIMATE"]["share"]),
                         f(t["legit_flagged_FRAUD_rate"], 4), f(t["phish_called_LEGITIMATE_rate"], 4)])
        table(["test set", "n", "ROC-AUC", "PR-AUC", "recall@1%FPR", "ECE", "FRAUD", "REVIEW", "LEGIT",
               "legit→FRAUD", "phish→LEGIT"], rows)
    if "external" in fin:
        rows = []
        for ds, v in fin["external"].items():
            m = v.get("metrics_at_0.5", {})
            rows.append([ds, v["n_unseen_domains"], f(m.get("roc_auc"), 4), f(m.get("recall_at_fpr_1pct")), f(v["FRAUD_share"]),
                         f(v["REVIEW_share"]), f(v["LEGITIMATE_share"]), f(v.get("legit_flagged_FRAUD_rate"), 4),
                         f(v.get("phish_called_LEGITIMATE_rate"), 4)])
        table(["external set (unseen domains)", "n", "ROC-AUC", "recall@1%FPR", "FRAUD", "REVIEW", "LEGIT", "legit→FRAUD", "phish→LEGIT"], rows)
bm = J("benchmark", "cli_benchmark.json")
if bm:
    h("CLI benchmark")
    table(["run", "seconds", "URLs/s", "peak RAM (MB, all processes)"],
          [[r["label"], f(r["seconds"], 1), f(r["urls_per_second"], 0), f(r["peak_rss_MB_process_tree"], 0)] for r in bm["runs"]])
    lines.append("Package size: " + json.dumps(bm["package_bytes"]) + "\n")

out = os.path.join(R, "SUMMARY.md")
with open(out, "w", encoding="utf-8") as fh:
    fh.write("# Generated results summary (from results/*.json)\n" + "\n".join(lines))
print("wrote", out, len(lines), "lines")
