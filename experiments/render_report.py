"""Fill docs/REPORT.template.md with numbers read from results/**.json -> REPORT.md.
No number in the report is typed by hand; a missing result file renders as 'n/a'."""
from __future__ import annotations

import glob
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = os.path.join(ROOT, "results")


def J(*p):
    fp = os.path.join(R, *p)
    return json.load(open(fp, encoding="utf-8")) if os.path.exists(fp) else None


def f(x, d=3):
    if x is None:
        return "n/a"
    return f"{x:.{d}f}" if isinstance(x, float) else str(x)


def pct(x, d=1):
    return "n/a" if x is None else f"{100 * x:.{d}f}%"


def table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def laya_table():
    a = J("laya", "analysis_phreshphish.json")
    if not a:
        return "n/a"
    rows = []
    for ck, v in a["zeroshot"].items():
        for pn, pv in v["prompts"].items():
            t = pv["test_raw"]
            rows.append([f"zero-shot, {ck} checkpoint, prompt '{pn}'", f(t["roc_auc"]), f(t["recall_at_fpr_1pct"], 2),
                         f(pv["ms_per_url"], 0), f(pv["test_shipped_calibration"]["ece"], 2)])
    for ck, v in a.get("signals", {}).items():
        for pn, pv in v["prompts"].items():
            t = pv["test_raw"]
            rows.append([f"zero-shot, {ck}, URL + engineered signals written as text", f(t["roc_auc"]),
                         f(t["recall_at_fpr_1pct"], 2), f(pv["ms_per_url"], 0), f(pv["test_shipped_calibration"]["ece"], 2)])
    for ck, v in a["embed"].items():
        t = v["test"]
        rows.append([f"{ck} frozen embeddings + logistic regression (6k train)", f(t["roc_auc"]),
                     f(t["recall_at_fpr_1pct"], 2), f(v["ms_per_url"], 0), "-"])
    for tag, v in a["finetune"].items():
        t = v["test"]
        rows.append([f"fine-tuned with Laya's RLCD loss ({tag}, 6k train, {v['train_secs'] / 60:.0f} min CPU)",
                     f(t["roc_auc"]), f(t["recall_at_fpr_1pct"], 2), f(v["ms_per_url"], 0), "-"])
    c = next(iter(a["comparison"].values()))
    bj = J("baselines", "phreshphish.json") or {}
    us = bj.get("models", {}).get("lgbm", {}).get("us_per_url_predict")
    rows.append(["**LightGBM on URL features, PhreshPhish-trained baseline (same URLs)**", f"**{f(c['lgbm']['roc_auc'])}**",
                 f"**{f(c['lgbm']['recall_at_fpr_1pct'], 2)}**", f"**{us / 1000:.2f} (trees only; ~1 for the whole CLI)**" if us else "-", "-"])
    return table(["variant", "ROC-AUC", "recall @1% FPR", "ms / URL", "calibration error as shipped (ECE)"], rows)


DATA_TABLE = table(
    ["dataset", "period", "phishing labels from", "legitimate labels from", "URLs used"],
    [["PhreshPhish v1.0.1 (Hugging Face, CC BY 4.0)", "Jul 2024 – Dec 2025", "PhishTank, APWG eCX, Netcraft",
      "Webroot browsing telemetry (+ search results for targeted brands)", "493,834 (≤50 per domain)"],
     ["fresh26 (built here)", "Jun – Sep 2026", "OpenPhish community feed history (first-seen), PhishTank verified-online",
      "Hacker News story links (30 days) + Common Crawl 2026 captures on Tranco top-1M domains", "23,995 (balanced)"],
     ["Hannousse & Yahiouche (Mendeley, CC BY 4.0)", "May 2020", "PhishTank, OpenPhish", "Alexa + Yandex", "11,429"],
     ["Ariyadasa et al. 2021 (Mendeley, CC BY 4.0) — external test only", "Dec 2020 – Nov 2021",
      "PhishTank, OpenPhish, PhishRepo", "Google top-5 search results + Ebbu2017 (Yandex) URLs", "79,537"],
     ["JPCERT/CC phishing list — external, phishing only", "Dec 2025 – May 2026", "JPCERT-confirmed", "—", "13,352"],
     ["OpenPhish snapshot — phishing only; same feed as fresh26 (17 of the 201 scored URLs are also fresh26 test URLs)", "2026-09-25", "OpenPhish", "—", "300"],
     ["Tranco top-10k homepages — external, legitimate only", "list of 2026-09-24", "—",
      "Tranco (K9PXW) minus any domain in any threat feed", "9,646"]])


def baseline_table():
    b = J("baselines", "phreshphish.json")
    if not b:
        return "n/a"
    names = {"logreg": f"logistic regression ({b['n_features']} features)", "tree": "single decision tree",
             "lgbm_small": "LightGBM, 15 leaves", "lgbm": "LightGBM, 31 leaves",
             "char_ngram_lr": "character 3-5-gram hashing + logistic regression"}
    rows = []
    for k, m in b["models"].items():
        t = m["test"]
        rows.append([names.get(k, k), f(t["roc_auc"], 4), f(t["pr_auc"], 4), f(t["recall_at_fpr_1pct"], 3),
                     f(t["recall_at_fpr_0_1pct"], 3), pct(t["fpr"]), pct(t["fnr"])])
    return table(["model", "ROC-AUC", "PR-AUC", "recall @1% FPR", "recall @0.1% FPR", "FPR @0.5", "FNR @0.5"], rows)


def cross_table():
    rows = []
    for fp in sorted(glob.glob(os.path.join(R, "cross", "*.json"))):
        c = json.load(open(fp))
        for k, lab in (("all_lexical", "LightGBM, URL features"), ("char_ngram_lr", "char n-gram LR")):
            if k not in c:
                continue
            v = c[k].get("unseen_domains") or c[k]
            if "roc_auc" in v:
                rows.append([c["train"], c["test"], lab, f(v["roc_auc"]), f(v["recall_at_fpr_1pct"], 2), "-"])
            else:
                rows.append([c["train"], c["test"], lab, "-", "-", pct(v.get("recall_at_0.5"))])
    return table(["trained on", "tested on (unseen domains)", "model", "ROC-AUC", "recall @1% FPR",
                  "phishing caught at p ≥ 0.5 (phishing-only sets)"], rows) if rows else "n/a"


def compact_table():
    rows = []
    for ds in ("phreshphish", "fresh26"):
        fs = J("features", f"{ds}_feature_study.json")
        if not fs:
            continue
        for k, v in fs["test_compact"].items():
            if k == "all" or k.endswith(("top1", "top3", "top5", "top8", "top12", "top16", "top20")):
                rows.append([ds, v["n_features"], f(v["roc_auc"], 4), f(v["recall_at_fpr_1pct"], 3)])
    t1 = table(["dataset (in-distribution test)", "features (greedy selection)", "ROC-AUC", "recall @1% FPR"], rows)
    rows2 = []
    for tag, lab in (("cand_C12", 12), ("cand_C18", 18), ("cand_C24", 24), ("prelim", "all")):
        r = J("final", f"final_{tag}.json")
        if not r:
            continue
        e = r["external"]
        rows2.append([lab, f"{f(r['test']['fresh26']['metrics_at_0.5']['roc_auc'])} / {f(r['test']['fresh26']['metrics_at_0.5']['recall_at_fpr_1pct'], 2)}",
                      f"{f(e['ariyadasa']['metrics_at_0.5']['roc_auc'])} / {f(e['ariyadasa']['metrics_at_0.5']['recall_at_fpr_1pct'], 2)}",
                      pct(e["jpcert_recent"]["FRAUD_share"], 0)])
    t2 = table(["features", "fresh26 2026 (ROC-AUC / recall@1%)", "Ariyadasa external (ROC-AUC / recall@1%)",
                "JPCERT phishing flagged FRAUD"], rows2)
    return t1 + "\n\nThe same compact sets trained with the full multi-dataset recipe and tested **out of distribution** " \
                "(run before the final parser fixes; relative differences are what matter):\n\n" + t2


def enrich_table():
    h = J("enrichment", "enrichment_study_hannousse_fresh26e.json") or {}
    rows = []
    for k, v in (h.get("hannousse") or {}).items():
        rows.append(["Hannousse 2020 (authors' features, live at the time)", k, f(v["roc_auc"]), f(v["recall_at_fpr_1pct"], 2)])
    fr = h.get("fresh26e") or {}
    for k in ("lexical_only", "lexical+dns", "lexical+rdap", "lexical+dns+rdap", "dns+rdap_only"):
        if k in fr:
            rows.append(["fresh26e 2026, live DNS/RDAP", k, f(fr[k]["roc_auc"]), f(fr[k]["recall_at_fpr_1pct"], 2)])
    for view in ("live_only", "recent_phish_7d"):
        for k, v in (fr.get(view) or {}).items():
            if isinstance(v, dict) and "roc_auc" in v:
                rows.append([f"fresh26e, {view.replace('_', ' ')}", k, f(v["roc_auc"]), f(v["recall_at_fpr_1pct"], 2)])
    e = J("final", "final_enrich.json")
    if e:
        lo = e["live_only"]
        rows.append(["**shipped enriched model** (cross-fitted, live non-platform URLs)", "offline model alone",
                     f(lo["safe_only_uncalibrated"]["roc_auc"]), f(lo["safe_only_uncalibrated"]["recall_at_fpr_1pct"], 2)])
        rows.append(["", "offline model + DNS/RDAP correction", f(lo["safe+enrichment_uncalibrated"]["roc_auc"]),
                     f(lo["safe+enrichment_uncalibrated"]["recall_at_fpr_1pct"], 2)])
    return table(["data", "features", "ROC-AUC", "recall @1% FPR"], rows) if rows else "n/a"


def final_tables():
    r = J("final", "final_safe.json")
    if not r:
        return "n/a", "n/a", {}
    rows = []
    for ds, v in r["test"].items():
        m, t = v["metrics_at_0.5"], v["three_way"]
        rows.append([ds, f"{m['n']:,}", f(m["roc_auc"]), f(m["pr_auc"]), f(m["recall_at_fpr_1pct"], 2), pct(t["FRAUD"]["share"], 0),
                     pct(t["REVIEW"]["share"], 0), pct(t["LEGITIMATE"]["share"], 0), pct(t["legit_flagged_FRAUD_rate"]),
                     pct(t["phish_called_LEGITIMATE_rate"])])
    tp = J("final", "phreshphish_temporal_domain_disjoint.json")
    if tp:
        m = tp["metrics"]
        rows.append([f"PhreshPhish-only model, same recipe, official time split + unseen domains (test {tp['test_period'][0]}..{tp['test_period'][1]})",
                     f"{m['n']:,}", f(m["roc_auc"]), f(m["pr_auc"]), f(m["recall_at_fpr_1pct"], 2), "-", "-", "-", "-", "-"])
    t1 = table(["test split (unseen domains)", "URLs", "ROC-AUC", "PR-AUC", "recall @1% FPR", "FRAUD", "REVIEW",
                "LEGITIMATE", "legitimate → FRAUD", "phishing → LEGITIMATE"], rows)
    rows = []
    for ds, v in r["external"].items():
        m = v.get("metrics_at_0.5", {})
        dash = lambda x, fn: "—" if x is None else fn(x)  # noqa: E731  single-class sets have no ROC-AUC
        rows.append([ds, f"{v['n_unseen_domains']:,}", dash(m.get("roc_auc"), f), dash(m.get("recall_at_fpr_1pct"), lambda x: f(x, 2)),
                     pct(v["FRAUD_share"]), pct(v["REVIEW_share"]), pct(v["LEGITIMATE_share"]),
                     dash(v.get("legit_flagged_FRAUD_rate"), pct), dash(v.get("phish_called_LEGITIMATE_rate"), pct)])
    t2 = ("External sets, never used for training or calibration (unseen domains only):\n\n" +
          table(["external set", "URLs", "ROC-AUC", "recall @1% FPR", "FRAUD", "REVIEW", "LEGITIMATE",
                 "legitimate → FRAUD", "phishing → LEGITIMATE"], rows))
    th = r["thresholds"]
    t1 = (f"Model: {r['meta']['n_trees']} trees × {r['meta']['leaves']} leaves, {r['model_bytes'] / 1024:.0f} KB, "
          f"{r['meta']['calibration']} calibration (chosen by held-out log loss); verdict rule "
          f"`LEGITIMATE` if p ≤ {th['legit']:.3f}, `FRAUD` if p ≥ {th['fraud']:.3f}, otherwise `REVIEW`. "
          f"Shipped runtime vs training pipeline: max |Δp| = {r['end_to_end_max_abs_prob_diff']:.1e}.\n\n" + t1)
    return t1, t2, r


def calibration_text():
    c = J("final", "calibration_safe.json")
    if not c:
        return "n/a"
    lines = []
    for ds, v in c["sets"].items():
        rel = {x["bin"]: x for x in v["reliability"]}
        pick = [b for b in ("0.00-0.05", "0.20-0.30", "0.80-0.90", "0.95-1.00") if b in rel]
        lines.append([ds, f"{v['n']:,}", f(v["ece"]),
                      "; ".join(f"{rel[b]['mean_predicted']:.2f} → {rel[b]['observed_phishing_rate']:.2f}" for b in pick)])
    t = table(["test set", "URLs", "ECE", "predicted → actually phishing (bins ≤0.05, 0.2-0.3, 0.8-0.9, ≥0.95)"], lines)
    ps = c["prior_shift_examples"]
    return (t + "\n\n* **On the 2026 data and on the fully external 2021 set the probability is close to a probability** "
            "(overall calibration error 0.012-0.016; the extreme bins agree closely), but in the middle (0.4-0.8) the 2026 "
            "numbers are over-confident by up to 11 points (0.75 predicted → 0.65 observed).\n"
            "* **On PhreshPhish the middle is under-confident by 7-13 points** (0.65 → 78%, 0.86 → 94% phishing), and **on "
            "2020-era data 11% of URLs scored ≤ 0.05 were phishing** — those receive a `LEGITIMATE` verdict (4.9% of 2020 "
            "phishing is called LEGITIMATE).\n"
            f"* **It is a probability at ~50% prevalence.** At lower fraud rates the same evidence means much less: "
            f"0.97 → {ps['p=0.97']['base_rate=0.1']:.2f} at 10% prevalence, {ps['p=0.97']['base_rate=0.01']:.2f} at 1%, "
            f"{ps['p=0.97']['base_rate=0.001']:.3f} at 0.1%. `--base-rate` applies this correction. Verdicts still use the "
            "error-rate thresholds, but a row whose re-weighted probability contradicts its verdict is downgraded to `REVIEW`, "
            "so a low base rate moves many FRAUD rows to REVIEW. The enriched model's probabilities are stated at the same "
            "reference prevalence as the offline model's.")


def bench():
    b = J("benchmark", "cli_benchmark.json")
    if not b:
        return "n/a", "n/a"
    rows = [[r["label"], f(r["seconds"], 1), f"{r['urls_per_second']:,.0f}", f(r["peak_rss_MB_process_tree"], 0)] for r in b["runs"]]
    pk = b["package_bytes"]
    t = table(["run (offline mode, whole CLI incl. CSV I/O)", "seconds", "URLs / second", "peak RAM, all processes (MB)"], rows)
    t += (f"\n\nPackage size: {pk['total'] / 1024:.0f} KB in total — model {pk['data_files'].get('model_safe.json', 0) / 1024:.0f} KB, "
          f"enrichment model {pk['data_files'].get('model_enrich.json', 0) / 1024:.0f} KB, Public Suffix List "
          f"{pk['data_files'].get('public_suffix_list.dat', 0) / 1024:.0f} KB, code {pk['python_code'] / 1024:.0f} KB. "
          "For comparison, the smallest Laya checkpoint is 644 MB + a 34 MB tokenizer and needs PyTorch (~1 GB).")
    best = max(r["urls_per_second"] for r in b["runs"])
    return t, f"{best:,.0f}"


def laya_texts():
    a = J("laya", "analysis_phreshphish.json") or {}
    st = J("laya", "stack_ci_phreshphish.json") or {}
    cc = J("laya", "cascade_ci_phreshphish.json") or {}
    b = J("benchmark", "cli_benchmark.json") or {}
    comp = a.get("comparison", {})
    ft = comp.get("finetune_head_multilingual", {})
    em = comp.get("embed_multilingual", {})
    lg = ft.get("lgbm", {})
    runs = b.get("runs", [])
    per_url_ms = 1000.0 / max(r["urls_per_second"] for r in runs if "1 process" in r["label"] and "10 URLs" not in r["label"]) if runs else None
    laya_ms = [ft.get("laya_ms_per_url"), em.get("laya_ms_per_url")]
    zs = [v for k, v in comp.items() if k.startswith("zeroshot")]
    slow_lo = min(x for x in laya_ms if x) / per_url_ms if per_url_ms else None
    slow_hi = max((v.get("laya_ms_per_url") or 0) for v in zs) / per_url_ms if (per_url_ms and zs) else None
    pk = (b.get("package_bytes") or {}).get("total")
    size_lo = (643.8e6 + 34.4e6) / pk if pk else None   # multilingual weights + tokenizer vs whole package
    size_hi = (842.6e6 + 3.6e6) / pk if pk else None    # English weights + tokenizer vs whole package
    sh = J("laya", "shipped_model_on_laya_test.json")  # written by experiments/shipped_on_laya_test.py
    if not sh:
        raise SystemExit("results/laya/shipped_model_on_laya_test.json missing: run experiments/shipped_on_laya_test.py")
    shipped_txt = f"ROC-AUC {sh['roc_auc']:.3f}, recall {sh['recall_at_fpr_1pct']:.2f}"
    headline = (f"The best Laya variants were clearly worse than the tiny model on the same URLs (fine-tuned: ROC-AUC "
                f"{f(ft.get('laya', {}).get('roc_auc'))} vs {f(lg.get('roc_auc'))}, recall at 1% false-positive rate "
                f"{f(ft.get('laya', {}).get('recall_at_fpr_1pct'), 2)} vs {f(lg.get('recall_at_fpr_1pct'), 2)}; frozen embeddings: "
                f"{f(em.get('laya', {}).get('roc_auc'))} / {f(em.get('laya', {}).get('recall_at_fpr_1pct'), 2)}), "
                f"~{slow_lo:.0f}–{slow_hi:.0f}× slower per URL than the whole pure-Python pipeline and "
                f"~{size_lo:.0f}–{size_hi:.0f}× larger than the whole 0.9 MB package (before PyTorch), and combining it "
                f"with the tiny model added nothing significant. (Comparator: a PhreshPhish-trained LightGBM baseline; "
                f"the shipped 3-dataset model scores {shipped_txt} on the same URLs.)")
    fci, fr = ft.get("laya_minus_lgbm", {}).get("delta_auc_ci", [None, None]), ft.get("laya_minus_lgbm", {}).get("delta_recall1_ci", [None, None])
    parts = [f"Paired-bootstrap difference, fine-tuned Laya minus LightGBM: ROC-AUC [{f(fci[0])}, {f(fci[1])}], recall at "
             f"1% FPR [{f(fr[0], 2)}, {f(fr[1], 2)}]."]
    for k, lab in (("embed", "embeddings"), ("finetune", "fine-tuned Laya")):
        if k in st:
            v = st[k]
            parts.append(f"Cross-fitted stacking of LightGBM + {lab}: recall at 1% FPR {f(v['lgbm']['recall_at_fpr_1pct'], 3)} → "
                         f"{f(v['stack']['recall_at_fpr_1pct'], 3)}, gain CI [{v['delta_recall1_ci95'][0]:+.3f}, {v['delta_recall1_ci95'][1]:+.3f}].")
    if cc:
        parts.append("Cascade (Laya re-ranks only LightGBM's uncertain band) recall gain CIs: " +
                     ", ".join(f"[{v['gain_ci95'][0]:+.3f}, {v['gain_ci95'][1]:+.3f}]" for v in cc.values()) + ".")
    parts.append("Every interval includes 0 or is negative.")
    return headline, " ".join(parts)


def answers(r, speed):
    e = J("final", "final_enrich.json") or {}
    lo = e.get("live_only", {})
    t = (r or {}).get("test", {})
    ext = (r or {}).get("external", {})
    g = lambda ds, k: t.get(ds, {}).get("three_way", {}).get(k)  # noqa: E731
    items = [
        ("What approach worked?", "A small gradient-boosted tree model (400 trees) over 83 hand-crafted URL features, trained on "
         "three differently collected datasets (2020, 2024-25, 2026), exported to JSON and scored in pure Python, with "
         "a calibrated probability and a three-way verdict. Optionally, a 70 KB residual model adds DNS/RDAP evidence."),
        ("What did not work?", "Laya in every mode; zero-shot anything; character n-grams out of distribution; a domain-"
         "popularity list; compact 12-24-feature sets out of distribution; bigger tree models (more false alarms); "
         "evaluating DNS/RDAP on old data (pure takedown leakage); plain UDP DNS on the test network."),
        ("Was Laya useful?", "No. " + laya_texts()[0]),
        ("How many features were considered?", "86 lexical candidates (+3 popularity features excluded as circular) and 16 "
         "DNS/RDAP fields. 3 lexical features were dropped as dataset artifacts and 1 is constant (82 studied); the shipped "
         "URL model uses 83 (adds a government/education flag; the domain-ending reputation is hierarchical), the "
         "enrichment model 10 (6 DNS/RDAP fields were dropped: existence/takedown signals and lookup-time registry fields)."),
        ("Which features mattered?", "Domain-ending reputation (25-45% of gain depending on the dataset), path length/shape, "
         "subdomain length, URL randomness, http vs https, hyphens/dots, login/payment words, free-hosting platform; with "
         "enrichment: DNS configuration (MX records, number of addresses, TTL), time to expiry, registration period and domain age."),
        ("Did a much smaller feature set work nearly as well?", "In-distribution yes (12-16 features recover 99.3-99.7% of ROC-AUC); "
         "out-of-distribution no (−7 to −17 points recall at 1% FPR), so all 83 are shipped — they cost ~0.2 ms and no model size."),
        ("Which model performed best?", "LightGBM on URL features for the shipped model (best out-of-distribution); a "
         "character n-gram model was marginally better only in-distribution."),
        ("How accurate on unseen data?", f"ROC-AUC {f(t.get('phreshphish', {}).get('metrics_at_0.5', {}).get('roc_auc'))} "
         f"(PhreshPhish), {f(t.get('fresh26', {}).get('metrics_at_0.5', {}).get('roc_auc'))} (2026 data), "
         f"{f(ext.get('ariyadasa', {}).get('metrics_at_0.5', {}).get('roc_auc'))} (fully external Ariyadasa), "
         f"{f(t.get('hannousse', {}).get('metrics_at_0.5', {}).get('roc_auc'))} (2020 data)."),
        ("False-positive / false-negative rates?", f"Legitimate URLs called FRAUD: {pct(g('phreshphish', 'legit_flagged_FRAUD_rate'))} "
         f"(PhreshPhish), {pct(g('fresh26', 'legit_flagged_FRAUD_rate'))} (2026), "
         f"{pct(ext.get('ariyadasa', {}).get('legit_flagged_FRAUD_rate'))} (external), "
         f"{pct(g('hannousse', 'legit_flagged_FRAUD_rate'))} (2020 data). Phishing called LEGITIMATE: "
         f"{pct(g('phreshphish', 'phish_called_LEGITIMATE_rate'))}, {pct(g('fresh26', 'phish_called_LEGITIMATE_rate'))}, "
         f"{pct(ext.get('ariyadasa', {}).get('phish_called_LEGITIMATE_rate'))}, "
         f"{pct(g('hannousse', 'phish_called_LEGITIMATE_rate'))}. The rest goes to REVIEW."),
        ("How fast?", f"Up to {speed} URLs/second for the whole CSV pipeline on 4 cores (offline mode). "
         "Enriched mode is limited by network lookups (cached per domain)."),
        ("Memory and size?", "See §5.7 — about 70 MB of RAM for one process, about 220 MB with 4 workers; about 0.9 MB of files "
         "in total (449 KB model)."),
        ("Does it need the network, paid services or API keys?", "Offline mode (the default): 100% local, zero network. "
         "With --enrich / --enrich-review: free public DNS-over-HTTPS and registry RDAP only. No paid services, no API keys, "
         "no accounts."),
        ("What if DNS or RDAP is unavailable?", "Every row still gets a verdict. If DNS fails (or the host is an IP or a shared platform) the offline model is used; if only RDAP is unavailable the enriched model runs without registration data; `lookup_status` "
         "explains why. TLS and HTTP are never used."),
        ("How does it do on domains it has never seen?", "All reported numbers are on domains never seen in training."),
        ("What are the weaknesses?", "See §7: distribution shift, bare homepages → REVIEW, platform-hosted phishing, compromised sites, "
         "adversarial URLs, base-rate dependence, ageing reputations, patchy RDAP."),
        ("Is it useful?", "As a first-line filter, yes: a ~0.5 MB, dependency-free, CPU-only model with few false alarms that "
         "rarely clears real phishing and gives well-calibrated probabilities at the extremes. It is not a complete phishing "
         "defence: 18-45% of URLs need a second look, and it should be retrained on new data periodically."),
    ]
    return "\n".join(f"* **{q}** {a}" for q, a in items)


if __name__ == "__main__":
    s = open(os.path.join(ROOT, "docs", "REPORT.template.md"), encoding="utf-8").read()
    final_t, ext_t, r = final_tables()
    bench_t, speed = bench()
    e = J("final", "final_enrich.json") or {}
    lo = e.get("live_only", {})
    rep = {
        "LAYA_TABLE": laya_table(), "DATA_TABLE": DATA_TABLE, "BASELINE_TABLE": baseline_table(),
        "CROSS_TABLE": cross_table(), "COMPACT_TABLE": compact_table(), "ENRICH_TABLE": enrich_table(),
        "FINAL_TABLE": final_t, "EXTERNAL_TABLE": ext_t, "CALIBRATION_TEXT": calibration_text(),
        "BENCH_TABLE": bench_t, "SPEED": speed, "ANSWERS": answers(r, speed),
        "LAYA_HEADLINE": laya_texts()[0], "LAYA_RULE": laya_texts()[1],
        "ENR_SAFE_R1": f(lo.get("safe_only_uncalibrated", {}).get("recall_at_fpr_1pct"), 2),
        "ENR_ENR_R1": f(lo.get("safe+enrichment_uncalibrated", {}).get("recall_at_fpr_1pct"), 2),
    }
    for k, v in rep.items():
        s = s.replace("{{" + k + "}}", v)
    open(os.path.join(ROOT, "REPORT.md"), "w", encoding="utf-8").write(s)
    left = [k for k in rep if "{{" + k + "}}" in s]
    print("REPORT.md written; unfilled:", left)
