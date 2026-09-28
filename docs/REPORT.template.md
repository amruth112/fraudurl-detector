# fraudurl — engineering report

*Experiment run end-to-end on 2026-09-25 on one Windows 10 desktop (Intel i5-7500, 4 cores, 16 GB RAM; its GTX 1650
GPU was not used — every run was CPU-only). The result tables in §5 and most figures elsewhere are generated from the
JSON files in `results/` by `experiments/render_report.py`; the data table (§3), the Laya cost figures (§2) and some
narrative numbers were written by hand from those files and the run logs, and were then checked against them in a
separate audit pass. Much of the research, coding and reviewing was done with the help of AI coding agents; every
result comes from a run recorded in `results/`, and estimates are labelled as estimates.*

---

## 0. The short version

**It works, within honest limits.** A 450 KB gradient-boosted tree model over 83 features computed from the URL
string alone, run by ~2,100 lines of pure standard-library Python, separates phishing from legitimate URLs with
ROC-AUC 0.96–0.98 on domains it has never seen (0.91 on 2020-era data), flags only 0.3–1.8% of legitimate URLs as
FRAUD on the test and external sets (3% of bare homepages of popular sites), and calls only 1.6–2.6% of phishing
URLs "LEGITIMATE" (3.5% of a small OpenPhish snapshot taken on 2026-09-25, 4.9% on 2020-era data); the rest goes to REVIEW. It needs no GPU, no network, no API key, no database and no
third-party Python package. It scores {{SPEED}} URLs per second on 4 CPU cores (~1,000 per core).

**Comparison with Laya (an open, general-purpose text-decision model, tested as a possible replacement for, or addition to, the hand-made features): no benefit.** It was installed, run and tested five different ways (zero-shot with three
prompts on two checkpoints, URL + engineered signals as text, frozen embeddings, fine-tuning with its own loss,
stacking/cascading). {{LAYA_HEADLINE}} A decision rule fixed in advance rejected it in every mode.

**Limitations:** from the URL text alone, (1) performance drops sharply when the data comes from a
different collection or year (ROC-AUC 0.95–0.99 in-distribution → 0.85–0.96 on other collections), (2) 18–45% of
URLs (about a quarter on 2026 data) end up in `REVIEW` because the text is genuinely ambiguous — above all bare homepages
(`https://example.com/`), which look exactly like phishing landing pages, and (3) phishing hosted on
legitimate platforms (Google Docs/Sites/Forms, Weebly) is the hardest case. Optional DNS + domain
registration lookups help measurably — on live 2026 URLs outside shared platforms, recall at 1% false positives
rises from 0.43 to 0.58 — but only for phishers' own domains, and on popular sites' bare homepages they cut the
share left in REVIEW from 76% to 63%.

---

## 1. What was built

```
CSV in ──► detect encoding / delimiter / header / URL column (streaming, chunked)
        ──► parse URL like a browser; split host with the Public Suffix List (vendored, 327 KB)
        ──► 83 lexical features (pure Python, ~0.2 ms/URL)                      [offline mode: no network]
        ──► [optional --enrich / --enrich-review] DNS over HTTPS (Cloudflare) + RDAP registry data, cached
        ──► 400-tree LightGBM model evaluated by a 60-line pure-Python tree walker (model_safe.json, 450 KB)
        ──► [optional] 70 KB residual model adds a DNS/RDAP correction to the log-odds (model_enrich.json)
        ──► Platt calibration ──► FRAUD / REVIEW / LEGITIMATE + probability + 3 plain-English reasons
CSV out (all original columns + 8 result columns)
```

* **Run it:** `python -m fraudurl input.csv` (details in `README.md`).
* **Dependencies at run time:** none beyond Python 3.9+ (LightGBM is only used to *train*; the exported model is
  JSON and is scored by `fraudurl/model.py`, verified to reproduce LightGBM to 1e-14).
* **Reasons** are the model's own per-feature contributions (path attribution; they sum exactly to the score),
  phrased for the value the URL actually has ("uses unencrypted http://", "domain ending '.cn' (98% of
  training URLs with it were phishing)", "domain registered 3 days ago").

---

## 2. Laya: what it is, how it was tested, why it is not used

**What it is** (from reading the source at commit 4066d5d and running it): a general-purpose
"typed decision" model — a BERT-family encoder (ModernBERT-large, 396M parameters, or mmBERT-base) plus a
small transformer head (whole checkpoints: 421M parameters / 843 MB and 322M / 644 MB) that scores the options of a question (`choice`, `score`, or
`noul` = yes/no) about a piece of text, in one forward pass. Outputs are temperature-scaled probabilities
(English checkpoint T≈1.98; the multilingual one is uncalibrated, T=1). It runs fully offline once
downloaded, has no telemetry, and is Apache-2.0 (code and model cards; encoders Apache-2.0/MIT), so licensing
was never an obstacle. We found **no evidence that it was trained or evaluated on URL classification**: its published
"phishing" evaluation is on phishing *e-mails*, not URLs, and it is presented as a base model to be specialised for a
task rather than used zero-shot. Its own CPU unit tests pass on the test machine (61/61, 8/8, 7/7).

**Cost on this CPU (measured):** 17–19 s to load from disk (32–42 s including the first download), 1.8–2.5 GB
RSS after loading, 3.5 GB peak, 93–221 ms per URL (multilingual) and 436–576 ms per URL (English) per question. A URL is only ~18 tokens; the question/option
header adds ~45 more to every input.

**Five ways of using it, all on the same 1,500 test URLs from domains never seen in training** (PhreshPhish):

{{LAYA_TABLE}}

* The **decision rule, fixed in advance** (written in `experiments/analyze_laya.py` before looking at test results):
  Laya counts as useful only if a Laya mode beats the best tiny model on ROC-AUC *and* recall at 1% FPR with
  the paired 95% CI excluding 0, or if a cascade improves recall at acceptable latency. {{LAYA_RULE}}
  **Rejected in every mode.**
* **Equal-data control** (all methods trained on the same 6,000 URLs): LightGBM on URL features 0.988 /
  0.875 recall; character n-grams 0.981 / 0.830; Laya embeddings 0.968 / 0.621. Laya's representation does
  carry signal — just less than cheap hand-made features.
* The expensive **full-encoder fine-tune** was deliberately not run: the protocol required the cheaper head
  fine-tune to come close first (it reached 0.933 vs 0.99), the estimated CPU cost is 1–4 h per epoch here (not
  measured), and even a
  perfect result could not overcome a speed handicap of roughly two orders of magnitude and a size handicap of
  roughly three for this task.

**Verdict:** Laya is a reasonable general text-decision model, but for URL fraud detection it is the wrong
tool — a URL is a short, adversarial, highly structured string where character/structure statistics and
domain reputation matter, not language understanding.

---

## 3. Data (all labels come from the sources)

{{DATA_TABLE}}

**Biases found and removed before trusting any number** (each would have inflated results):

1. Popular public "phishing URL datasets" (PhiUSIIL, StealthPhisher, LegitPhish) were rejected: a single
   regex (`legit ⇔ https://www.<domain>/`) separates their classes with ≥ 99% balanced accuracy.
2. In PhreshPhish only *legitimate* URLs lacked a scheme → the model only sees "explicit http://".
3. Crawl/telemetry legitimate URLs never have `#fragments` → fragments are ignored everywhere.
4. Excluding every feed domain from the legitimate side removed all google.com/github.com/weebly URLs (a
   model would learn "google.com ⇒ phishing") → big platforms appear in both classes.
5. The local network's DNS resolver failed under load and Quad9 answers NXDOMAIN for known-malicious domains (label
   leak) → DNS moved to DNS-over-HTTPS to Cloudflare's unfiltered resolver.
6. Old phishing domains are dead today: 44% of Sep–Dec 2025 phishing hosts no longer resolve vs 0% of benign
   ones; "does not resolve today" alone would score ROC-AUC 0.73 on stale data → enrichment is evaluated only
   on fresh 2026 data. The shipped enriched model and the "live only" results use only domains that still
   resolve, with existence signals removed and domain age/expiry rebased to the day the URL was seen; the other
   fresh26e rows in §5.4 include dead domains and existence signals and therefore overstate the gain.
7. Training features were cached as float32 while the runtime computes float64, and one export lost feature
   names → the export now runs an end-to-end check (raw URL → shipped runtime vs training pipeline).
8. A date bug left Common Crawl legitimate rows without dates, so rebased domain age was missing only for
   legitimate URLs (found by the leakage audit; it inflated the enriched model's gain by ~6 points) → fixed and
   everything retrained.

---

## 4. How it was evaluated

* **Every split is by registrable domain** (Public Suffix List including the private section, so
  `a.github.io` and `b.github.io` are different domains): train 60% / validation 10% (early stopping) /
  calibration 10% (calibration and thresholds) / test 20%. No domain is ever in two splits.
* **Honest caveat on selection:** the final feature set and tree size were chosen by comparing seven trained
  configurations on test and external metrics (§5.3, §5.5), and the enriched model's calibration uses cross-fitted
  scores on all fresh26e rows, so the reported numbers carry a small selection optimism.
* **New domains:** every test number is on domains absent from training.
* **Time:** training data spans 2020–2026; external checks include JPCERT (Dec 2025–May 2026) and OpenPhish
  URLs captured on the day of the experiment (same feed as fresh26's phishing, so not fully independent: 17 of
  the 201 scored URLs are also fresh26 test URLs).
* **Different collections:** train on one dataset, test on another (§5.2), plus a fully external dataset
  (Ariyadasa 2021) and a false-positive stress test (Tranco top-10k homepages).
* **Metrics:** ROC-AUC, PR-AUC, recall at 1% and 0.1% false-positive rate, FPR/FNR, confusion counts,
  three-way verdict shares, ECE / Brier / reliability tables; paired bootstrap CIs for model comparisons.

---

## 5. Results

### 5.1 Model families (PhreshPhish, 99,169 test URLs from unseen domains)

{{BASELINE_TABLE}}

Character n-grams win *in-distribution* but lose *out-of-distribution* (next section), so they were not shipped.

### 5.2 Generalisation to other collections (the most important table)

{{CROSS_TABLE}}

A URL-only model trained on one collection loses a lot on another collection. The shipped model is therefore
trained on all three collections (2020, 2024–25, 2026) with weights 10% / 55% / 35%.

### 5.3 Which features matter — and can a handful do the job?

* **Started with 86 candidate lexical features** in 8 groups (lengths/counts, character composition, host
  structure, domain shape, hosting platform, path semantics, brand/keyword, scheme), plus 3 popularity features
  excluded because they are circular with how legitimate URLs are usually sampled. Three were then removed as
  dataset artifacts (explicit https, missing scheme, fragment length) and one is a constant (parse error), so the
  feature studies below ran on **82**; the shipped model adds one learned government/education flag → **83**.
* **The strongest single signal is the domain ending's phishing rate** (45% of gain in the PhreshPhish
  feature-study model, 25% on fresh26), then path
  length/shape, subdomain length, randomness (entropy), http vs https, hyphens/dots and login/payment words.
  The domain-ending reputation is learned per *full* public suffix with fallback to the top-level domain
  (`gov.br` had 0 phishing among 11 training URLs, but with shrinkage toward `.br` its shipped reputation is
  58% vs 92% for `com.br`), plus one learned government/education flag.
  14 (PhreshPhish) to 23 (fresh26) features — raw IP, `user@`, rare punctuation…, plus punycode and shorteners on
  fresh26 — have zero measurable importance in aggregate: they are rare, not useless.
* **Removing any single feature group costs at most 0.006 ROC-AUC**: the features are highly redundant
  (e.g. path length / longest segment / path entropy correlate at ρ ≈ 0.94–0.97).

{{COMPACT_TABLE}}

**Answer:** *within one dataset* a surprisingly small set works — 12–16 features recover 99.3–99.7% of the
ROC-AUC. *Across datasets and time* it does not: the compact sets lose 7–17 points of recall at 1% FPR on
out-of-distribution data.
Because features cost almost nothing (all 83 take ~0.2 ms to compute and do not change the model size), the
shipped model uses all of them.

### 5.4 Does domain / DNS / page information help?

{{ENRICH_TABLE}}

* **Yes, measurably — for phishers' own domains.** On live, non-platform 2026 URLs the DNS+RDAP correction
  lifts recall at 1% FPR from {{ENR_SAFE_R1}} to {{ENR_ENR_R1}}.
* **Page content helps too** (Hannousse: +8 points recall at 1% FPR), but it requires visiting the page, which the
  offline design rules out, so it is not implemented.
* **TLS certificates** were not used: fetching them means connecting to the (possibly malicious) server, and
  certificate-transparency services were unavailable (crt.sh HTTP 502) or rate-limited (Cert Spotter, 100/h).
* **Domain popularity lists** (Tranco) gave mixed results on non-circular tests: the top-1M list helped slightly
  on PhreshPhish (recall at 1% FPR 0.91 → 0.92) and Ariyadasa (0.25 → 0.28) but hurt on fresh 2026 HN links
  (0.37 → 0.24), and it would add a 10 MB file that goes stale — not shipped.

### 5.5 The shipped model on unseen data

{{FINAL_TABLE}}

{{EXTERNAL_TABLE}}

### 5.6 Is the probability a probability?

{{CALIBRATION_TEXT}}

### 5.7 Speed, memory, size

{{BENCH_TABLE}}

---

## 6. Behaviour you should expect

* **Completely new domains:** that is the only thing the test sets contain — all numbers above are for
  domains the model never saw.
* **`--enrich` not used, DNS lookup failed, domain no longer resolves, IP address, or shared hosting
  platform:** the URL is scored by the offline model; with `--enrich` or `--enrich-review`, `analysis_mode` says "offline (enrichment
  unavailable for this URL)" and `lookup_status` says why. If DNS works but only the registry (RDAP) lookup is
  unavailable (no RDAP server for the TLD, rate limit, error), the enriched model runs without registration
  data. Nothing crashes and every row gets a result.
* **Not a URL / empty cell:** `ERROR` with a reason; the row is still written.
* **HTTP/page content:** never fetched. Offline mode (the default) makes zero network requests.

## 7. Weaknesses (read before relying on it)

1. **Distribution shift is the dominant risk.** Out-of-collection ROC-AUC is 0.85–0.96 depending on how
   different your URLs are; recall at 1% FPR can fall below 0.5. Expect less than the in-distribution numbers.
2. **Bare homepages go to REVIEW.** On 1,000 bare homepages of popular (Tranco top-10k) domains never seen in
   training (`experiments/homepage_check.py`), offline mode gives 76% `REVIEW`, 21% `LEGITIMATE`,
   3.1% `FRAUD`; `--enrich` gives 63% / 34% / 3.3%. False alarms include
   machine-looking infrastructure hosts (ad/CDN/DNS/telemetry), brand-embedding domains and real sites on heavily
   abused endings (e.g. Chinese news sites on `.cn`).
3. **Shared hosting platforms cut both ways.** Tenants of heavily abused free-hosting platforms (`pages.dev`,
   `webflow.io`, `r2.dev`, `vercel.app`, `wixsite.com`) are almost always called `FRAUD` — including legitimate
   tenants — while phishing on Google Docs/Sites/Forms/Drive, Weebly or S3 usually lands in `REVIEW` and can even
   be called `LEGITIMATE` (the Google Forms row in `examples/` is). Enrichment is
   deliberately skipped for all shared platforms (domain data would describe the platform, not the page).
4. **Compromised legitimate websites** hosting phishing pages look legitimate by domain age and often by URL.
5. **Adversaries can adapt:** every feature is visible in the URL; a careful attacker can make a URL look
   ordinary (https, no hyphens, common TLD, plausible path).
6. **Probabilities are stated at the calibration prevalence (~47% fraud, both modes).** Use `--base-rate` for
   realistic prevalence; at 1% prevalence even a 0.97 score means only ~27% chance of fraud, and verdicts that
   the re-weighted probability contradicts are downgraded to `REVIEW`.
7. **TLD reputations and brand lists age.** They reflect 2020–2026 data and should be retrained periodically.
8. **RDAP is patchy:** many popular ccTLDs (.de, .io, .co, .me, .ru, .cn, .jp, .eu, .us…) have no public
   RDAP server; registries rate-limit bulk lookups.

## 8. Questions and answers

{{ANSWERS}}

## 9. How the results were produced

The datasets are **not** included in the repository (see `NOTICE.md` for sources and licences). To reproduce,
download them into `data/` as described in `experiments/README.md`, install `experiments/requirements.txt`, and
run the pipeline in this order:

```
python experiments/build_datasets.py hannousse fresh26 phreshphish external
python experiments/baselines.py --dataset phreshphish
python experiments/feature_study.py --dataset phreshphish      # and --dataset fresh26
python experiments/laya_eval.py zeroshot --data data/processed/phreshphish.csv --checkpoint multilingual
python experiments/laya_eval.py zeroshot --data data/processed/phreshphish.csv --checkpoint english
python experiments/laya_eval.py signals  --data data/processed/phreshphish.csv --checkpoint multilingual
python experiments/laya_eval.py embed    --data data/processed/phreshphish.csv --checkpoint multilingual
python experiments/laya_finetune.py      --data data/processed/phreshphish.csv --stage head
python experiments/analyze_laya.py phreshphish && python experiments/cascade_ci.py && python experiments/stack_ci.py
for p in "fresh26 phreshphish" "hannousse phreshphish" "phreshphish fresh26" "phreshphish hannousse" \
         "phreshphish openphish26"; do python experiments/cross_dataset.py $p; done
python experiments/equal_data_control.py
python experiments/enrich_dataset.py fresh26e && python experiments/enrichment_study.py
python experiments/enrich_model_study.py && python experiments/stale_leakage_demo.py && python experiments/popularity_study.py
python experiments/train_final.py --tag safe && python experiments/train_enrich_final.py
python experiments/temporal_eval.py && python experiments/homepage_check.py && python experiments/shipped_on_laya_test.py
python experiments/calibration_report.py safe && python experiments/benchmark_cli.py 200000
python experiments/collect_results.py            # -> results/SUMMARY.md
python experiments/render_report.py              # -> REPORT.md
python -m pytest -q tests
```
