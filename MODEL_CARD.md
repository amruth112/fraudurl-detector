# Model card: fraudurl 1.0.1 (same models as 1.0.0)

## What it is

Two small gradient-boosted tree models, trained with LightGBM and exported to JSON. They are scored by a
pure-Python tree walker in `fraudurl/model.py`, so no machine-learning library is needed at run time.

| | Offline model (`model_safe.json`) | Lookup model (`model_enrich.json`) |
|---|---|---|
| Input | 83 features computed from the URL text only (71 are used by at least one tree) | 10 DNS / registration features (9 used); adds a correction to the offline model's log-odds |
| Size | 400 trees × 15 leaves, 449 KB | 150 trees × 7 leaves, 71 KB |
| Output | Platt-calibrated probability | Platt-calibrated, prior-shifted to the same reference prevalence as the offline model (47.1%) |
| Verdict cut-offs | FRAUD if p ≥ 0.873, LEGITIMATE if p ≤ 0.101, REVIEW in between | FRAUD if p ≥ 0.923, LEGITIMATE if p ≤ 0.125 |
| Used when | always | `--enrich` / `--enrich-review`, for domains that resolve and are not shared hosting platforms |

The cut-offs were chosen on held-out calibration data to target about 1% of legitimate URLs called FRAUD and
about 2% of phishing called LEGITIMATE.

The per-URL reasons come from path attribution (Saabas): each tree's contributions, plus a fixed starting
value, add up exactly to the raw score.

## Intended use

- **For:** first-line triage of credential-phishing URLs in bulk (CSV files, pipelines). It flags the clear
  cases, clears the clear legitimate ones, and sends the rest to REVIEW for a person.
- **Not for:** blocking decisions without human review in low-prevalence traffic; malware or scam detection
  beyond URL phishing patterns; judging a page's content (the tool never visits pages).

## Training data

- **Rows:** 316,682 training URLs.
- **Split:** by registrable domain, 60% train / 10% early stopping / 10% calibration / 20% test. No domain
  appears in two splits.
- **Weighting:** the datasets were weighted by share of total training weight, not by row count:

| Dataset | Share of training weight |
|---|---|
| PhreshPhish 2024–25 | 55% |
| URLs collected for this project in June–September 2026 (phishing from the PhishTank and OpenPhish feeds; legitimate from Hacker News links and Common Crawl) | 35% |
| Hannousse 2020 | 10% |

Sources, licences and credits are in [NOTICE.md](NOTICE.md). The full data pipeline is in
`experiments/build_datasets.py`.

## Evaluation (test domains never seen in training)

| Test set | ROC-AUC | Recall at 1% false-positive rate | Legitimate called FRAUD | Phishing called LEGITIMATE | REVIEW share |
|---|---|---|---|---|---|
| PhreshPhish 2024–25 (n = 99,169) | 0.984 | 0.85 | 0.3% | 2.6% | 18% |
| 2026 collection (n = 4,718) | 0.975 | 0.73 | 1.8% | 1.6% | 24% |
| Hannousse 2020 (n = 2,369) | 0.907 | 0.51 | 1.3% | 4.9% | 45% |
| Ariyadasa 2021, fully external (n = 54,613 URLs on unseen domains) | 0.958 | 0.58 | 1.8% | 2.1% | 33% |

- **Bare homepages** of 1,000 popular (Tranco top-10k) sites: 3% FRAUD, 76% REVIEW.
- **Lookup model**, on 4,523 live 2026 URLs outside shared platforms (cross-fitted): ROC-AUC 0.948 → 0.962,
  recall at 1% FPR 0.43 → 0.58.
- **Calibration error (ECE)**: 0.012–0.038 depending on the test set.
- **Selection optimism**: the final configuration was chosen among seven candidates by comparing their test
  and external results, so these numbers are slightly optimistic.

Full details, including the comparison with the Laya language model, are in [REPORT.md](REPORT.md).

## Limitations and risks

- **Distribution shift.** Performance drops on data unlike the training data. Trained on one collection and
  tested on another, ROC-AUC was 0.85–0.96.
- **Low prevalence.** When phishing is rare in your traffic, most FRAUD verdicts can be false alarms. At 1%
  prevalence, only about 25–75% of FRAUD verdicts are real phishing by default (26% on the fully external
  Ariyadasa set, 31% on 2026 data, 73% on PhreshPhish). Use `--base-rate`.
- **Shared platforms.**
  - Phishing hosted on big legitimate platforms (Google Docs, Forms or Sites; Weebly) often looks legitimate
    or lands in REVIEW.
  - Honest tenants of heavily abused free-hosting platforms (`pages.dev`, `webflow.io`) are often called FRAUD.
- **Other misses.** Compromised legitimate sites and carefully disguised URLs are hard to catch from the URL
  alone.
- **Legitimate URLs flagged.** Some legitimate login pages look like phishing from their URL alone.
- **Ageing.**
  - The domain-ending reputations and the brand list reflect 2020–2026 data, so retrain periodically.
  - The Public Suffix List in `fraudurl/data/` is tied to the model's learned domain-ending table. Refresh it
    only together with a retrain.
- **Lookups.** `--enrich` and `--enrich-review` send host names to Cloudflare's DNS-over-HTTPS service and domains to registry
  RDAP servers. Some registries' terms restrict high-volume automated queries, so users are responsible for
  complying.

## Ethical considerations

- **Nothing at the URLs is touched.** The tool never visits, downloads or submits anything at the URLs it
  checks.
- **Offline mode sends nothing anywhere.**
- **REVIEW is a feature, not a failure.** It keeps a person in the loop for ambiguous cases instead of
  guessing.
