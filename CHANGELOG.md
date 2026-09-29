# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-09-29

Packaging release: the first version on PyPI. The code, the models and every result are the same as in 1.0.0.

- **Install from PyPI:** `pip install fraudurl`.
- **PyPI project page:** at release time the README is rewritten so its images and links work on pypi.org
  (`experiments/build_pypi_readme.py`); CI checks the rendered page on every change.
- **Same files everywhere:** PyPI gets the exact wheel and sdist attached to the GitHub release, checked
  against its `SHA256SUMS`, and uploads use PyPI trusted publishing (no stored passwords or tokens).
- **Documentation:** a step-by-step guide on the website, clearer wording on what is detected (phishing
  only), and the accuracy range across all four test sets (ROC-AUC 0.91–0.98).
- **Package metadata:** keywords for PyPI search.

## [1.0.0] - 2026-09-28

First public release.

- **Offline check:** 83 URL-text features, a 400-tree LightGBM model exported to JSON and scored in pure
  Python, a Platt-calibrated probability, three-way verdicts (FRAUD / REVIEW / LEGITIMATE) and plain-English
  reasons from the model's own contributions.
- **Optional lookups:**
  - DNS over HTTPS and registry RDAP, cached per domain.
  - A second model corrects the score using them.
  - `--enrich` looks up every URL; `--enrich-review` looks up only the URLs the offline check leaves in
    REVIEW.
- **Your own lists:** `--allow-list` and `--block-list`, for domains, IPs or URL prefixes. Hosts-file format
  is accepted and the block list always wins.
- **Pipeline use:** `--url` and `--format json` output JSON Lines, with what each stage found (offline check,
  your list, DNS and registration facts). `--quiet` silences messages.
- **CSV handling:**
  - Detects encoding, delimiter, header and URL column.
  - Streams large files in chunks across up to 4 processes, with flat memory.
  - Protects added cells against spreadsheet-formula injection.
- **Tuning:** `--base-rate` re-weights probabilities for your expected fraud rate; `--url-column`, `--workers`
  and `--cache-dir` control input, parallelism and the lookup cache.
- **Single file:** `fraudurl_standalone.py`, the whole tool with the models embedded, generated from the
  package.
- **Measured on test domains never seen in training:** ROC-AUC 0.907–0.984, with legitimate URLs called FRAUD
  0.3–1.8% of the time. 1,000,000 URLs are scored in about 6 minutes on 4 CPU cores. See
  [MODEL_CARD.md](MODEL_CARD.md) and [REPORT.md](REPORT.md).

[1.0.1]: https://github.com/amruth112/fraudurl-detector/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/amruth112/fraudurl-detector/releases/tag/v1.0.0
