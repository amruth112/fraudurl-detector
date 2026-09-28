# Notices and credits

fraudurl is Copyright (c) 2026 Amruthjithraj V.R and released under the MIT License (see
[LICENSE](LICENSE)). This covers the code and the trained model files `fraudurl/data/model_safe.json` and
`fraudurl/data/model_enrich.json`, except as noted below.

## Third-party file shipped with the tool

`fraudurl/data/public_suffix_list.dat` (also embedded, zlib + base64, in `fraudurl_standalone.py`) is the
[Public Suffix List](https://publicsuffix.org/), VERSION 2026-09-24_13-26-36_UTC, COMMIT
a179a48c465e818cfd8d626691cb317985da87fb, unmodified. It is licensed under the Mozilla Public License 2.0
(<https://mozilla.org/MPL/2.0/>; a copy is in [LICENSES/MPL-2.0.txt](LICENSES/MPL-2.0.txt)). Source:
<https://publicsuffix.org/list/public_suffix_list.dat>.

## Data used to train the models

The model files contain decision trees, calibration values and a table of phishing rates per domain ending.
They contain no URLs from any source. No training data is redistributed in this repository.

- **PhreshPhish v1.0.1**: T. Dalton, H. Gowda, G. Rao, S. Pargi, A. Hadj Khodabakhshi, J. Rombs, S. Jou,
  M. Marwah, "PhreshPhish: A Real-World, High-Quality, Large-Scale Phishing Website Dataset and Benchmark",
  arXiv:2507.10854, 2025. <https://huggingface.co/datasets/phreshphish/phreshphish>. Licensed
  [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
  - What was used: only the URL, label and date; HTML was not used.
  - Changes: URLs were de-duplicated, capped at 50 per registrable domain and re-split by registrable domain.
- **Web page phishing detection**: A. Hannousse, S. Yahiouche, Mendeley Data, V3, 2021,
  doi:10.17632/c2gw7fy2j4.3. Paper: *Engineering Applications of Artificial Intelligence* 104 (2021) 104347,
  doi:10.1016/j.engappai.2021.104347. Licensed CC BY 4.0.
  - What was used: only the `url` and `status` columns of dataset B.
  - Changes: conflicting and duplicate URLs were removed; rows were re-split by registrable domain.
- **Phishing URLs, June–September 2026**: [PhishTank](https://phishtank.org) (operated by Cisco Talos) and
  the [OpenPhish](https://openphish.com) community feed.
- **Legitimate URLs, 2026**:
  - Hacker News story links obtained through the HN Search API by Algolia.
  - URL-index records from the [Common Crawl](https://commoncrawl.org) crawl CC-MAIN-2026-34, on domains
    chosen with the [Tranco](https://tranco-list.eu) list K9PXW (V. Le Pochat et al., NDSS 2019).
- **Enrichment model**: also uses DNS answers (Cloudflare 1.1.1.1) and RDAP registration data collected on
  2026-09-25.

The models were trained with [LightGBM](https://github.com/microsoft/LightGBM) (MIT License). No LightGBM code
is distributed.

## Evaluation only (not used for training, not redistributed)

- S. Ariyadasa, S. Fernando, S. Fernando, "Phishing Websites Dataset", Mendeley Data, V1, 2021,
  doi:10.17632/n96ncsr5g4.1 (CC BY 4.0).
- JPCERT/CC phishurl-list, <https://github.com/JPCERTCC/phishurl-list>.
- Laya by Convai Innovations (Apache-2.0), <https://huggingface.co/convaiinnovations>, compared in
  `experiments/` at upstream commit 4066d5d5fbf08b66c6757ddeedbd797bd7655bc0. Laya's code is not included.

## Other notes

- The legitimate URLs in `examples/sample_urls.csv` rows 1–15 come from the PhreshPhish (CC BY 4.0) and 2026
  test sets.
- The phishing-style rows 16–30 are made up. They use reserved domain names (RFC 2606, RFC 6761), a
  documentation IP address (RFC 5737), or, in row 27, a placeholder Google Forms ID (`EXAMPLE-ONLY`) that does
  not exist.
- Brand names in `fraudurl/lexical.py` are trademarks of their owners and are used only to recognise
  impersonation. No affiliation with, or endorsement by, any data provider or brand is implied.
