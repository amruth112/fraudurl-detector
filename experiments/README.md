# experiments/

This folder holds the research code behind the shipped models and every number in [REPORT.md](../REPORT.md).
None of it is needed to *use* fraudurl.

```bash
python -m pip install -r experiments/requirements.txt
```

The research code was run on Python 3.12. The pinned versions need a recent Python (3.11+), even though the
tool itself runs on 3.9+. In file names, tags and result keys, `safe` is the internal name of the offline
model and `enrich` the lookup model.

## Data (not included)

The training and test data are **not** in this repository: the files are large, and several sources do not
allow redistribution. Sources, licences and citations are in [NOTICE.md](../NOTICE.md). To reproduce, place
the raw files under `data/raw/` (`data/` is git-ignored):

| Path under `data/raw/` | Source |
|---|---|
| `candidates/phreshphish/phreshphish_urls.tsv` | PhreshPhish (Hugging Face `phreshphish/phreshphish`): url, label and date columns |
| `candidates/hannousse/dataset_B_05_2020.csv` | Hannousse & Yahiouche, Mendeley Data doi:10.17632/c2gw7fy2j4.3 |
| `candidates/ariyadasa_pwd2021/index.sql` | Ariyadasa et al., Mendeley Data doi:10.17632/n96ncsr5g4.1 (evaluation only) |
| `candidates/jpcert_phishurl/<year>/*.csv` | github.com/JPCERTCC/phishurl-list (evaluation only) |
| `feeds/phishtank_online-valid_*.csv.bz2` | PhishTank verified-online dump |
| `feeds/openphish_*.txt`, `feeds/openphish_history_first_seen.csv` | OpenPhish community feed (snapshots and first-seen dates from its public GitHub history) |
| `feeds/hn_stories_30d.csv` | Hacker News story links via the Algolia HN Search API |
| `cc_legit/cc_*.csv` | Common Crawl URL-index records, collected by `harvest_cc_*.py` |
| `tranco/top-1m.csv` | Tranco list (K9PXW was used) |

`collect_fresh.py` and `harvest_cc_*.py` show how the 2026 files were collected. Collection is rate-limited on
purpose: be gentle with these services.

## Pipeline, in order

1. `build_datasets.py`: builds `data/processed/*.csv` with a domain-grouped train/val/cal/test split.
2. `baselines.py`, `feature_study.py`, `cross_dataset.py`, `temporal_eval.py`: model and feature studies.
3. `laya_eval.py`, `laya_finetune.py`, `analyze_laya.py`, `stack_ci.py`, `cascade_ci.py`,
   `equal_data_control.py`: the Laya comparison. These need PyTorch and Laya.
4. `enrich_dataset.py`, `enrichment_study.py`, `enrich_model_study.py`, `stale_leakage_demo.py`,
   `popularity_study.py`: DNS/RDAP enrichment. `enrich_dataset.py` performs live lookups, so run it on fresh
   data only: stale domains leak the answer (see REPORT.md §3).
5. `train_final.py --tag safe`, `train_enrich_final.py`: train and export the shipped models to
   `fraudurl/data/`.
6. `calibration_report.py`, `homepage_check.py`, `shipped_on_laya_test.py`, `benchmark_cli.py`, `scale_1m.py`,
   `project_1m.py`, `enrich_scale_estimate.py`, `audit_output_1m.py`: evaluation and scale checks.
7. `collect_results.py` writes `results/SUMMARY.md`; `render_report.py` fills `docs/REPORT.template.md` into
   `REPORT.md`.
8. `build_single_file.py`, `check_standalone.py`, `verify_standalone.py`: build the single-file edition and
   check it against the package.
9. `make_readme_assets.py`: draws the README images in `docs/assets/`, from `results/` and a real run of the
   tool.

Scripts that write per-URL outputs (`results/**/*.npz`, `results/benchmark/output_audit_1m.json`) keep them
local; they are git-ignored because they contain third-party URL lists.
