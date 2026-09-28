# Contributing

Thanks for helping. Bug reports, wrong-verdict reports, fixes and documentation improvements are all welcome.

## Ground rules

- **No live malicious URLs** anywhere: code, tests, issues or pull requests. See [SECURITY.md](SECURITY.md)
  for how to defang URLs and which reserved names to use in tests.
- **No third-party datasets in the repository.** The training data is not redistributed. See
  [NOTICE.md](NOTICE.md) and `experiments/README.md` for how it is obtained.
- **Keep the tool dependency-free.** `fraudurl/` must run on the Python 3.9+ standard library alone.
  Research code in `experiments/` may use numpy, pandas, scikit-learn and LightGBM.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

The tests run offline in a few seconds. Anything that touches enrichment uses an in-memory stub instead of
the network.

## The single-file edition

`fraudurl_standalone.py` is **generated** from the package. Never edit it by hand. After changing anything in
`fraudurl/`:

```bash
python experiments/build_single_file.py
python experiments/check_standalone.py      # CI runs this too
```

Commit the rebuilt file together with your change.

## Documentation

`REPORT.md` is generated. Edit `docs/REPORT.template.md` (hand-written text) or `experiments/render_report.py`
(tables and answers), then run `python experiments/render_report.py`. Never edit `REPORT.md` by hand.

## Changing the model

Retraining changes verdicts for users, so:

1. Rebuild the data and retrain with the scripts in `experiments/` (see `experiments/README.md`).
2. Refresh `fraudurl/data/public_suffix_list.dat` **only together with a retrain**. The model's
   domain-ending table depends on how the list splits domains.
3. Regenerate the results and docs (`experiments/collect_results.py`, `experiments/render_report.py`) and
   the example outputs.
4. Note the before/after metrics in `CHANGELOG.md`.
