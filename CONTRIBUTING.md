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

## Releasing

1. Bump `__version__` in `fraudurl/__init__.py`, then rebuild the single file (see above).
2. Add a `## [X.Y.Z] - YYYY-MM-DD` section and its link line to `CHANGELOG.md`; the release notes are cut
   from it. Update `version` and `date-released` in `CITATION.cff` and the title of `MODEL_CARD.md`.
3. Push to `main` and wait for CI to pass, including the "PyPI package and project page" job.
4. Push the tag `vX.Y.Z`. `release.yml` tests, builds, creates the GitHub release and starts
   `publish-pypi.yml`. Check the GitHub release, then approve the waiting run (environment `pypi`); it
   uploads those exact files to PyPI through trusted publishing.
5. If the upload fails, fix the cause and re-run `publish-pypi.yml` from the tag. Never delete or rebuild a
   release once any of its files is on PyPI: a version can be uploaded only once.

Do not edit `README.md` for PyPI: `experiments/build_pypi_readme.py` rewrites it into the PyPI page at
release time, with absolute links pinned to the tag.

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
