"""False-alarm stress test: bare homepages of legitimate top-10k (Tranco) domains, safe vs --enrich.

Sample: 1,000 homepages drawn with random_state=7 from tranco_home.csv, restricted to registrable
domains never used for training, validation or calibration. Both runs go through the shipped CLI.
Network: --enrich performs DNS-over-HTTPS + RDAP lookups for these 1,000 legitimate domains only.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = os.path.join(ROOT, ".cache", "tmp")

if __name__ == "__main__":
    seen = set()
    for name in ("phreshphish", "fresh26", "hannousse"):
        d = pd.read_csv(os.path.join(ROOT, "data", "processed", f"{name}.csv"), usecols=["group", "split"])
        seen |= set(d.group[d.split.isin(["train", "val", "cal"])])
    th = pd.read_csv(os.path.join(ROOT, "data", "processed", "tranco_home.csv"))
    th = th[~th.group.isin(seen)].sample(1000, random_state=7)
    inp = os.path.join(TMP, "homepage_check_1000.csv")
    th[["url"]].to_csv(inp, index=False)
    out = {"n": len(th), "sample": "tranco_home unseen domains, random_state=7"}
    for mode, extra in (("safe", []), ("enrich", ["--enrich", "--cache-dir", os.path.join(ROOT, ".cache", "fraudurl_cache")])):
        o = os.path.join(TMP, f"homepage_check_1000.{mode}.csv")
        subprocess.run([sys.executable, "-m", "fraudurl", inp, "-o", o, "--workers", "1"] + extra, cwd=ROOT, check=True)
        r = pd.read_csv(o, encoding="utf-8-sig", keep_default_na=False)
        out[mode] = {k: round(float(v), 4) for k, v in r.fraud_verdict.value_counts(normalize=True).items()}
        if mode == "enrich":
            out["enrich_analysis_modes"] = r.analysis_mode.value_counts().to_dict()
            out["legit_homepages_called_fraud_with_enrich"] = r[r.fraud_verdict == "FRAUD"].url.head(15).tolist()
    print(json.dumps(out, indent=1))
    json.dump(out, open(os.path.join(ROOT, "results", "final", "homepage_check_safe_vs_enrich.json"), "w"), indent=1)
