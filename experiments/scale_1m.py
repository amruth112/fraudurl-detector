"""Scale test: push 1,000,000 real URLs through the shipped CLI (safe mode, default settings) and record
wall time, peak memory of the whole process tree, output size and the verdict mix.

The URL pool is every URL in the processed datasets (all splits, both classes), de-duplicated and
sampled with random_state=0. Labels are not used here; this measures throughput and footprint only.
"""
from __future__ import annotations

import glob
import json
import os
import subprocess
import sys
import time

import pandas as pd
import psutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = os.path.join(ROOT, ".cache", "tmp")
N = int(sys.argv[1]) if len(sys.argv) > 1 else 1_000_000


def make_csv(path):
    pool = []
    for f in sorted(glob.glob(os.path.join(ROOT, "data", "processed", "*.csv"))):
        try:
            d = pd.read_csv(f, usecols=["url"], dtype=str)
        except ValueError:
            continue
        pool.append(d.url.dropna())
    urls = pd.concat(pool, ignore_index=True).drop_duplicates()
    n_unique = len(urls)
    urls = urls.sample(n=N, replace=N > n_unique, random_state=0).reset_index(drop=True)
    pd.DataFrame({"id": range(N), "url": urls, "note": "scale test"}).to_csv(path, index=False)
    return n_unique, int(urls.nunique())


if __name__ == "__main__":
    inp = os.path.join(TMP, f"scale_{N}.csv")
    outp = inp + ".out.csv"
    pool_unique, in_unique = make_csv(inp)
    t0 = time.time()
    p = subprocess.Popen([sys.executable, "-m", "fraudurl", inp, "-o", outp], cwd=ROOT,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc = psutil.Process(p.pid)
    peak, samples = 0, []
    while p.poll() is None:
        try:
            tree = [proc] + proc.children(recursive=True)
            rss = sum(x.memory_info().rss for x in tree if x.is_running())
            peak = max(peak, rss)
            samples.append((round(time.time() - t0, 1), round(rss / 1e6, 1)))
        except psutil.Error:
            pass
        time.sleep(0.25)
    _, err = p.communicate()
    dt = time.time() - t0
    r = pd.read_csv(outp, encoding="utf-8-sig", keep_default_na=False, usecols=["fraud_verdict", "registrable_domain"])
    res = {
        "n_urls": N, "unique_urls_in_input": in_unique, "unique_url_pool": pool_unique,
        "unique_registrable_domains": int(r.registrable_domain.replace("", pd.NA).dropna().nunique()),
        "cli_args": "default (safe mode, workers = min(4, cpu_count))",
        "cpu": "Intel i5-7500 (4 cores, 3.4 GHz), Windows 10",
        "seconds": round(dt, 1), "urls_per_second": round(N / dt, 1),
        "peak_rss_MB_process_tree": round(peak / 1e6, 1),
        "rss_MB_at_25_50_75_100pct_of_run": [s[1] for s in (samples[len(samples) // 4], samples[len(samples) // 2],
                                                             samples[3 * len(samples) // 4], samples[-1])] if samples else [],
        "input_bytes": os.path.getsize(inp), "output_bytes": os.path.getsize(outp),
        "output_rows": len(r), "returncode": p.returncode,
        "verdicts": r.fraud_verdict.value_counts().to_dict(),
        "stderr_tail": err.decode("utf-8", "replace").replace(ROOT + os.sep, "")[-300:],
    }
    os.makedirs(os.path.join(ROOT, "results", "benchmark"), exist_ok=True)
    json.dump(res, open(os.path.join(ROOT, "results", "benchmark", f"scale_{N}.json"), "w"), indent=1)
    print(json.dumps(res, indent=1))
