"""Benchmark the shipped CLI end to end: throughput, cold start and peak memory of the whole
process tree (main process + worker processes), on a large CSV of real test URLs."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pandas as pd
import psutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "results", "benchmark")
os.makedirs(OUT, exist_ok=True)


def make_csv(n, path):
    parts = []
    for name in ("phreshphish", "fresh26", "ariyadasa"):
        d = pd.read_csv(os.path.join(ROOT, "data", "processed", f"{name}.csv"), usecols=["url", "split"], dtype=str)
        parts.append(d[d.split == "test"].url if name != "ariyadasa" else d.url)
    urls = pd.concat(parts, ignore_index=True)
    urls = urls.sample(n=n, replace=n > len(urls), random_state=0).reset_index(drop=True)
    pd.DataFrame({"id": range(n), "url": urls, "note": "benchmark"}).to_csv(path, index=False)


def run(args, label):
    t0 = time.time()
    p = subprocess.Popen([sys.executable, "-m", "fraudurl"] + args, cwd=ROOT,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc = psutil.Process(p.pid)
    peak = 0
    while p.poll() is None:
        try:
            tree = [proc] + proc.children(recursive=True)
            peak = max(peak, sum(x.memory_info().rss for x in tree if x.is_running()))
        except psutil.Error:
            pass
        time.sleep(0.05)
    out, err = p.communicate()
    dt = time.time() - t0
    return {"label": label, "seconds": dt, "peak_rss_MB_process_tree": peak / 1e6, "returncode": p.returncode,
            "stderr_tail": err.decode("utf-8", "replace").replace(ROOT + os.sep, "")[-400:]}


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000
    big = os.path.join(ROOT, ".cache", "tmp", f"bench_{n}.csv")
    if not os.path.exists(big):
        make_csv(n, big)
    small = os.path.join(ROOT, ".cache", "tmp", "bench_10.csv")
    make_csv(10, small)
    res = {"n_urls": n, "cpu": "Intel i5-7500 (4 cores, 3.4 GHz), Windows 10", "runs": []}
    res["runs"].append(run([small, "-o", small + ".out.csv", "--workers", "1"], "cold start, 10 URLs, 1 process"))
    res["runs"].append(run([big, "-o", big + ".out1.csv", "--workers", "1"], f"{n} URLs, 1 process"))
    res["runs"].append(run([big, "-o", big + ".out4.csv", "--workers", "4"], f"{n} URLs, 4 processes"))
    for r in res["runs"]:
        k = 10 if "10 URLs" in r["label"] else n
        r["urls_per_second"] = k / r["seconds"]
        print(r["label"], f"{r['seconds']:.1f}s", f"{r['urls_per_second']:.0f} URL/s",
              f"peak {r['peak_rss_MB_process_tree']:.0f} MB", "rc", r["returncode"], flush=True)
    sizes = {f: os.path.getsize(os.path.join(ROOT, "fraudurl", "data", f)) for f in os.listdir(os.path.join(ROOT, "fraudurl", "data"))}
    code = sum(os.path.getsize(os.path.join(ROOT, "fraudurl", f)) for f in os.listdir(os.path.join(ROOT, "fraudurl")) if f.endswith(".py"))
    res["package_bytes"] = {"data_files": sizes, "python_code": code, "total": code + sum(sizes.values())}
    out_rows = sum(1 for _ in open(big + ".out4.csv", encoding="utf-8-sig")) - 1
    res["output_rows"] = out_rows
    with open(os.path.join(OUT, "cli_benchmark.json"), "w") as fh:
        json.dump(res, fh, indent=2)
    print(json.dumps(res["package_bytes"], indent=1), "output rows", out_rows)
