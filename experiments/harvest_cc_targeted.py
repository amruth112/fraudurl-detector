"""Targeted Common Crawl harvest: for Tranco domains sampled across rank tiers, locate the
index block holding the domain's captures (binary search in cluster.idx) and fetch only
that block from the data CDN. Same label rule as harvest_cc_blocks.py.
"""
from __future__ import annotations

import argparse
import bisect
import csv
import json
import os
import random
import sys
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "experiments"))
from fraudurl.lexical import ParsedURL  # noqa: E402
from harvest_cc_blocks import fetch_block  # noqa: E402
from harvest_cc_legit import feed_domains  # noqa: E402

RAW = os.path.join(ROOT, "data", "raw")
OUT = os.path.join(RAW, "cc_legit")


def surt_prefix(reg):
    return ",".join(reversed(reg.split(".")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default="CC-MAIN-2026-34")
    ap.add_argument("--domains", type=int, default=4000)
    ap.add_argument("--per-domain", type=int, default=3)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    ranks = []
    with open(os.path.join(RAW, "tranco", "top-1m.csv"), encoding="utf-8") as fh:
        for line in fh:
            r, d = line.strip().split(",", 1)
            ranks.append((int(r), d.lower()))
    excl = feed_domains()
    rng = random.Random(args.seed)
    tiers = [((1, 10_000), 0.2), ((10_001, 100_000), 0.3), ((100_001, 1_000_000), 0.5)]
    targets, seen = [], set()
    for (lo, hi), frac in tiers:
        pool = [x for x in ranks if lo <= x[0] <= hi]
        rng.shuffle(pool)
        k = int(round(args.domains * frac))
        for r, d in pool:
            if k == 0:
                break
            reg = ParsedURL("http://" + d).reg
            if not reg or reg in excl or reg in seen:
                continue
            seen.add(reg)
            targets.append((r, reg))
            k -= 1
    print(f"{len(targets)} target domains", flush=True)

    keys, locs = [], []
    with open(os.path.join(OUT, f"cluster_{args.index}.idx"), encoding="utf-8") as fh:
        for line in fh:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 4:
                keys.append(p[0].split(" ", 1)[0])
                locs.append((p[1], int(p[2]), int(p[3])))

    def work(t):
        rank, reg = t
        pre = surt_prefix(reg)
        i = max(0, bisect.bisect_left(keys, pre + ")") - 1)
        found = []
        for j in (i, i + 1):  # captures may start at the end of block i and continue in i+1
            if j >= len(locs):
                break
            for line in fetch_block(args.index, *locs[j]):
                surt = line.split(" ", 1)[0]
                if not (surt.startswith(pre + ")") or surt.startswith(pre + ",")):
                    continue
                try:
                    js = json.loads(line.split(" ", 2)[2])
                except (IndexError, ValueError):
                    continue
                mime = (js.get("mime-detected") or js.get("mime") or "").lower()
                u = js.get("url", "")
                if js.get("status") == "200" and "html" in mime and u and not u.endswith("robots.txt") \
                        and ParsedURL(u).reg == reg:
                    found.append((u, line.split(" ", 2)[1][:8]))
            if found and j == i and not keys[j + 1 if j + 1 < len(keys) else j].startswith(pre):
                break
        found = list(dict.fromkeys(found))
        random.Random(reg).shuffle(found)
        return rank, reg, found[: args.per_domain]

    out_fp = os.path.join(OUT, f"cc_targeted_{args.index}_s{args.seed}.csv")
    stats = {"domains_with_urls": 0, "no_capture": 0, "urls": 0}
    with open(out_fp, "w", encoding="utf-8", newline="") as fh, ThreadPoolExecutor(args.workers) as ex:
        w = csv.writer(fh)
        w.writerow(["url", "reg_domain", "tranco_rank", "cc_date", "cc_index"])
        for n, (rank, reg, urls) in enumerate(ex.map(work, targets)):
            if urls:
                stats["domains_with_urls"] += 1
                stats["urls"] += len(urls)
            else:
                stats["no_capture"] += 1
            for u, ts in urls:
                w.writerow([u, reg, rank, ts, args.index])
            if (n + 1) % 250 == 0:
                fh.flush()
                print(f"{n + 1}/{len(targets)} {stats}", flush=True)
    print("DONE", stats, out_fp, flush=True)


if __name__ == "__main__":
    main()
