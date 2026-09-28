"""Harvest legitimate URLs on the big multi-tenant platforms that phishers abuse.

The phishing feed is dominated by URLs on legitimate platforms (google.com Sites/Docs/
Forms, weebly, QR shorteners, dropbox, adobe ...). If the legitimate class contained no
URLs from those platforms, a model would learn "google.com => phishing". So for every
platform registrable domain that (a) appears in the phishing feed and (b) is in the Tranco
top-10k, we sample random Common Crawl index blocks inside that domain's key range and
keep HTTP-200 HTML captures as legitimate, excluding any exact URL present in a feed.
"""
from __future__ import annotations

import argparse
import bisect
import bz2
import collections
import csv
import glob
import io
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

RAW = os.path.join(ROOT, "data", "raw")
OUT = os.path.join(RAW, "cc_legit")


def feed_urls_and_counts():
    urls, cnt = set(), collections.Counter()
    for f in glob.glob(os.path.join(RAW, "feeds", "phishtank_*.csv.bz2")):
        for r in csv.DictReader(io.StringIO(bz2.decompress(open(f, "rb").read()).decode("utf-8", "replace"))):
            urls.add(r["url"].strip())
            cnt[ParsedURL(r["url"]).reg] += 1
    for f in glob.glob(os.path.join(RAW, "feeds", "openphish_*.txt")):
        for line in open(f, encoding="utf-8", errors="replace"):
            if line.strip():
                urls.add(line.strip())
                cnt[ParsedURL(line.strip()).reg] += 1
    return urls, cnt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default="CC-MAIN-2026-34")
    ap.add_argument("--top-platforms", type=int, default=60)
    ap.add_argument("--blocks-per-platform", type=int, default=6)
    ap.add_argument("--per-platform", type=int, default=30)
    ap.add_argument("--per-host", type=int, default=3)
    ap.add_argument("--seed", type=int, default=11)
    args = ap.parse_args()

    tranco = {}
    with open(os.path.join(RAW, "tranco", "top-1m.csv"), encoding="utf-8") as fh:
        for line in fh:
            r, d = line.strip().split(",", 1)
            if int(r) > 10_000:
                break
            reg = ParsedURL("http://" + d).reg
            tranco.setdefault(reg, int(r))
    feed_urls, cnt = feed_urls_and_counts()
    platforms = [(reg, c) for reg, c in cnt.most_common() if reg in tranco][: args.top_platforms]
    print("platforms:", platforms, flush=True)

    keys, locs = [], []
    with open(os.path.join(OUT, f"cluster_{args.index}.idx"), encoding="utf-8") as fh:
        for line in fh:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 4:
                keys.append(p[0].split(" ", 1)[0])
                locs.append((p[1], int(p[2]), int(p[3])))
    rng = random.Random(args.seed)

    def work(item):
        reg, _ = item
        pre = ",".join(reversed(reg.split(".")))
        lo = max(0, bisect.bisect_left(keys, pre + ")") - 1)
        hi = bisect.bisect_right(keys, pre + ",~")
        cand = list(range(lo, max(lo + 1, hi)))
        picks = sorted(random.Random(reg).sample(cand, min(len(cand), args.blocks_per_platform)))
        caps = []
        for j in picks:
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
                if js.get("status") == "200" and "html" in mime and u and u not in feed_urls \
                        and not u.endswith("robots.txt") and ParsedURL(u).reg == reg:
                    caps.append((u, line.split(" ", 2)[1][:8]))
        caps = list(dict.fromkeys(caps))
        random.Random(reg + "x").shuffle(caps)
        per_host, out = collections.Counter(), []
        for u, ts in caps:
            h = ParsedURL(u).host
            if per_host[h] < args.per_host:
                per_host[h] += 1
                out.append((u, ts))
            if len(out) >= args.per_platform:
                break
        return reg, len(cand), out

    out_fp = os.path.join(OUT, f"cc_platforms_{args.index}.csv")
    with open(out_fp, "w", encoding="utf-8", newline="") as fh, ThreadPoolExecutor(1) as ex:
        w = csv.writer(fh)
        w.writerow(["url", "reg_domain", "tranco_rank", "cc_date", "cc_index"])
        tot = 0
        for reg, nblocks, urls in ex.map(work, platforms):
            for u, ts in urls:
                w.writerow([u, reg, tranco[reg], ts, args.index])
            tot += len(urls)
            print(f"{reg}: blocks_in_range={nblocks} urls={len(urls)}", flush=True)
    print("DONE", tot, out_fp, flush=True)


if __name__ == "__main__":
    main()
