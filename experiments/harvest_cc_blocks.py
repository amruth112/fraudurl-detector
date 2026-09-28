"""Harvest REAL legitimate deep URLs from Common Crawl by sampling random index blocks.

Why: the CDX query server is heavily throttled (~10 domains/min). Instead we download the
crawl's cluster.idx (a directory of ~870k compressed index blocks, 3,000 captures each),
pick blocks uniformly at random and fetch just those byte ranges from the data CDN.

Label rule (source-based, no heuristics of ours): a capture is kept as LEGITIMATE if
  * Common Crawl fetched it in the 2026 crawl with HTTP 200 and an HTML mime type, and
  * its registrable domain is in the Tranco top-1M list (id recorded), and
  * that registrable domain does not appear in any phishing/malware feed snapshot.
No website is contacted; only commoncrawl.org index files are downloaded.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import os
import random
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "experiments"))
from fraudurl.lexical import ParsedURL  # noqa: E402
from harvest_cc_legit import feed_domains  # noqa: E402

RAW = os.path.join(ROOT, "data", "raw")
OUT = os.path.join(RAW, "cc_legit")
UA = "fraudurl-research/1.0 (academic phishing-detection experiment)"


_RATE = {"min_interval": float(os.environ.get("CC_MIN_INTERVAL", "0")), "last": 0.0}
_RATE_LOCK = __import__("threading").Lock()


def fetch_block(index, fname, offset, length):
    """Fetch one compressed index block. Honours CC_MIN_INTERVAL (seconds between requests)."""
    url = f"https://data.commoncrawl.org/cc-index/collections/{index}/indexes/{fname}"
    for attempt in range(4):
        with _RATE_LOCK:
            wait = _RATE["last"] + _RATE["min_interval"] * (1 + attempt) - __import__("time").time()
            if wait > 0:
                __import__("time").sleep(wait)
            _RATE["last"] = __import__("time").time()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA,
                                                       "Range": f"bytes={offset}-{offset + length - 1}"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return gzip.decompress(r.read()).decode("utf-8", "replace").splitlines()
        except Exception:  # noqa: BLE001
            continue
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default="CC-MAIN-2026-34")
    ap.add_argument("--blocks", type=int, default=500)
    ap.add_argument("--per-domain", type=int, default=3)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    tranco = {}
    with open(os.path.join(RAW, "tranco", "top-1m.csv"), encoding="utf-8") as fh:
        for line in fh:
            r, d = line.strip().split(",", 1)
            reg = ParsedURL("http://" + d).reg
            if reg and reg not in tranco:
                tranco[reg] = int(r)
    excl = feed_domains()
    print(f"tranco regs={len(tranco)} excluded feed regs={len(excl)}", flush=True)

    idx_path = os.path.join(OUT, f"cluster_{args.index}.idx")
    blocks = []
    with open(idx_path, encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 4:
                blocks.append((parts[1], int(parts[2]), int(parts[3])))
    rng = random.Random(args.seed)
    picked = sorted(rng.sample(blocks, args.blocks))
    print(f"{len(blocks)} blocks in index, sampling {len(picked)}", flush=True)

    by_reg: dict[str, list] = {}
    n_lines = n_ok = 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for i, lines in enumerate(ex.map(lambda b: fetch_block(args.index, *b), picked)):
            for line in lines:
                n_lines += 1
                try:
                    j = json.loads(line.split(" ", 2)[2])
                except (IndexError, ValueError):
                    continue
                if j.get("status") != "200":
                    continue
                mime = (j.get("mime-detected") or j.get("mime") or "").lower()
                if "html" not in mime:
                    continue
                u = j.get("url", "")
                if not u or u.endswith("robots.txt"):
                    continue
                reg = ParsedURL(u).reg
                if reg in tranco and reg not in excl:
                    n_ok += 1
                    by_reg.setdefault(reg, []).append((u, line.split(" ", 2)[1][:8]))
            if (i + 1) % 50 == 0:
                print(f"blocks {i + 1}/{len(picked)} lines={n_lines} kept={n_ok} domains={len(by_reg)}", flush=True)

    out_fp = os.path.join(OUT, f"cc_blocks_{args.index}_s{args.seed}.csv")
    n = 0
    with open(out_fp, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "reg_domain", "tranco_rank", "cc_date", "cc_index"])
        for reg in sorted(by_reg):
            caps = list(dict.fromkeys(by_reg[reg]))  # dedupe, keep order
            rng.shuffle(caps)
            for u, ts in caps[: args.per_domain]:
                w.writerow([u, reg, tranco[reg], ts, args.index])
                n += 1
    print(f"DONE lines={n_lines} kept_captures={n_ok} domains={len(by_reg)} urls_written={n} -> {out_fp}", flush=True)


if __name__ == "__main__":
    main()
