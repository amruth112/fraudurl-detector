"""Harvest REAL legitimate deep URLs from the Common Crawl URL index (CDX API).

Label source: a URL is 'legitimate' if its registrable domain is in the Tranco top-1M
list (research-grade popularity ranking, list id recorded) AND the URL was actually
captured by Common Crawl's 2026 crawl with HTTP 200 / text/html. Domains that appear in
any phishing/malware feed we downloaded are excluded (label conflict).

Domains are sampled across the whole Tranco range (not just giant sites) so the legit
class includes long-tail small sites. Only the public CDX index is queried - no website
is visited. Polite: few concurrent requests, retries with backoff, resumable output.

Usage: python experiments/harvest_cc_legit.py --domains 3000 --per-domain 3
"""
from __future__ import annotations

import argparse
import bz2
import csv
import glob
import io
import json
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from fraudurl.lexical import ParsedURL  # noqa: E402

RAW = os.path.join(ROOT, "data", "raw")
OUT = os.path.join(RAW, "cc_legit")
UA = "fraudurl-research/1.0 (academic phishing-detection experiment; low rate)"


def feed_domains():
    """Registrable domains present in any phishing/malware feed snapshot (to exclude)."""
    regs = set()
    for f in glob.glob(os.path.join(RAW, "feeds", "phishtank_*.csv.bz2")):
        rows = csv.DictReader(io.StringIO(bz2.decompress(open(f, "rb").read()).decode("utf-8", "replace")))
        for r in rows:
            regs.add(ParsedURL(r["url"]).reg)
    for f in glob.glob(os.path.join(RAW, "feeds", "openphish_*.txt")):
        for line in open(f, encoding="utf-8", errors="replace"):
            if line.strip():
                regs.add(ParsedURL(line.strip()).reg)
    for f in glob.glob(os.path.join(RAW, "feeds", "urlhaus_*.csv")):
        for line in open(f, encoding="utf-8", errors="replace"):
            if line.startswith('"'):
                parts = line.split('","')
                if len(parts) > 2:
                    regs.add(ParsedURL(parts[2]).reg)
    regs.discard("")
    return regs


def sample_domains(n, seed, exclude):
    tranco = os.path.join(RAW, "tranco", "top-1m.csv")
    ranks = []
    with open(tranco, encoding="utf-8") as fh:
        for line in fh:
            r, d = line.strip().split(",", 1)
            ranks.append((int(r), d.lower()))
    rng = random.Random(seed)
    buckets = [((1, 10_000), 0.2), ((10_001, 100_000), 0.3), ((100_001, 1_000_000), 0.5)]
    chosen, seen_regs = [], set()
    for (lo, hi), frac in buckets:
        pool = [x for x in ranks if lo <= x[0] <= hi]
        rng.shuffle(pool)
        k = int(round(n * frac))
        for r, d in pool:
            if k == 0:
                break
            reg = ParsedURL("http://" + d).reg
            if not reg or reg in exclude or reg in seen_regs:
                continue
            seen_regs.add(reg)
            chosen.append((r, d))
            k -= 1
    return chosen


_last = [0.0]
_lock = threading.Lock()


def cdx_query(index, domain, limit, min_interval):
    q = urllib.parse.urlencode([("url", domain), ("matchType", "domain"), ("output", "json"),
                                ("limit", str(limit)), ("fl", "url,status,mime,timestamp"),
                                ("filter", "status:200"), ("filter", "mime:text/html")])
    url = f"https://index.commoncrawl.org/{index}-index?{q}"
    for attempt in range(4):
        with _lock:
            wait = _last[0] + min_interval - time.time()
            if wait > 0:
                time.sleep(wait)
            _last[0] = time.time()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read(5_000_000).decode("utf-8", "replace")
            return "ok", [json.loads(x) for x in body.splitlines() if x.startswith("{")]
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return "no_captures", []
            time.sleep(3 * (attempt + 1))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            time.sleep(3 * (attempt + 1))
    return "failed", []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domains", type=int, default=3000)
    ap.add_argument("--per-domain", type=int, default=3)
    ap.add_argument("--index", default="CC-MAIN-2026-34")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--min-interval", type=float, default=0.4)
    ap.add_argument("--seed", type=int, default=13)
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    out_fp = os.path.join(OUT, f"cc_legit_{args.index}.csv")
    log_fp = os.path.join(OUT, f"cc_legit_{args.index}.domains.jsonl")
    done = set()
    if os.path.exists(log_fp):
        for line in open(log_fp, encoding="utf-8"):
            done.add(json.loads(line)["domain"])
    excl = feed_domains()
    print(f"excluding {len(excl)} feed domains", flush=True)
    doms = [x for x in sample_domains(args.domains, args.seed, excl) if x[1] not in done]
    print(f"{len(done)} domains already done, {len(doms)} to query", flush=True)
    new_file = not os.path.exists(out_fp)
    out = open(out_fp, "a", encoding="utf-8", newline="")
    w = csv.writer(out)
    if new_file:
        w.writerow(["url", "tranco_rank", "tranco_domain", "cc_timestamp", "cc_index"])
    log = open(log_fp, "a", encoding="utf-8")
    wlock = threading.Lock()
    stats = {"ok": 0, "no_captures": 0, "failed": 0, "urls": 0}

    def work(item):
        rank, dom = item
        st, rows = cdx_query(args.index, dom, 60, args.min_interval)
        rng = random.Random(hash(dom) & 0xFFFFFFFF)
        by_url = {}
        for r in rows:
            u = r.get("url", "")
            if u and ParsedURL(u).reg == ParsedURL("http://" + dom).reg:
                by_url.setdefault(u, r)
        urls = list(by_url.values())
        rng.shuffle(urls)
        picked = urls[: args.per_domain]
        with wlock:
            for r in picked:
                w.writerow([r["url"], rank, dom, r.get("timestamp", ""), args.index])
            out.flush()
            log.write(json.dumps({"domain": dom, "rank": rank, "status": st, "n_rows": len(rows),
                                  "n_picked": len(picked)}) + "\n")
            log.flush()
            stats[st if st in stats else "failed"] += 1
            stats["urls"] += len(picked)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for i, _ in enumerate(ex.map(work, doms)):
            if (i + 1) % 100 == 0:
                print(f"{i + 1}/{len(doms)} {stats}", flush=True)
    print("DONE", stats, flush=True)


if __name__ == "__main__":
    main()
