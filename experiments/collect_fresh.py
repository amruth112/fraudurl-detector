"""Collect fresh (2026) data:
  * OpenPhish community feed history (git): first-seen time for every phishing URL.
  * Hacker News stories (Algolia API): real legitimate links submitted in the last 30 days.
Outputs go to data/raw/feeds/. Nothing here visits any listed URL.
"""
from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEEDS = os.path.join(ROOT, "data", "raw", "feeds")
REPO = os.path.join(ROOT, ".cache", "tmp", "feeds", "openphish_public_feed")


def openphish_history():
    log = subprocess.run(["git", "-C", REPO, "log", "--reverse", "--format=%H %cI", "--", "feed.txt"],
                         capture_output=True, text=True, check=True).stdout.split("\n")
    first = {}
    for line in log:
        if not line.strip():
            continue
        sha, when = line.split(" ", 1)
        blob = subprocess.run(["git", "-C", REPO, "show", f"{sha}:feed.txt"], capture_output=True,
                              text=True, encoding="utf-8", errors="replace").stdout
        for u in blob.splitlines():
            u = u.strip()
            if u and u not in first:
                first[u] = when
    fp = os.path.join(FEEDS, "openphish_history_first_seen.csv")
    with open(fp, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "first_seen"])
        for u, t in first.items():
            w.writerow([u, t])
    print("openphish history:", len(first), "unique URLs ->", fp, flush=True)


def hacker_news(days=30):
    now = int(time.time())
    rows = {}
    for d in range(days):
        hi, lo = now - d * 86400, now - (d + 1) * 86400
        url = ("https://hn.algolia.com/api/v1/search_by_date?tags=story&hitsPerPage=1000"
               f"&numericFilters=created_at_i>{lo},created_at_i<={hi}")
        for attempt in range(3):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "fraudurl-research/1.0"})
                with urllib.request.urlopen(req, timeout=60) as r:
                    hits = json.loads(r.read())["hits"]
                break
            except Exception:  # noqa: BLE001
                time.sleep(5)
                hits = []
        for h in hits:
            u = (h.get("url") or "").strip()
            if u and u not in rows:
                rows[u] = (h.get("created_at", "")[:10], h.get("points") or 0, h.get("objectID"))
        print(f"day -{d}: {len(hits)} hits, total urls {len(rows)}", flush=True)
        time.sleep(1.0)
    fp = os.path.join(FEEDS, "hn_stories_30d.csv")
    with open(fp, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "date", "points", "hn_id"])
        for u, (dt, pts, oid) in rows.items():
            w.writerow([u, dt, pts, oid])
    print("hn:", len(rows), "->", fp, flush=True)


if __name__ == "__main__":
    what = sys.argv[1:] or ["openphish", "hn"]
    if "openphish" in what:
        openphish_history()
    if "hn" in what:
        hacker_news()
