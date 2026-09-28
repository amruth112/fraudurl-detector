"""Build the processed, leakage-safe datasets used by every experiment.

Output: data/processed/<name>.csv with columns
  url, label (1 = phishing), source, date, group (registrable domain), split (train/val/cal/test)
plus dataset-specific extras. Splits are assigned by hashing the registrable domain, so a
domain never appears in two splits.
"""
from __future__ import annotations

import bz2
import csv
import glob
import io
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import DATA, grouped_split  # noqa: E402
from fraudurl.lexical import ParsedURL  # noqa: E402

RAW, PROC = os.path.join(DATA, "raw"), os.path.join(DATA, "processed")
os.makedirs(PROC, exist_ok=True)


def _annotate(df):
    ps = [ParsedURL(u) for u in df.url]
    df["host"] = [p.host for p in ps]
    df["group"] = [p.reg or p.host for p in ps]
    df = df[df.host.astype(bool)].copy()
    df["split"] = grouped_split(df.group.values)
    return df


def _cap(df, per_host=None, per_group=None, seed=0):
    df = df.sample(frac=1.0, random_state=seed)
    if per_host:
        df = df[df.groupby("host").cumcount() < per_host]
    if per_group:
        df = df[df.groupby("group").cumcount() < per_group]
    return df


def _dedupe(df):
    df = df.copy()
    df["url"] = df.url.astype(str).str.strip()
    df = df[df.url.str.len() > 3]
    conflict = df.groupby("url").label.nunique()
    df = df[~df.url.isin(conflict[conflict > 1].index)]  # same URL labelled both ways: drop
    return df.drop_duplicates("url")


def build_hannousse():
    src = os.path.join(RAW, "candidates", "hannousse", "dataset_B_05_2020.csv")
    raw = pd.read_csv(src)
    df = pd.DataFrame({"url": raw.url, "label": (raw.status == "phishing").astype(int),
                       "source": "hannousse2020", "date": "2020"})
    extra = raw.drop(columns=["url", "status"]).add_prefix("h_")
    df = pd.concat([df, extra], axis=1)
    df = _annotate(_dedupe(df))
    df.to_csv(os.path.join(PROC, "hannousse.csv"), index=False)
    return df


def phishtank_frame():
    f = sorted(glob.glob(os.path.join(RAW, "feeds", "phishtank_online-valid_*.csv.bz2")))[-1]
    pt = pd.read_csv(io.BytesIO(bz2.decompress(open(f, "rb").read())), dtype=str)
    return pd.DataFrame({"url": pt.url, "label": 1, "source": "phishtank_online_valid",
                         "date": pt.submission_time.str[:10], "target": pt.target,
                         "snapshot": os.path.basename(f)})


def cc_legit_frame():
    parts = []
    for f in glob.glob(os.path.join(RAW, "cc_legit", "cc_*.csv")):
        d = pd.read_csv(f, dtype=str)
        if "url" not in d or d.empty:
            continue
        date = d["cc_date"] if "cc_date" in d else d.get("cc_timestamp", pd.Series([""] * len(d))).str[:8]
        # Early block harvests did not record the capture timestamp. Every row comes from crawl
        # CC-MAIN-2026-34 (captures dated 2026-08-02..2026-08-15), so use its midpoint rather than
        # leaving the date empty - an empty date only on legitimate rows would leak the label.
        date = date.fillna("20260808").replace("", "20260808")
        parts.append(pd.DataFrame({"url": d.url, "label": 0, "source": "commoncrawl_2026_tranco",
                                   "date": date.fillna("").str[:4] + "-" + date.fillna("").str[4:6] + "-" + date.fillna("").str[6:8],
                                   "tranco_rank": pd.to_numeric(d.get("tranco_rank"), errors="coerce")}))
    return pd.concat(parts, ignore_index=True)


def _tranco_top(n=10_000):
    out = {}
    with open(os.path.join(RAW, "tranco", "top-1m.csv"), encoding="utf-8") as fh:
        for line in fh:
            r, d = line.strip().split(",", 1)
            if int(r) > n:
                break
            out.setdefault(ParsedURL("http://" + d).reg, int(r))
    return out


def _feed_blocklists():
    """URLs, hosts and registrable domains present in ANY threat feed we downloaded."""
    import json as _json
    hosts, regs, urls = set(), set(), set()

    def add(u):
        urls.add(str(u).strip().split("#", 1)[0])
        try:
            p = ParsedURL(u)
        except Exception:  # noqa: BLE001
            return
        if p.host:
            hosts.add(p.host); regs.add(p.reg)
    for u in phishtank_frame().url:
        add(u)
    for f in glob.glob(os.path.join(RAW, "feeds", "openphish_*.txt")):
        for line in open(f, encoding="utf-8", errors="replace"):
            add(line.strip())
    op = os.path.join(RAW, "feeds", "openphish_history_first_seen.csv")
    if os.path.exists(op):
        for u in pd.read_csv(op).url:
            add(u)
    for f in glob.glob(os.path.join(RAW, "feeds", "urlhaus_*.csv")):
        for line in open(f, encoding="utf-8", errors="replace"):
            if line.startswith('"'):
                add(line.split('","')[2])
    cp = os.path.join(RAW, "feeds", "certpl_domains.json")
    if os.path.exists(cp):
        for r in _json.load(open(cp, encoding="utf-8")):
            add("http://" + r.get("DomainAddress", ""))
    for name in ("phishingarmy_ext.dat", "phishunt.dat"):
        fp = os.path.join(RAW, "feeds", name)
        if os.path.exists(fp):
            for line in open(fp, encoding="utf-8", errors="replace"):
                line = line.strip()
                if line and not line.startswith("#"):
                    add(line if "://" in line else "http://" + line)
    hosts.discard(""); regs.discard("")
    return hosts, regs, urls


def _platform_cap(df, platforms, per_host=3, small=3, big=30, seed=0):
    df = df.sample(frac=1.0, random_state=seed)
    df = df[df.groupby("host").cumcount() < per_host]
    rank = df.groupby("group").cumcount()
    lim = np.where(df.group.isin(platforms), big, small)
    return df[rank.values < lim]


def build_fresh26(seed=0, per_class=12000):
    """Fresh 2026 set. Phishing: OpenPhish history + PhishTank (Jun-Sep 2026).
    Legitimate: Hacker News links (Aug-Sep 2026) + Common Crawl 2026 captures on Tranco domains.
    Big multi-tenant platforms (Tranco top-10k) may appear in BOTH classes (up to 30 URLs each)
    so the model cannot learn 'google.com => phishing'; other domains are single-class."""
    platforms = set(_tranco_top(10_000))
    bad_hosts, bad_regs, bad_urls = _feed_blocklists()
    # ---- phishing
    op = pd.read_csv(os.path.join(RAW, "feeds", "openphish_history_first_seen.csv"))
    ph = pd.concat([
        pd.DataFrame({"url": op.url, "label": 1, "source": "openphish_history", "date": op.first_seen.str[:10]}),
        phishtank_frame().drop(columns=["target", "snapshot"]).query("date >= '2026-06-26'"),
    ], ignore_index=True)
    ph = _annotate(_dedupe(ph))
    ph = _platform_cap(ph, platforms, seed=seed)
    # ---- legitimate
    hn = pd.read_csv(os.path.join(RAW, "feeds", "hn_stories_30d.csv"))
    lg = pd.concat([pd.DataFrame({"url": hn.url, "label": 0, "source": "hackernews_30d", "date": hn.date}),
                    cc_legit_frame().drop(columns=["tranco_rank"])], ignore_index=True)
    lg = _annotate(_dedupe(lg))
    # platform domains (google.com, github.com ...): drop only exact feed URLs; any other
    # domain/host that ever appeared in a feed is dropped entirely from the legitimate class
    plat = lg.group.isin(platforms)
    in_feed = (~plat & (lg.host.isin(bad_hosts) | lg.group.isin(bad_regs))) |               (plat & lg.url.str.split("#", n=1).str[0].isin(bad_urls))
    lg = lg[~in_feed]
    lg = _platform_cap(lg, platforms, seed=seed)
    # a non-platform domain may not appear in both classes
    both = (set(lg.group) & set(ph.group)) - platforms
    lg, ph = lg[~lg.group.isin(both)], ph[~ph.group.isin(both)]
    n = min(per_class, len(lg), len(ph))
    df = pd.concat([lg.sample(n=n, random_state=seed), ph.sample(n=n, random_state=seed)], ignore_index=True)
    # strip #fragments on both sides (never sent to servers; crawl data never has them)
    df["url"] = df.url.str.split("#", n=1).str[0]
    df = df.drop_duplicates("url")
    df["is_platform"] = df.group.isin(platforms)
    df.to_csv(os.path.join(PROC, "fresh26.csv"), index=False)
    rows = []
    for f in glob.glob(os.path.join(RAW, "feeds", "openphish_*.txt")):
        for line in open(f, encoding="utf-8", errors="replace"):
            if line.strip():
                rows.append({"url": line.strip(), "label": 1, "source": "openphish_" + os.path.basename(f)[10:23],
                             "date": "2026-09-25"})
    op_now = _annotate(_dedupe(pd.DataFrame(rows)))
    op_now.to_csv(os.path.join(PROC, "openphish26.csv"), index=False)
    return df, op_now


def build_phreshphish(per_group=50, seed=0):
    src = os.path.join(RAW, "candidates", "phreshphish", "phreshphish_urls.tsv")
    raw = pd.read_csv(src, sep="\t", lineterminator="\n", quoting=csv.QUOTE_NONE, dtype=str)
    raw.columns = [c.strip() for c in raw.columns]
    raw = raw[raw.label.isin(["benign", "phish"])]
    df = pd.DataFrame({"url": raw.url.str.strip(), "label": (raw.label == "phish").astype(int),
                       "source": "phreshphish2025", "date": raw.date, "target": raw.target.fillna(""),
                       "lang": raw.lang, "tsplit": raw.split.str.strip()})
    df = _annotate(_dedupe(df))
    df = _cap(df, per_group=per_group, seed=seed)
    df.to_csv(os.path.join(PROC, "phreshphish.csv"), index=False)
    return df


def _norm(u):
    u = str(u).strip().lower().split("#", 1)[0]
    u = u.split("://", 1)[-1]
    if u.startswith("www."):
        u = u[4:]
    return u.rstrip("/")


def build_external():
    """External test sets (never used for training):
    * ariyadasa: Ariyadasa et al. 2021 (Mendeley n96ncsr5g4, CC BY 4.0), 80k URLs, both classes.
    * jpcert_recent: JPCERT/CC confirmed phishing first seen 2025-12-17..2026-05 (after all
      PhreshPhish data), phishing only -> recall check.
    * tranco_home: homepages of the Tranco top-10k domains (list K9PXW), legitimate only ->
      false-positive stress test (phishing is ~45-60% bare homepages, so this is the hard case).
    """
    import re
    out = {}
    sql = open(os.path.join(RAW, "candidates", "ariyadasa_pwd2021", "index.sql"), encoding="utf-8",
               errors="replace").read()
    rows = re.findall(r"\((\d+), '((?:[^'\\]|\\.)*)', '[^']*', (\d), '([^']*)'\)", sql)
    ar = pd.DataFrame({"url": [r[1].replace("\\'", "'") for r in rows], "label": [int(r[2]) for r in rows],
                       "source": "ariyadasa2021", "date": [r[3][:10] for r in rows]})
    ph = pd.read_csv(os.path.join(PROC, "phreshphish.csv"), usecols=["url"])
    seen = set(ph.url.map(_norm))
    ar = ar[~ar.url.map(_norm).isin(seen)]
    ar = _annotate(_dedupe(ar))
    ar.to_csv(os.path.join(PROC, "ariyadasa.csv"), index=False)
    out["ariyadasa"] = ar
    parts = []
    for f in glob.glob(os.path.join(RAW, "candidates", "jpcert_phishurl", "*", "*.csv")):
        d = pd.read_csv(f, dtype=str)
        d.columns = [c.strip().lower() for c in d.columns]
        if "url" in d and "date" in d:
            parts.append(d[["url", "date"]])
    jp = pd.concat(parts, ignore_index=True)
    jp["date"] = pd.to_datetime(jp.date, errors="coerce").dt.strftime("%Y-%m-%d")
    jp = jp[jp.date >= "2025-12-17"]
    jp = pd.DataFrame({"url": jp.url, "label": 1, "source": "jpcert_phishurl", "date": jp.date})
    jp = _annotate(_dedupe(jp))
    jp.to_csv(os.path.join(PROC, "jpcert_recent.csv"), index=False)
    out["jpcert_recent"] = jp
    _, bad_regs, _ = _feed_blocklists()
    top = _tranco_top(10_000)
    tr = pd.DataFrame({"url": ["https://" + d + "/" for d in top if d and d not in bad_regs],
                       "label": 0, "source": "tranco_K9PXW_top10k_homepage", "date": "2026-09-24"})
    tr = _annotate(_dedupe(tr))
    tr.to_csv(os.path.join(PROC, "tranco_home.csv"), index=False)
    out["tranco_home"] = tr
    return out


if __name__ == "__main__":
    which = sys.argv[1:] or ["hannousse", "fresh26", "phreshphish"]
    if "external" in which:
        for k, v in build_external().items():
            print(k, v.shape, v.groupby("label").size().to_dict())
    if "phreshphish" in which:
        p = build_phreshphish()
        print("phreshphish", p.shape, p.groupby(["split", "label"]).size().to_dict(),
              p.groupby(["tsplit", "label"]).size().to_dict())
    if "hannousse" in which:
        h = build_hannousse()
        print("hannousse", h.shape, h.groupby(["split", "label"]).size().to_dict())
    if "fresh26" in which:
        f, op = build_fresh26()
        print("fresh26", f.shape, f.groupby(["split", "label"]).size().to_dict(),
              f.groupby(["source", "label"]).size().to_dict(), "platform rows", int(f.is_platform.sum()))
        print("openphish26", op.shape)
