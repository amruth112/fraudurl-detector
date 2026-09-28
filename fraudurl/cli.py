"""fraudurl - classify every URL in a CSV as FRAUD / LEGITIMATE / REVIEW.

    python -m fraudurl input.csv                      # writes input.fraudurl.csv
    python -m fraudurl input.csv -o results.csv --enrich
    python -m fraudurl input.csv --enrich-review      # lookups only for the uncertain (REVIEW) rows
    python -m fraudurl --url https://example.com/login --enrich-review   # one URL -> JSON on screen
    python -m fraudurl input.csv --block-list block.txt --allow-list allow.txt

Offline mode (default) never touches the network: every decision is made from the URL text.
--enrich adds DNS + RDAP (domain registration) lookups for every URL, --enrich-review only for the
rows the offline check leaves in REVIEW; both are cached per domain in ./.fraudurl_cache.
It never visits the URLs themselves.
"""
from __future__ import annotations

import argparse
import csv
import errno
import ipaddress
import json
import os
import re
import sys
import time
import unicodedata
from concurrent.futures import ProcessPoolExecutor

from . import __version__
from .lexical import ParsedURL, extract
from .model import Model
from .psl import _to_ascii
from .reasons import describe

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_SAFE = os.path.join(HERE, "data", "model_safe.json")
MODEL_ENRICH = os.path.join(HERE, "data", "model_enrich.json")

OUT_COLS = ["fraud_verdict", "fraud_probability", "verdict_confidence", "top_reasons",
            "registrable_domain", "analysis_mode", "lookup_status", "error"]

_MODEL: Model | None = None      # safe (URL-only) model - always used
_ENRICH: Model | None = None     # optional residual model on DNS/RDAP features
_BASE_RATE = None
_LISTS = None                    # the user's own allow/block lists (see _load_lists)


def _init_worker(enrich, base_rate, lists=None):
    global _MODEL, _ENRICH, _BASE_RATE, _LISTS
    _MODEL = Model(MODEL_SAFE)
    _ENRICH = Model(MODEL_ENRICH) if enrich else None
    _BASE_RATE = base_rate
    _LISTS = lists


def score_rows(rows, extra_feats=None):
    """rows: list of URL strings. Returns list of result dicts (one per URL)."""
    m = _MODEL
    out = []
    for i, url in enumerate(rows):
        res = {"registrable_domain": "", "error": ""}
        if url is None or not str(url).strip():
            res.update(fraud_verdict="ERROR", error="empty URL")
            out.append(res)
            continue
        f = extract(str(url))
        if f.get("parse_error"):
            res.update(fraud_verdict="ERROR", error="could not parse a hostname from this value")
            out.append(res)
            continue
        if any(ch.isspace() for ch in str(url).strip()) or (not f.get("host_is_ip") and f.get("host_n_labels", 0) < 2):
            res.update(fraud_verdict="ERROR", error="not a URL (contains spaces or has no domain name)")
            out.append(res)
            continue
        ef = extra_feats[i] if extra_feats is not None else None
        try:
            raw, p, contrib, x = m.predict(f, want_reasons=True)
            names, used = list(m.features), m
            if _ENRICH is not None and ef:
                # enriched: safe log-odds + DNS/RDAP correction, with its own calibration/thresholds
                xe = _ENRICH.vector(ef)
                r2, c2 = _ENRICH.raw_with_contrib(xe)
                raw = raw + r2
                p = _ENRICH.calibrate(raw)
                contrib, x, names, used = contrib + c2, x + xe, names + list(_ENRICH.features), _ENRICH
        except Exception as e:  # noqa: BLE001
            res.update(fraud_verdict="ERROR", error=f"scoring failed: {type(e).__name__}")
            out.append(res)
            continue
        # Verdicts use thresholds fixed by measured error rates (prior-independent). The reported
        # probability can be re-weighted to the user's expected fraud rate (--base-rate); if that
        # re-weighting contradicts the verdict, the row is downgraded to REVIEW.
        th = used.thresholds
        p_adj = used.adjust_prior(p, _BASE_RATE)
        if p >= th["fraud"] and p_adj >= 0.5:
            verdict, conf = "FRAUD", p_adj
        elif p <= th["legit"] and p_adj <= 0.5:
            verdict, conf = "LEGITIMATE", 1 - p_adj
        else:
            verdict, conf = "REVIEW", max(p_adj, 1 - p_adj)
        p = p_adj
        order = sorted(range(len(contrib)), key=lambda j: -contrib[j] if verdict != "LEGITIMATE" else contrib[j])
        reasons = [r for r in (describe(names[j], x[j], contrib[j], f) for j in order
                               if (contrib[j] > 0.05 if verdict != "LEGITIMATE" else contrib[j] < -0.05)
                               and x[j] == x[j]) if r][:3]
        res.update(fraud_verdict=verdict, fraud_probability=f"{p:.3f}", verdict_confidence=f"{conf:.3f}",
                   top_reasons="; ".join(reasons))
        out.append(res)
    return out


def _safe_cell(v):
    """Prevent spreadsheet formula injection in generated cells (=, +, -, @ at the start)."""
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def _chunk_job(args):
    urls, enrich_feats = args
    parsed = []
    for u in urls:
        try:
            parsed.append(ParsedURL(str(u)) if u else None)
        except Exception:  # noqa: BLE001
            parsed.append(None)
    res = score_rows(urls, enrich_feats)
    for r, p in zip(res, parsed):
        r["registrable_domain"] = p.reg if p is not None else ""
        if _LISTS and p is not None and p.host and r["fraud_verdict"] != "ERROR":
            hit = _list_match(_LISTS, p)
            if hit:
                _apply_list(r, *hit)
    return res


# ------------------------------------------------------------------ the user's own allow / block lists
_HOSTNAME = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)+")
_PLAIN_HOST = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+\.?")
_NOT_IP_LETTER = re.compile(r"[g-wyzG-WYZ]")  # a letter outside hex digits and 'x': cannot be an IP spelling
_HOSTS_FILE_IPS = ("0.0.0.0", "127.0.0.1", "::1", "::")


def _canon_ip(host):
    """One spelling per IP address, so '1.2.3.4', '0x01020304', '16909060' and '01.02.03.04' all match."""
    h = host.strip("[]")
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    parts = h.split(".")
    try:
        vals = [int(x, 16) if x.lower().startswith("0x") else int(x, 8) if len(x) > 1 and x.startswith("0")
                else int(x, 10) for x in parts]
    except ValueError:
        return host
    if (not 1 <= len(vals) <= 4 or any(v < 0 for v in vals) or any(v > 255 for v in vals[:-1])
            or vals[-1] >= 256 ** (5 - len(vals))):
        return host
    n = 0
    for v in vals[:-1]:
        n = n * 256 + v
    return str(ipaddress.IPv4Address(n * 256 ** (5 - len(vals)) + vals[-1]))


def _uts46_host(host_unicode):
    """Browser (UTS-46 non-transitional) spelling of a host with 'ß' or 'ς'. The IDNA-2003 conversion used
    for the model maps them to 'ss' / 'σ', i.e. to a different domain, which a list must not do."""
    out = []
    for lab in host_unicode.split("."):
        lab = unicodedata.normalize("NFC", lab.lower())
        if "ß" in lab or "ς" in lab:
            try:
                out.append("xn--" + lab.encode("punycode").decode("ascii"))
                continue
            except UnicodeError:
                pass
        out.append(lab if lab.isascii() else _to_ascii(lab))
    return ".".join(out)


def _list_host(p):
    if p.ip:
        return _canon_ip(p.host)
    if "ß" in p.host_unicode or "ς" in p.host_unicode:
        return _uts46_host(p.host_unicode)
    return p.host


def _norm_target(path, query):
    """Path (+ ?query) for prefix matching: lower-case, %2e decoded, '.' and '..' segments resolved as a
    browser would, so '/secure/../x' cannot slip past an entry for '/x'."""
    path = path or "/"
    raw = path.split("/")[1:] if path.startswith("/") else path.split("/")
    segs = []
    for s in raw:
        s = s.lower().replace("%2e", ".")
        if s in (".", ".."):
            if s == ".." and segs:
                segs.pop()
            continue
        segs.append(s)
    if raw and raw[-1].lower().replace("%2e", ".") in (".", ".."):
        segs.append("")
    return "/" + "/".join(segs) + (f"?{query}" if query else "")


def _prefix_candidates(t):
    """Every prefix of t that ends at a boundary ('/', '?', '&'), with and without that character, plus t:
    an entry '/secure' matches '/secure', '/secure/x' and '/secure?a' but not '/secure-verify'."""
    out, q = {t}, t.find("?")
    for i, ch in enumerate(t):
        if ch == "/" or (ch == "?" and i == q) or (ch == "&" and -1 < q < i):
            out.add(t[:i])
            out.add(t[:i + 1])
    return out


def _load_lists(allow_files=(), block_files=()):
    """Read allow/block list files: one entry per line, '#' lines are comments and anything after the
    first space is ignored (room for a note); hosts-file lines ('0.0.0.0 evil.com') are understood.
    An entry is a domain or host (example.com also covers every subdomain such as login.example.com),
    an IP address, or a URL with a path (covers URLs under it; '*.example.com/path' also on subdomains).
    Returns None when no files are given."""
    if not allow_files and not block_files:
        return None
    lists = {"_notes": []}
    for kind, files in (("block", block_files), ("allow", allow_files)):
        hosts, prefixes, wprefixes, n = set(), {}, {}, 0
        for path in files or ():
            if not os.path.isfile(path):
                raise SystemExit(f"{kind} list not found: {path}")
            good, bad = 0, []
            with _open_text(path) as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.replace("﻿", "").strip()
                    if not line or line.startswith("#"):
                        continue
                    tok = line.split()
                    entry = tok[1] if len(tok) > 1 and tok[0] in _HOSTS_FILE_IPS else tok[0]
                    wild = entry.startswith("*.")
                    entry = entry[2:] if wild else entry
                    entry = entry.lstrip(".")
                    if _PLAIN_HOST.fullmatch(entry) and _NOT_IP_LETTER.search(entry):  # fast path: plain domain
                        hosts.add(entry.lower().rstrip("."))
                        good += 1
                        continue
                    try:
                        p = ParsedURL(entry)
                    except Exception:  # noqa: BLE001
                        p = None
                    h = _list_host(p) if p is not None and p.host else ""
                    if not h or not (p.ip or _HOSTNAME.fullmatch(h)):
                        bad.append(lineno)
                        continue
                    t = _norm_target(p.path, p.query)
                    if t == "/":
                        hosts.add(h)
                    else:
                        (wprefixes if wild else prefixes).setdefault(h, set()).add(t)
                    good += 1
            if not good:
                raise SystemExit(f"{kind} list {path} has no valid entries (one domain or URL per line)")
            if bad:
                lists["_notes"].append(f"{kind} list {path}: {len(bad)} line(s) skipped as not a domain, IP or URL "
                                       f"(first: line {bad[0]})")
            n += good
        lists[kind] = {"hosts": hosts, "prefixes": prefixes, "wprefixes": wprefixes, "entries": n}
    return lists


def _list_match(lists, p):
    """('block'|'allow', matched entry) or None. The block list is checked first and always wins."""
    host = _list_host(p)
    parents = [host] if p.ip else [".".join(host.split(".")[i:]) for i in range(host.count(".") + 1)]
    cands = None
    for kind in ("block", "allow"):
        lst = lists.get(kind)
        if not lst:
            continue
        if lst["prefixes"] or lst["wprefixes"]:
            if cands is None:
                cands = _prefix_candidates(_norm_target(p.path, p.query))
            hit = cands & lst["prefixes"].get(host, set())
            if hit:
                return kind, host + max(hit, key=len)
            for par in parents:
                hit = cands & lst["wprefixes"].get(par, set())
                if hit:
                    return kind, "*." + par + max(hit, key=len)
        for par in parents:
            if par in lst["hosts"]:
                return kind, par
    return None


def _apply_list(r, kind, entry):
    r["_model_verdict"], r["_model_prob"] = r["fraud_verdict"], r.get("fraud_probability", "")
    r["fraud_verdict"] = "FRAUD" if kind == "block" else "LEGITIMATE"
    r["verdict_confidence"] = r["fraud_probability"] = ""  # an analyst decision, not a model probability
    alone = r["_model_verdict"] + (f" ({r['_model_prob']})" if r["_model_prob"] else "")
    r["top_reasons"] = f"on your {kind} list (entry '{entry}'); the model alone said {alone}"
    r["_list"] = kind


def _detect_encoding(path) -> str:
    """UTF-16/UTF-8 BOMs first; otherwise validate the WHOLE file as UTF-8 (streaming, fast)
    and fall back to Windows-1252 if any byte sequence is invalid."""
    import codecs
    with open(path, "rb") as fh:
        head = fh.read(4)
        if head.startswith(codecs.BOM_UTF8):
            return "utf-8-sig"
        if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            return "utf-16"
        fh.seek(0)
        dec = codecs.getincrementaldecoder("utf-8")()
        try:
            for block in iter(lambda: fh.read(1 << 20), b""):
                dec.decode(block)
            dec.decode(b"", final=True)
            return "utf-8"
        except UnicodeDecodeError:
            return "cp1252"


def _open_text(path):
    return open(path, encoding=_detect_encoding(path), newline="", errors="replace")


_URL_HEADERS = ("url", "urls", "link", "links", "href", "uri", "website", "site", "domain", "address")


def _looks_like_url(v: str) -> bool:
    v = (v or "").strip()
    if not v or len(v) < 4 or any(c.isspace() for c in v):
        return False
    if "://" in v[:12]:
        return True
    if "@" in v.split("/", 1)[0]:  # e-mail address, not a URL
        return False
    host = v.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0]
    labels = host.split(".")
    return len(labels) >= 2 and all(labels) and (labels[-1].isalpha() and len(labels[-1]) >= 2
                                                 or host.replace(".", "").isdigit())


def _strong_url(v: str) -> bool:
    """Unmistakably a URL (scheme, 'www.' or a path) - used to tell data rows from header rows."""
    v = (v or "").strip()
    return _looks_like_url(v) and ("://" in v[:12] or v.lower().startswith("www.") or "/" in v)


def _detect_delimiter(lines) -> str:
    """Pick the first delimiter (tab, comma, semicolon, pipe) that splits the header line and at least
    90% of the sample lines into 2+ fields (parsed with the csv module, so quoted fields are respected).
    None qualifies -> one URL per line (a headerless list where only some URLs contain commas stays intact)."""
    for d in ("\t", ",", ";", "|"):
        rows = [r for r in csv.reader(lines, delimiter=d) if r]
        if rows and len(rows[0]) >= 2 and sum(len(r) >= 2 for r in rows) >= 0.9 * len(rows):
            return d
    return "\n"


def _pick_column(header, sample_rows, wanted):
    if wanted:
        for i, h in enumerate(header):
            if h.strip().lower() == wanted.strip().lower():
                return i
        raise SystemExit(f"column {wanted!r} not found; columns are: {header}")
    low = [h.strip().lower() for h in header]
    for name in _URL_HEADERS:  # header-name priority, not column order
        if name in low:
            return low.index(name)
    for i, h in enumerate(low):
        if ("url" in h or "link" in h) and "mail" not in h:
            return i
    # fall back to the column whose values look most like URLs
    best, best_i = -1, 0
    for i in range(len(header)):
        score = sum(_strong_url(r[i]) * 2 + _looks_like_url(r[i]) for r in sample_rows if i < len(r))
        if score > best:
            best, best_i = score, i
    return best_i


def _enrich_mode(enrich) -> str:
    """'off' | 'review' (lookups only for rows the offline check leaves in REVIEW) | 'all'.
    Any non-string value is read as before: truthy = 'all', falsy = 'off'."""
    if isinstance(enrich, str):
        if enrich in ("", "off", "none"):
            return "off"
        if enrich in ("review", "all"):
            return enrich
        raise SystemExit(f"enrich mode must be 'off', 'review' or 'all', not {enrich!r}")
    return "all" if enrich else "off"


def _open_input(inp, url_column):
    """Open a CSV / text file and work out delimiter, header and URL column.
    Returns (file, delimiter, row reader, header, first data rows, URL column index)."""
    csv.field_size_limit(min(sys.maxsize, 2 ** 31 - 1))  # allow very long URLs / fields
    fin = _open_text(inp)
    sample = [fin.readline() for _ in range(50)]
    fin.seek(0)
    delim = _detect_delimiter([ln for ln in sample if ln.strip()])
    reader = csv.reader(fin, delimiter=delim) if delim != "\n" else ([ln.rstrip("\r\n")] for ln in fin)
    head = []
    for row in reader:  # look ahead a few rows to understand the file
        head.append(row)
        if len(head) >= 50:
            break
    if not head:
        raise SystemExit("input CSV is empty")
    first = head[0]
    if url_column is not None or any(c.strip().lower() in _URL_HEADERS or "url" in c.lower() for c in first):
        has_header = True
    else:
        width = max(len(r) for r in head)
        cand = _pick_column([str(i) for i in range(width)], head[1:] or head, None)
        rest_strong = sum(_strong_url(r[cand]) for r in head[1:] if cand < len(r))
        first_cell = first[cand] if cand < len(first) else ""
        # a header row: its cell is not a URL while the rows below it are
        has_header = not _strong_url(first_cell) and (rest_strong > 0 or not _looks_like_url(first_cell))
    if has_header:
        header, first_rows = first, head[1:]
    else:
        header, first_rows = [f"column_{i + 1}" for i in range(len(first))], head
    ucol = _pick_column(header, first_rows, url_column)
    return fin, delim, reader, header, first_rows, ucol


def _num(v):
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _unique_names(header):
    """JSON keys for the original columns: blank names become column_<n>, repeats get _2, _3, ..."""
    seen, out = set(), []
    for j, h in enumerate(header):
        base = h or f"column_{j + 1}"
        name, k = base, 2
        while name in seen:
            name, k = f"{base}_{k}", k + 1
        seen.add(name)
        out.append(name)
    return out


def _clean_arg(u):
    """A command-line URL with undecodable bytes (lone surrogates) becomes U+FFFD instead of crashing output."""
    u = str(u)
    try:
        return u.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except UnicodeEncodeError:
        return u.encode("utf-8", "surrogatepass").decode("utf-8", "replace")


def _json_record(url, row, keys, res, offline, evidence, with_input):
    kind = res.get("_list")
    rec = {"url": url,
           "fraud_verdict": res.get("fraud_verdict"),
           "fraud_probability": _num(res.get("fraud_probability")),
           "verdict_confidence": _num(res.get("verdict_confidence")),
           "top_reasons": [x for x in (res.get("top_reasons") or "").split("; ") if x],
           "registrable_domain": res.get("registrable_domain") or None,
           "analysis_mode": res.get("analysis_mode"),
           "lookup_status": res.get("lookup_status") or None,
           "error": res.get("error") or None}
    stages = {"offline_check": {"verdict": res.get("_model_verdict", offline[0]) if kind else offline[0],
                              "probability": _num(res.get("_model_prob", offline[1]) if kind else offline[1])}}
    if kind:
        stages["your_list"] = {"list": kind, "decision": res.get("fraud_verdict")}
    if evidence:
        stages["lookups"] = evidence
    rec["stages"] = stages
    if with_input:
        rec["input"] = dict(zip(keys, row + [""] * (len(keys) - len(row))))
    return rec


def run(inp, outp, url_column=None, enrich=False, workers=None, chunk=20000, base_rate=None,
        cache_dir=None, quiet=False, urls=None, fmt="csv", allow_lists=(), block_lists=()):
    """Score a CSV/text file (``inp``) or a list of URLs (``urls``) and write CSV or JSON lines to ``outp``
    ('-' or None = the screen). ``enrich``: False/'off', 'review' or True/'all'."""
    emode = _enrich_mode(enrich)
    enrich = emode != "off"
    if enrich and not os.path.exists(MODEL_ENRICH):
        print("note: no enrichment model shipped; using offline mode", file=sys.stderr)
        enrich, emode = False, "off"
    if fmt not in ("csv", "json"):
        raise SystemExit("output format must be 'csv' or 'json'")
    to_screen = outp in (None, "-")
    if urls is not None and not workers and len(urls) < 5000:
        workers = 1  # a handful of URLs: starting worker processes would cost more than it saves
    workers = workers or max(1, min(4, (os.cpu_count() or 2)))
    workers = max(1, min(workers, 61))  # Windows cannot wait on more than 61 worker processes
    if urls is None and not os.path.isfile(inp):
        raise SystemExit(f"input file not found: {inp}")
    if not to_screen:
        out_dir = os.path.dirname(os.path.abspath(outp))
        if not os.path.isdir(out_dir):
            raise SystemExit(f"output folder does not exist: {out_dir}")
        if urls is None and os.path.exists(outp) and os.path.samefile(inp, outp):
            raise SystemExit("output file is the same as the input file; choose another name with -o")
    lists = _load_lists(allow_lists, block_lists)
    if lists:
        for note in lists["_notes"]:
            print(f"warning: {note}", file=sys.stderr)
        if not quiet:
            print(", ".join(f"{k} list: {lists[k]['entries']:,} entries" for k in ("block", "allow")
                            if lists[k]["entries"]), file=sys.stderr)
    t0 = time.time()
    if urls is None:
        fin, delim, reader, header, first_rows, ucol = _open_input(inp, url_column)
    else:
        fin, delim, reader, header, first_rows, ucol = None, ",", iter(()), ["url"], [[_clean_arg(u)] for u in urls], 0
    keys = _unique_names(header)
    try:
        if to_screen:
            fout = sys.stdout
            try:
                fout.reconfigure(encoding="utf-8", newline="")
            except (AttributeError, ValueError):
                pass
        else:  # CSV gets a BOM so Excel shows non-ASCII correctly
            fout = open(outp, "w", encoding="utf-8-sig" if fmt == "csv" else "utf-8", newline="")
    except OSError as e:
        raise SystemExit(f"cannot write {outp}: {e.strerror or e}")
    w = csv.writer(fout) if fmt == "csv" else None
    if w is not None:
        w.writerow(header + OUT_COLS)
    enricher = None  # created on first use, so --enrich-review costs nothing when no row needs a lookup
    counts, n = {}, 0
    multiline = [0, 0]  # rows with a line break inside a cell, first such data row (unbalanced-quote hint)
    pool = (ProcessPoolExecutor(workers, initializer=_init_worker, initargs=(enrich, base_rate, lists))
            if workers > 1 else None)
    if pool is None:
        _init_worker(enrich, base_rate, lists)

    def score(pairs):
        parts = [([u for u, _ in pairs[i:i + 1000]],
                  [e for _, e in pairs[i:i + 1000]] if any(e for _, e in pairs[i:i + 1000]) else None)
                 for i in range(0, len(pairs), 1000)]
        out = []
        for r in (pool.map(_chunk_job, parts) if pool else map(_chunk_job, parts)):
            out.extend(r)
        return out

    def flush(rows):
        nonlocal n, enricher
        urls_ = [r[ucol] if ucol < len(r) else "" for r in rows]
        # pass 1: offline check of every row (also applies the user's allow/block lists)
        results = score([(u, None) for u in urls_])
        offline = [(r.get("fraud_verdict"), r.get("fraud_probability", "")) for r in results]
        status = [""] * len(rows)
        modes = [f"your {r['_list']} list" if r.get("_list") else "offline (URL text only)" for r in results]
        evidence = [None] * len(rows)
        # pass 2: DNS + RDAP lookups for every row ('all') or only the uncertain ones ('review')
        if enrich:
            if emode == "all":
                idx = [i for i, r in enumerate(results) if not r.get("_list")]
            else:
                idx = [i for i, r in enumerate(results) if r["fraud_verdict"] == "REVIEW"]
                for i, r in enumerate(results):
                    if r["fraud_verdict"] in ("FRAUD", "LEGITIMATE") and not r.get("_list"):
                        modes[i] = "offline (URL text only; clear without lookups)"
                        status[i] = "not looked up (verdict already clear)"
            if idx:
                if enricher is None:
                    from .enrich import Enricher
                    try:
                        enricher = Enricher(cache_dir or os.path.join(os.getcwd(), ".fraudurl_cache"))
                    except OSError as e:
                        raise SystemExit(f"cannot use the lookup cache folder: {e.strerror or e}")
                ev = [] if fmt == "json" else None
                efeats, st = _enrich_chunk(enricher, [urls_[i] for i in idx], evidence=ev)
                redo = [k for k, e in enumerate(efeats) if e]
                for k, res in zip(redo, score([(urls_[idx[k]], efeats[k]) for k in redo])):
                    results[idx[k]] = res
                for k, i in enumerate(idx):
                    status[i] = st[k]
                    modes[i] = ("enriched (URL + DNS + RDAP)" if efeats[k]
                                else "offline (enrichment unavailable for this URL)")
                    if ev is not None:
                        evidence[i] = ev[k]
        if delim != "\n":
            for i, r in enumerate(rows):
                if any("\n" in c or "\r" in c for c in r):
                    multiline[0] += 1
                    multiline[1] = multiline[1] or n + i + 1
        for i, (row, res) in enumerate(zip(rows, results)):
            res["analysis_mode"] = modes[i]
            res["lookup_status"] = status[i]
            counts[res["fraud_verdict"]] = counts.get(res["fraud_verdict"], 0) + 1
            if len(row) > len(header):  # extra fields: keep them (joined) in the last column
                row = row[: len(header) - 1] + [(delim if delim != "\n" else " ").join(row[len(header) - 1:])]
            if w is not None:
                row = row + [""] * (len(header) - len(row))  # short rows: keep result columns aligned
                w.writerow(row + [_safe_cell(res.get(c, "")) for c in OUT_COLS])
            else:
                rec = _json_record(urls_[i], row, keys, res, offline[i], evidence[i], with_input=urls is None)
                fout.write(json.dumps(rec) + "\n")  # ASCII-only JSON: safe on any console and line reader
        n += len(rows)
        if not quiet:
            el = time.time() - t0
            print(f"\r{n:,} URL{'' if n == 1 else 's'} processed ({n / max(el, 1e-9):,.0f}/s)", end="",
                  file=sys.stderr, flush=True)

    buf = list(first_rows)
    try:
        for row in reader:
            buf.append(row)
            if len(buf) >= chunk:
                flush(buf); buf = []
    except csv.Error as e:
        raise SystemExit(f"could not read the CSV near data row {n + len(buf) + 1}: {e}")
    if buf:
        flush(buf)
    if pool:
        pool.shutdown()
    if enricher:
        enricher.close()
    if to_screen:
        fout.flush()
    else:
        fout.close()
    if fin is not None:
        fin.close()
    el = time.time() - t0
    summary = {"rows": n, "seconds": round(el, 2), "urls_per_second": round(n / max(el, 1e-9)),
               "verdicts": counts, "enrich": enrich, "enrich_mode": emode,
               "output": "-" if to_screen else os.path.abspath(outp)}
    if not quiet:
        print("", file=sys.stderr)
        print(f"Done: {n:,} URL{'' if n == 1 else 's'} in {el:.1f}s -> {'screen' if to_screen else outp}",
              file=sys.stderr)
        print("Verdicts: " + ", ".join(f"{k}={v:,}" for k, v in sorted(counts.items())), file=sys.stderr)
        if multiline[0]:
            print(f"note: {multiline[0]:,} row(s) have a line break inside a cell (first at data row {multiline[1]:,}). "
                  "If rows seem to be missing, the input probably has an unbalanced quote (\") character.",
                  file=sys.stderr)
    return summary


def _platform(p) -> bool:
    """Shared platforms: domain data describes the platform (google.com is 28 years old), not the
    page an attacker put on it, so enrichment would wrongly vouch for it -> safe model only."""
    from .lexical import SHORTENERS, USER_CONTENT_HOSTS
    return bool(p.private_suffix or p.host in USER_CONTENT_HOSTS or p.reg in USER_CONTENT_HOSTS
                or p.suffix in USER_CONTENT_HOSTS or p.host in SHORTENERS or p.reg in SHORTENERS)


def _lookup_evidence(p, d, r, now):
    """The facts the DNS / registry lookups returned for one URL, for JSON output (not model features)."""
    from .enrich import _parse_dt
    ev = {}
    if d:
        ev["dns"] = {"status": d.get("a_status"), "ipv4": d.get("a") or [], "ipv6": d.get("aaaa") or [],
                     "alias_of": d.get("cname"), "ttl_seconds": d.get("ttl_a"),
                     "nameservers": d.get("ns") or [], "mail_servers": d.get("mx") or []}
    if p.private_suffix:
        ev["registration"] = {"status": "not applicable (hosting platform)"}
    elif r:
        created = _parse_dt(r.get("created"))
        ev["registration"] = {"status": r.get("status"), "registered": r.get("created"),
                              "expires": r.get("expires"), "last_changed": r.get("changed"),
                              "registrar": r.get("registrar"), "registry_status": r.get("domain_status") or [],
                              "domain_age_days": (now - created).days if created else None}
    return ev


def _enrich_chunk(enricher, urls, evidence=None):
    """DNS + RDAP features and a status note per URL. If ``evidence`` is a list, the raw lookup facts
    for each URL are appended to it (for JSON output)."""
    from datetime import datetime, timezone
    from .enrich import dns_features, rdap_features
    ps = []
    for u in urls:
        try:
            p = ParsedURL(str(u)) if u and not any(c.isspace() for c in str(u).strip()) else None
            ps.append(p if p is not None and p.host and ("." in p.host or p.ip) else None)
        except Exception:  # noqa: BLE001
            ps.append(None)
    items = [(p.host, p.reg, p.ip, p.private_suffix) for p in ps if p is not None and not p.ip and not _platform(p)]
    dns_r, rdap_r = enricher.run(items)
    now = datetime.now(timezone.utc)
    feats, status = [], []
    for p in ps:
        if p is None or not p.host or p.ip:
            feats.append({}); status.append("skipped (no domain)" if p is None or not p.host else "skipped (IP host)")
            if evidence is not None:
                evidence.append(None)
            continue
        if _platform(p):
            feats.append({}); status.append("skipped (shared hosting platform: domain data would describe the platform, not this page)")
            if evidence is not None:
                evidence.append(None)
            continue
        if evidence is not None:
            evidence.append(_lookup_evidence(p, dns_r.get(p.host), rdap_r.get(p.reg), now))
        d = dns_r.get(p.host)
        d_st = (d or {}).get("a_status", "unavailable")
        if p.private_suffix:
            r_st = "not applicable (hosting platform)"
        else:
            r_st = (rdap_r.get(p.reg) or {}).get("status", "unavailable")
        f = dict(dns_features(d))
        if f.get("dns_resolves") != 1.0:
            # dead or unresolvable domain: enrichment says nothing about a live site -> safe model
            feats.append({})
            note = {"nxdomain": "domain does not exist in DNS (dead link or taken down)",
                    "nodata": "domain has no address records"}.get(d_st, f"DNS lookup failed ({d_st})")
            status.append(f"dns={d_st}; rdap={r_st}; {note}")
            continue
        if not p.private_suffix:
            f.update(rdap_features(rdap_r.get(p.reg), now))
        feats.append(f)
        status.append(f"dns={d_st}; rdap={r_st}")
    return feats, status


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fraudurl", description="Classify URLs in a CSV as FRAUD / LEGITIMATE / REVIEW.")
    ap.add_argument("input", nargs="?", help="CSV or text file of URLs (or use --url instead)")
    ap.add_argument("--url", action="append", metavar="URL",
                    help="check this URL instead of a file (repeat for several); results go to the screen as JSON")
    ap.add_argument("-o", "--output", help="output file (default: <input>.fraudurl.csv; with --url: the screen). "
                                           "'-' = the screen")
    ap.add_argument("--format", choices=("csv", "json"),
                    help="csv (default for files) or json: one JSON object per line with the lookup facts "
                         "(default with --url)")
    ap.add_argument("--url-column", help="name of the URL column (auto-detected by default)")
    ap.add_argument("--enrich", action="store_true",
                    help="DNS + domain-registration lookups for EVERY URL (network; cached per domain; slow)")
    ap.add_argument("--enrich-review", action="store_true",
                    help="DNS + domain-registration lookups only for URLs the offline check leaves in REVIEW")
    ap.add_argument("--block-list", action="append", metavar="FILE",
                    help="your own list of domains/URLs that are always FRAUD (one per line; repeatable)")
    ap.add_argument("--allow-list", action="append", metavar="FILE",
                    help="your own list of domains/URLs that are always LEGITIMATE (the block list wins)")
    ap.add_argument("--workers", type=int, help="parallel worker processes (default: up to 4)")
    ap.add_argument("--base-rate", type=float, help="expected share of fraudulent URLs in your data (e.g. 0.01); "
                                                   "re-weights probabilities from the ~47%% fraud share used in calibration")
    ap.add_argument("--cache-dir", help="where enrichment results are cached (default ./.fraudurl_cache)")
    ap.add_argument("--quiet", action="store_true", help="no progress or summary messages")
    ap.add_argument("--version", action="version", version=f"fraudurl {__version__}")
    a = ap.parse_args(argv)
    if a.enrich and a.enrich_review:
        ap.error("use either --enrich (every URL) or --enrich-review (only REVIEW rows), not both")
    if a.url and a.input:
        ap.error("give either an input file or --url, not both")
    if not a.url and not a.input:
        ap.error("give an input file, or one or more --url")
    if a.base_rate is not None and not 0 < a.base_rate < 1:
        raise SystemExit("--base-rate must be between 0 and 1")
    fmt = a.format or ("json" if a.url else "csv")
    if a.url:
        outp = a.output or "-"
    else:
        outp = a.output or os.path.splitext(a.input)[0] + (".fraudurl.csv" if fmt == "csv" else ".fraudurl.jsonl")
    emode = "review" if a.enrich_review else ("all" if a.enrich else "off")
    try:
        run(a.input, outp, a.url_column, emode, a.workers, base_rate=a.base_rate, cache_dir=a.cache_dir,
            quiet=a.quiet, urls=a.url, fmt=fmt, allow_lists=a.allow_list or (), block_lists=a.block_list or ())
    except OSError as e:  # the reader of our output (e.g. '| head -1') went away: stop quietly
        if outp != "-" or not (isinstance(e, BrokenPipeError) or e.errno in (errno.EPIPE, errno.EINVAL)):
            raise
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
        raise SystemExit(1)


if __name__ == "__main__":
    main()
