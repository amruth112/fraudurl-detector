#!/usr/bin/env python3
"""Prove (or disprove) that fraudurl_standalone.py is the fraudurl package in one file.

Offline and reproducible: nothing here makes a network request. The harness process installs an
audit hook that refuses every socket operation; the enriched-path checks run in-process against a
copy of the real DNS/RDAP cache (.cache/fraudurl_cache) with a fixed "now"; every CLI subprocess
runs in safe mode (no --enrich).

    python experiments/verify_standalone.py                  # all six checks (~15 min on 4 cores)
    python experiments/verify_standalone.py --steps 1,2,4,5  # skip the slow / cross-interpreter parts
    python experiments/verify_standalone.py --keep           # keep .cache/tmp/verify_standalone/

  1. CLI equivalence: 50+ input files / option sets through `python -m fraudurl` and
     `python fraudurl_standalone.py`. Output bytes, exit codes and normalised stdout/stderr must
     match. The standalone is also run by a second interpreter (--sys-python) and compared.
  2. Enriched path, in-process: score_rows / _chunk_job / _enrich_chunk / run(enrich=True) of both
     implementations on URLs whose hosts are in the cache, with a fixed 'now'.
  3. Self-containment: the standalone copied alone into an empty folder and run by --sys-python;
     then run under a wrapper that blocks sockets (monkeypatch + audit hook) and logs file writes.
  4. Python 3.9: ast.parse(feature_version=(3, 9)), a PEP 701 f-string scan, a 3.10+ API scan.
  5. Build: rebuilding gives identical bytes (the original file is restored in any case), embedded
     data == package data, no top-level name collisions between the concatenated modules.
  6. Speed: both on .cache/tmp/bench_200000.csv with the default 4 workers, ABBA order.

Writes results/benchmark/standalone_equivalence.json. Exit status 1 if any problem was found.
"""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True  # never drop __pycache__ into fraudurl/, experiments/ or the project root

import argparse
import ast
import base64
import contextlib
import csv
import difflib
import hashlib
import importlib.util
import io
import json
import lzma
import os
import random
import re
import shutil
import statistics
import subprocess
import time
import tokenize
import types
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SA = os.path.join(ROOT, "fraudurl_standalone.py")
PKG = os.path.join(ROOT, "fraudurl")
BUILD = os.path.join(ROOT, "experiments", "build_single_file.py")
CACHE = os.path.join(ROOT, ".cache", "fraudurl_cache")
BENCH = os.path.join(ROOT, ".cache", "tmp", "bench_200000.csv")
SCRATCH = os.path.join(ROOT, ".cache", "tmp", "verify_standalone")
OUT_JSON = os.path.join(ROOT, "results", "benchmark", "standalone_equivalence.json")
PY = sys.executable
NOW = datetime(2026, 9, 26, 12, 0, 0, tzinfo=timezone.utc)  # fixed 'now' for every RDAP age
ORDER = ["psl", "lexical", "model", "reasons", "cache", "enrich", "cli"]
DATA = ["public_suffix_list.dat", "model_safe.json", "model_enrich.json"]
sys.path.insert(0, ROOT)

# ------------------------------------------------------------------ network guard (this process)
NET_EVENTS: list = []
_NET_PREFIXES = ("socket.", "urllib.Request", "http.client.", "ftplib.", "smtplib.", "poplib.",
                 "imaplib.", "nntplib.", "telnetlib.", "webbrowser.")


def _net_guard(event, args):
    if event.startswith(_NET_PREFIXES) and event != "socket.gethostname":
        NET_EVENTS.append(event)
        raise ConnectionRefusedError(f"network blocked by verify_standalone ({event})")


sys.addaudithook(_net_guard)

PROBLEMS: list = []


def problem(where, claim, what, evidence, fix, severity):
    PROBLEMS.append({"where": where, "claim_or_case": claim, "problem": what, "evidence": evidence,
                     "suggested_fix": fix, "severity": severity})


# ------------------------------------------------------------------ small helpers
def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def read(p) -> bytes:
    with open(p, "rb") as fh:
        return fh.read()


def write(p, b: bytes):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as fh:
        fh.write(b)


def child_env(pythonpath=None):
    env = dict(os.environ)
    for k in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT"):
        env.pop(k, None)
    env.update(PYTHONUTF8="1", PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1", COLUMNS="80")
    if pythonpath:
        env["PYTHONPATH"] = pythonpath
    return env


def run_proc(cmd, cwd, env, timeout=1800):
    t = time.perf_counter()
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, timeout=timeout)
    return {"rc": p.returncode, "stdout": p.stdout.decode("utf-8", "replace"),
            "stderr": p.stderr.decode("utf-8", "replace"), "wall": time.perf_counter() - t}


def text_diff(a: str, b: str, la="package", lb="standalone", limit=60) -> str:
    d = list(difflib.unified_diff(a.splitlines(), b.splitlines(), la, lb, lineterm="", n=1))
    return "\n".join(d[:limit]) + ("\n... (%d more diff lines)" % (len(d) - limit) if len(d) > limit else "")


def cmp_bytes(a: bytes, b: bytes) -> dict:
    """Like `cmp`: identical, or the first differing byte and line, plus a line diff."""
    if a == b:
        return {"identical": True}
    n = min(len(a), len(b))
    i = next((k for k in range(n) if a[k] != b[k]), n)
    line = a[:i].count(b"\n") + 1
    return {"identical": False, "cmp": f"differ: byte {i + 1}, line {line}",
            "bytes_a": len(a), "bytes_b": len(b),
            "diff": text_diff(a.decode("utf-8", "replace"), b.decode("utf-8", "replace"))}


def norm_output(text: str, paths) -> str:
    """Remove what legitimately differs between two runs: timings, rates, paths, the argparse prog
    name ('fraudurl' vs 'fraudurl_standalone.py') and the usage-line wrapping it causes."""
    text = text.replace("\r\n", "\n")
    for p in sorted({p for p in paths if p}, key=len, reverse=True):
        text = text.replace(p.replace("\\", "\\\\"), "<PATH>")  # repr() form inside exception messages
        text = text.replace(p, "<PATH>").replace(p.replace("\\", "/"), "<PATH>")
    text = re.sub(r"(?<![\\/\w.])fraudurl_standalone\.py(?=[\s:\]])", "fraudurl", text)  # prog name, not paths
    text = re.sub(r"\(\d[\d,]*/s\)", "(<RATE>/s)", text)
    text = re.sub(r" in \d+(?:\.\d+)?s -> ", " in <T>s -> ", text)
    text = re.sub(r"usage:.*?(?=\n\n|\n\S|\Z)", lambda m: " ".join(m.group(0).split()), text, flags=re.S)
    return text


def listing(d) -> dict:
    out = {}
    for root, dirs, files in os.walk(d):
        for x in dirs:
            out[os.path.relpath(os.path.join(root, x), d) + os.sep] = "dir"
        for x in files:
            p = os.path.join(root, x)
            out[os.path.relpath(p, d)] = os.path.getsize(p)
    return out


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def feats_equal(a: dict, b: dict) -> bool:
    return a.keys() == b.keys() and all((a[k] != a[k] and b[k] != b[k]) or a[k] == b[k] for k in a)


@contextlib.contextmanager
def fixed_now(now):
    """cli._enrich_chunk does `from datetime import datetime, timezone` and calls datetime.now();
    swap in a datetime module whose now() is fixed, so both implementations see the same instant."""
    import datetime as real
    fake = types.ModuleType("datetime")
    fake.__dict__.update(real.__dict__)

    class FixedDateTime(real.datetime):
        @classmethod
        def now(cls, tz=None):
            return now if tz is not None else now.replace(tzinfo=None)

    fake.datetime = FixedDateTime
    sys.modules["datetime"] = fake
    try:
        yield
    finally:
        sys.modules["datetime"] = real


# ------------------------------------------------------------------ test inputs
def load_cache(name) -> dict:
    d = {}
    p = os.path.join(CACHE, name)
    if not os.path.exists(p):
        return d
    with open(p, encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
                d[rec["k"]] = rec["v"]
            except (ValueError, KeyError):
                continue
    return d


IDN = ["https://пример.рф/вход", "https://xn--e1afmkfd.xn--p1ai/", "https://аpple.com/login",
       "https://раураl.com/signin", "http://müller.de/über", "https://例え.テスト/", "https://😀.ws/",
       "https://xn--pple-43d.com/", "https://bücher.example/", "https://中国.cn/", "https://ドメイン.jp/",
       "https://παράδειγμα.δοκιμή/", "https://مثال.إختبار/", "https://faß.de/", "https://ǅ.com/",
       "https://gооgle.com/", "https://www.xn--80ak6aa92e.com/", "https://xn--mnchen-3ya.de/",
       "https://münchen.de./", "https://MÜNCHEN.DE/", "https://ｐａｙｐａｌ.com/", "http://①②③.com/",
       "https://Ⅷ.com/", "https://\u200bpaypal.com/", "https://paypal\u00ad.com/", "https://xn--.com/",
       "https://xn--zz.com/", "https://" + "ü" * 80 + ".de/", "https://ex\u0301ample.com/"]
IPS = ["http://0x7f.0x0.0x0.0x1/login", "http://0x7f000001/", "http://0177.0.0.01/", "http://017700000001/",
       "http://2130706433/paypal", "http://3232235777/", "http://127.1/", "http://1.2.3/",
       "http://256.256.256.256/", "http://192.168.1.1:8080/admin", "http://[::1]:8080/x",
       "http://[2001:db8::1]/wp-admin/", "http://[2001:db8::1]:443/", "http://[fe80::1%25eth0]/",
       "http://[::ffff:192.0.2.1]/", "http://[not-an-ip]/", "http://[::1", "http://::1/", "http://[::1]x/",
       "http://1.2.3.4.5/", "http://0/", "http://0.0.0.0/", "http://0x/", "http://0xg1.2.3.4/",
       "http://999999999999/", "http://1.2.3.04/", "http://08.1.1.1/", "10.0.0.1/login.php",
       "https://203.0.113.5.nip.io/", "http://[::1]:99999/", "http://[v1.fe]/"]
PORTS = ["http://example.com:8080/", "http://example.com:80/", "https://example.com:443/",
         "http://example.com:0/", "http://example.com:65535/", "http://example.com:65536/",
         "http://example.com:99999/", "http://example.com:abc/", "http://example.com:/path",
         "http://example.com::80/", "http://user:pass@evil.example/", "https://paypal.com@evil.tk/login",
         "https://www.paypal.com:443@198.51.100.7/", "https://a@b@c.com/", "http://@example.com/",
         "http://user@/", "https://login.microsoftonline.com.evil.ru@10.0.0.1:8443/",
         "ftp://anonymous:x@ftp.example.org:21/pub/"]
JUNK = ["not a url", "hello world", "12345", "....", "://", "http://", "https://", "-", "?", "#", "N/A",
        "null", "None", "TRUE", "3.14", "1e10", "<script>alert(1)</script>", "javascript:alert(1)",
        "mailto:a@b.com", "tel:+15550100", "data:text/html,<h1>x</h1>", "file:///C:/Windows/system32",
        "C:\\Users\\x\\file.txt", "\\\\server\\share\\f", "//", "///", "http:///x", "http://.", "http://..com",
        "http://-evil-.com", "http://evil_.com/", "http://ex ample.com", "💩", "日本語", "a" * 300,
        "user@example.com", "@", "http://@", "http://:80", "http://[]/", "http://[", "]", "http://%",
        "http://%%%", "http://%e2%82%ac.com", "https://%65xample.com/", "http://%zz.com/",
        "hxxp://evil.com", "HTTP://EXAMPLE.COM/UPPER", "http:\\\\evil.com\\login", "http:/evil.com/one",
        "//cdn.example.com/lib.js", "'https://single-quoted.example.com/'", "localhost",
        "http://localhost:3000/", "example", ".com", "a.b", "www.example.com", "google.com/",
        "https://trailing.dot.example.com./", "https://example.com/%70%61%79%70%61%6c",
        "https://example.com/?url=https://evil.com&next=/", "https://example.com/a//b",
        "https://example.com/#frag", "https://example.co.uk/", "https://sub.domain.example.gov.br/",
        "https://s3.amazonaws.com/bucket/index.html", "https://mysite.github.io/login.html",
        "https://evil.pages.dev/microsoft/office365/", "https://bit.ly/3xYz",
        "https://docs.google.com/forms/d/e/1FAIpQLS/viewform", "ftp://files.example.org/pub/setup.exe",
        "https://example.com/path with space", "  https://leading-space.example.com/  "]
FORMULA = ['=HYPERLINK("http://evil.com","click")', "=cmd|' /C calc'!A0", "+1-555-0100", "-2+3",
           "@SUM(A1:A2)", "=http://evil.com/", "+http://evil.com/", "-https://evil.com/login",
           "@https://evil.com/", "=1+1", "-", "+", "=", "@"]
EMPTYISH = ["", " ", "\t", '""', "''", "\u00a0", "\u3000"]
LONG = ["https://example.com/" + "a" * 25000,
        "http://login-" + "x" * 30000 + ".com/verify",
        "https://example.com/?" + "&".join(f"k{i}=v{i}" for i in range(4000)),
        "http://" + "1" * 5000 + "/",
        "https://" + ".".join(["a"] * 12000) + ".com/",
        "https://example.com/" + "%41" * 8000,
        "https://" + "paypal-" * 3000 + "secure.com/login"]
AWK = IDN + IPS + PORTS + JUNK + FORMULA + ["https://www.paypal.com/signin",
                                            "http://paypal.com.secure-login.verify-account.tk/webscr?cmd=_login",
                                            "paypal-login.com", "www.google.com"]


def synth(n, seed, hosts=()):
    """Deterministic, varied URLs (brands, login words, random names, IPs, platforms, ports, paths)."""
    rng = random.Random(seed)
    W = ("login secure account verify update shop news blog mail support home docs app cloud pay bank "
         "store portal media info auth billing service online my").split()
    B = "paypal google microsoft apple amazon netflix dhl chase wellsfargo facebook office365 binance".split()
    T = ("com net org xyz top tk ru co.uk de info io app shop buzz com.br gov edu cn online site fr in co "
         "us ml").split()
    P = ("github.io pages.dev web.app blogspot.com netlify.app vercel.app 000webhostapp.com herokuapp.com "
         "firebaseapp.com workers.dev").split()
    E = ["", "", ".php", ".html", ".htm", ".asp", ".exe", ".zip", ".js", "/"]
    hosts = list(hosts)
    out = []
    for _ in range(n):
        r = rng.random()
        if r < 0.03:
            out.append(rng.choice(AWK))
            continue
        scheme = rng.choice(["https://", "http://", "", "www.", "https://www."])
        k = rng.random()
        if hosts and k < 0.25:
            host = rng.choice(hosts)
            scheme = rng.choice(["https://", "http://", ""])
        elif k < 0.35:
            host = f"{rng.randint(1, 254)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        else:
            kind = rng.random()
            if kind < 0.3:
                name = rng.choice(W) + rng.choice(["", "-", "."]) + rng.choice(W)
            elif kind < 0.55:
                name = rng.choice(B) + rng.choice(["-", ".", ""]) + rng.choice(W) + rng.choice(["", str(rng.randint(1, 999))])
            elif kind < 0.8:
                name = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randint(4, 22)))
            else:
                name = rng.choice(W) + "-" + rng.choice(B) + "-" + rng.choice(W)
            host = name + "." + (rng.choice(P) if rng.random() < 0.12 else rng.choice(T))
        if rng.random() < 0.05:
            host += ":" + str(rng.choice([8080, 8443, 80, 443, 3000, 21]))
        path = "".join("/" + rng.choice(W + B) for _ in range(rng.randint(0, 4)))
        if path and rng.random() < 0.5:
            path += rng.choice(E)
        q = ""
        if rng.random() < 0.25:
            q = "?" + "&".join(f"{rng.choice(['id', 'next', 'url', 'token', 'session', 'redirect', 'q'])}={rng.randint(0, 10 ** 6)}"
                               for _ in range(rng.randint(1, 4)))
        out.append(scheme + host + path + q)
    return out


def csv_bytes(rows, delimiter=",", lineterminator="\r\n", encoding="utf-8", bom=b""):
    buf = io.StringIO()
    csv.writer(buf, delimiter=delimiter, lineterminator=lineterminator).writerows(rows)
    return bom + buf.getvalue().encode(encoding)


def lines_bytes(lines, nl="\n", encoding="utf-8"):
    return (nl.join(lines) + nl).encode(encoding)


def build_cases(mix, big45, big25):
    C = []

    def add(name, content, args=(), fname="in.csv", kind="normal", covers=""):
        C.append({"name": name, "fname": fname, "content": content, "args": list(args), "kind": kind,
                  "covers": covers})

    hdr = [["id", "url", "note"]] + [[str(i), u, f"row {i}"] for i, u in enumerate(mix)]
    add("header_comma", csv_bytes(hdr), covers="header, comma")
    add("noheader_comma", csv_bytes([[u, "label"] for u in mix]), covers="no header, comma")
    add("semicolon", csv_bytes([["id", "URL", "comment"]] + [[str(i), u, "c;d"] for i, u in enumerate(mix)], ";"),
        covers="semicolon")
    add("tab", csv_bytes([["link", "category"]] + [[u, "x"] for u in mix], "\t"), fname="in.tsv", covers="tab")
    add("pipe", csv_bytes([["name", "website", "x"]] + [[f"n{i}", u, "y"] for i, u in enumerate(mix)], "|"),
        covers="pipe")
    single = [u for u in mix if "\n" not in u and "\r" not in u]
    add("single_col_header", lines_bytes(["url"] + single), covers="single column with header")
    add("single_col_noheader", lines_bytes(single), covers="single column, no header")
    quoted = [["url", "comment"], ["https://example.com/a,b?c=1,2", "has, commas"],
              ["https://example.com/line1\nline2", "newline inside the URL cell"],
              ['https://ex.com/"quoted"', 'multi\nline, with "quotes"'],
              ["https://paypal.com.login-verify.tk/", "a,b,c\r\nd"], ["https://ok.example.org/", "\"\"\"\""],
              ["https://example.com/x\r\n", "crlf inside"]] + [[u, "q,\"x\"\ny"] for u in mix[:60]]
    add("quoted_multiline", csv_bytes(quoted), covers="quoted fields with commas and newlines")
    txt = []
    for i, u in enumerate(single):
        txt.append(u)
        if i % 17 == 0:
            txt.append("")
    txt += ["https://example.com/a,b,c", "https://example.com/?x=1,2,3"]
    add("plain_txt", lines_bytes(txt), fname="list.txt", covers="plain .txt list, blank lines, commas in URLs")
    uni = [["url", "name"]] + [[u, "Café Müller ñ €"] for u in IDN + mix[:80]]
    add("utf8_bom", csv_bytes(uni, bom=b"\xef\xbb\xbf"), covers="UTF-8 with BOM")
    add("utf8_nobom", csv_bytes(uni), covers="UTF-8 without BOM")
    add("utf16_le", csv_bytes(uni, encoding="utf-16"), covers="UTF-16 (LE, BOM)")
    add("utf16_be", csv_bytes(uni, encoding="utf-16-be", bom=b"\xfe\xff"), covers="UTF-16 (BE, BOM)")
    cp = [["Website", "Beschreibung"], ["http://müller.de/über", "Bäckerei „Grüße“ – 5 €"],
          ["https://café.fr/menü", "déjà vu ç ß ™"], ["https://señor.es/año", "niño ‚quote‘"],
          ["https://www.paypal.com/", "à la carte"]] + [[u, "é"] for u in mix[:100] if u.isascii()]
    add("cp1252", csv_bytes(cp, encoding="cp1252"), covers="cp1252 with accented characters")
    add("invalid_utf8_bytes", csv_bytes(hdr[:120]) + b"999,https://x.example.com/\x81\x8d\x9d\xff,bad bytes\r\n",
        covers="mostly UTF-8 with invalid bytes -> cp1252 fallback, undefined cp1252 bytes")
    add("crlf", csv_bytes(hdr[:200], lineterminator="\r\n"), covers="CRLF")
    add("lf", csv_bytes(hdr[:200], lineterminator="\n"), covers="LF")
    add("cr_only", csv_bytes(hdr[:200], lineterminator="\r"), covers="CR-only line endings")
    short = [["a", "url", "b"], ["1"], ["2", "https://x.com/"], ["3", "https://y.com/", "b", "extra1", "extra2"], [],
             ["4", "paypal.com.evil.tk", "b"], ["5", "https://z.com/login", "c,d", ""], ["6", "", ""],
             ["7", "https://w.com/", "b", "", "", "", "e"]]
    add("short_and_extra_rows", csv_bytes(short), covers="short rows and extra fields")
    add("url_column_right", csv_bytes([["Name", "Website", "Email"]] + [[f"n{i}", u, "a@b.com"] for i, u in enumerate(mix[:150])]),
        args=["--url-column", " website "], covers="--url-column (right name, case/space-insensitive)")
    add("url_column_wrong", csv_bytes(hdr[:50]), args=["--url-column", "Nope"], covers="--url-column (wrong name)")
    add("url_column_headerless", csv_bytes([[u, "x"] for u in ["https://first.example.com/"] + mix[:50]]),
        args=["--url-column", "https://first.example.com/"], covers="--url-column on a headerless file")
    add("header_only", b"id,url,note\r\n", covers="header only")
    add("empty", b"", covers="empty file")
    add("whitespace_only", b"\n  \n\t\n", covers="only blank lines")
    add("idn_unicode", csv_bytes([["url"]] + [[u] for u in IDN]), covers="IDN / unicode hosts")
    add("ip_forms", csv_bytes([["url"]] + [[u] for u in IPS]), covers="IP forms (hex, octal, integer, IPv6)")
    add("ports_userinfo", csv_bytes([["url"]] + [[u] for u in PORTS]), covers="ports, user@host")
    add("long_urls", csv_bytes([["url", "n"]] + [[u, str(len(u))] for u in LONG] + [[u, "x"] for u in mix[:20]]),
        covers="very long URLs (>20k chars)")
    add("junk", csv_bytes([["url"]] + [[u] for u in JUNK]), covers="junk values")
    add("empty_cells", csv_bytes([["id", "url"]] + [[str(i), u] for i, u in enumerate(EMPTYISH + mix[:10] + EMPTYISH)]),
        covers="empty / whitespace cells")
    add("formula_values", csv_bytes([["url", "other"]] + [[u, v] for u, v in zip(FORMULA, reversed(FORMULA))]),
        covers="values starting with = + - @")
    add("nul_bytes", b"url\r\nhttps://ex\x00ample.com/\r\nhttp://paypal.com\x00.evil.tk/\r\nhttps://ok.com/\r\n",
        covers="NUL characters")
    add("email_and_url_columns", csv_bytes([["email", "homepage", "notes"]] + [["x@y.com", u, "n"] for u in mix[:80]]),
        covers="column choice: e-mail column next to URL column")
    add("no_url_header", csv_bytes([["col1", "col2"]] + [["abc", u] for u in mix[:80]]), covers="column choice by content")
    add("duplicate_url_headers", csv_bytes([["url", "URL", "link"]] + [["notaurl", u, "x"] for u in mix[:40]]),
        covers="duplicate URL-like headers")
    add("excel_sep_hint", b"sep=;\r\nid;url\r\n" + b"".join(f"{i};{u}\r\n".encode() for i, u in enumerate(single[:40])),
        covers="Excel 'sep=;' first line")
    add("unclosed_quote", b'url,note\r\nhttps://a.com/,"unterminated\r\nhttps://b.com/,x\r\n', covers="unclosed quote")
    add("base_rate_0.01", csv_bytes(hdr), args=["--base-rate", "0.01"], covers="--base-rate 0.01")
    add("base_rate_0.5", csv_bytes(hdr), args=["--base-rate", "0.5"], covers="--base-rate 0.5")
    add("workers_1", csv_bytes(hdr), args=["--workers", "1"], covers="--workers 1")
    add("workers_4", csv_bytes(hdr), args=["--workers", "4"], covers="--workers 4")
    add("workers_0", csv_bytes(hdr[:100]), args=["--workers", "0"], covers="--workers 0 (-> default)")
    add("big_45k_default_workers", csv_bytes([["id", "url", "note"]] + [[str(i), u, "b"] for i, u in enumerate(big45)]),
        covers=">20,000 rows (2 chunk boundaries), default workers")
    add("big_25k_workers1_base_rate", csv_bytes([["id", "url", "note"]] + [[str(i), u, "b"] for i, u in enumerate(big25)]),
        args=["--workers", "1", "--base-rate", "0.01"], covers=">20,000 rows, --workers 1, --base-rate 0.01")
    add("refuse_out_equals_in", csv_bytes(hdr[:20]), kind="out_equals_in", covers="output path == input")
    add("refuse_out_equals_in_case", csv_bytes(hdr[:20]), kind="out_equals_in_case",
        covers="output path == input (different letter case)")
    for v in ("0", "1", "-0.5", "abc", "nan", "inf"):
        add(f"refuse_base_rate_{v}", csv_bytes(hdr[:20]), args=["--base-rate", v], covers=f"invalid --base-rate {v}")
    add("version", None, args=["--version"], kind="no_input", covers="--version")
    add("help", None, args=["--help"], kind="no_input", covers="--help")
    add("no_args", None, kind="no_input", covers="no arguments")
    add("missing_input", None, kind="missing_input", covers="input file does not exist")
    add("output_dir_missing", csv_bytes(hdr[:20]), kind="output_dir_missing", covers="-o into a folder that does not exist")
    add("default_output_name", csv_bytes(hdr[:100]), kind="default_output", covers="no -o (default output name)")
    return C


# ------------------------------------------------------------------ step 1: CLI equivalence
def step1(mix, big45, big25, sys_py, cross):
    root = os.path.join(SCRATCH, "cli")
    cases = build_cases(mix, big45, big25)
    impls = {"pkg": ([PY, "-m", "fraudurl"], child_env(ROOT)), "sa": ([PY, SA], child_env())}
    if cross:
        impls["sa_sys"] = ([sys_py, SA], child_env())
    out = {"n_cases": len(cases), "cases": [], "all_equal": True, "cross_all_equal": True if cross else None}
    for c in cases:
        d = os.path.join(root, c["name"])
        os.makedirs(d, exist_ok=True)
        inp = os.path.join(d, c["fname"])
        if c["content"] is not None and c["kind"] != "default_output":
            write(inp, c["content"])
        in_sha = sha(c["content"]) if c["content"] is not None else None
        res = {}
        for impl, (base, env) in impls.items():
            argv, outp = [], os.path.join(d, f"out_{impl}.csv")
            this_in = inp
            if c["kind"] == "default_output":
                this_in = os.path.join(d, impl, c["fname"])
                write(this_in, c["content"])
                outp = os.path.splitext(this_in)[0] + ".fraudurl.csv"
            if c["kind"] == "missing_input":
                this_in = os.path.join(d, "does_not_exist.csv")
            if c["kind"] != "no_input":
                argv.append(this_in)
            if c["kind"] == "out_equals_in":
                argv += ["-o", this_in]
                outp = None
            elif c["kind"] == "out_equals_in_case":
                argv += ["-o", os.path.join(d, c["fname"].upper())]
                outp = None
            elif c["kind"] == "output_dir_missing":
                outp = os.path.join(d, "no_such_folder", f"out_{impl}.csv")
                argv += ["-o", outp]
            elif c["kind"] not in ("no_input", "default_output"):
                argv += ["-o", outp]
            if c["kind"] == "no_input":
                outp = None
            if outp and os.path.exists(outp):
                os.remove(outp)
            r = run_proc(base + argv + c["args"], cwd=d, env=env)
            paths = [this_in, outp or "", d, os.path.join(d, c["fname"].upper())]
            r["stdout_n"], r["stderr_n"] = norm_output(r["stdout"], paths), norm_output(r["stderr"], paths)
            r["out_exists"] = bool(outp and os.path.exists(outp))
            r["out_bytes"] = read(outp) if r["out_exists"] else None
            if c["content"] is not None and os.path.exists(this_in) and sha(read(this_in)) != in_sha:
                r["input_modified"] = True
            res[impl] = r
        row = {"case": c["name"], "covers": c["covers"], "args": c["args"], "kind": c["kind"],
               "input_bytes": len(c["content"]) if c["content"] is not None else None}
        a = res["pkg"]
        row["exit_code"] = a["rc"]
        row["output_rows"] = (a["out_bytes"].count(b"\n") if a["out_bytes"] else None)
        row["output_sha256"] = sha(a["out_bytes"])[:16] if a["out_bytes"] else None
        row["stderr_tail_pkg"] = a["stderr"][-300:]
        for other in [k for k in impls if k != "pkg"]:
            b = res[other]
            chk = {"exit_code_equal": a["rc"] == b["rc"], "output_exists_equal": a["out_exists"] == b["out_exists"],
                   "output_bytes_equal": a["out_bytes"] == b["out_bytes"],
                   "stdout_equal_normalised": a["stdout_n"] == b["stdout_n"],
                   "stderr_equal_normalised": a["stderr_n"] == b["stderr_n"],
                   "input_unmodified": not a.get("input_modified") and not b.get("input_modified")}
            if a["out_bytes"] != b["out_bytes"] and a["out_bytes"] is not None and b["out_bytes"] is not None:
                chk["cmp"] = cmp_bytes(a["out_bytes"], b["out_bytes"])
            if a["stderr_n"] != b["stderr_n"]:
                chk["stderr_diff"] = text_diff(a["stderr_n"], b["stderr_n"], "package", other)
                la = [x for x in a["stderr_n"].splitlines() if x.strip()]
                lb = [x for x in b["stderr_n"].splitlines() if x.strip()]
                chk["traceback_frames_only"] = bool(
                    "Traceback (most recent call last)" in a["stderr_n"] and "Traceback (most recent call last)" in b["stderr_n"]
                    and la and lb and la[-1] == lb[-1])
            if a["stdout_n"] != b["stdout_n"]:
                chk["stdout_diff"] = text_diff(a["stdout_n"], b["stdout_n"], "package", other)
            chk["exit_codes"] = [a["rc"], b["rc"]]
            row[other] = chk
            hard = chk["exit_code_equal"] and chk["output_exists_equal"] and chk["output_bytes_equal"] and chk["input_unmodified"]
            soft = chk["stdout_equal_normalised"] and chk["stderr_equal_normalised"]
            if other == "sa":
                if not (hard and soft):
                    out["all_equal"] = False
                    what = []
                    if not hard:
                        what.append("output/exit-code mismatch")
                    if not soft:
                        what.append("stderr differs only in traceback frames (file paths / line numbers): both crash "
                                    "with the same unhandled exception" if chk.get("traceback_frames_only")
                                    else "stdout/stderr differ after normalisation")
                    problem(f"step 1 CLI case '{c['name']}' ({c['covers']})",
                            "the standalone behaves identically to `python -m fraudurl`",
                            "; ".join(what),
                            json.dumps({k: v for k, v in chk.items() if k in ("exit_codes", "cmp", "stderr_diff", "stdout_diff")},
                                       ensure_ascii=False)[:3000],
                            ("in fraudurl/cli.py run(): wrap the input/output open() calls in try/except OSError and "
                             "raise SystemExit(f'cannot open {path}: {e.strerror}') so both editions print the same "
                             "one-line message instead of a traceback; then rebuild")
                            if chk.get("traceback_frames_only") else "see evidence",
                            "major" if not hard else "minor")
            else:
                if not hard:
                    out["cross_all_equal"] = False
                    problem(f"step 1 CLI case '{c['name']}' run by {sys_py}",
                            "same results on every Python 3.9+ (README: byte-identical results)",
                            "standalone under the second interpreter gives different output/exit code than the package under the venv",
                            json.dumps({k: v for k, v in chk.items() if k in ("exit_codes", "cmp")}, ensure_ascii=False)[:3000],
                            "see evidence", "major")
        if c["name"] == "unclosed_quote" and a["out_bytes"]:
            got = list(csv.reader(io.StringIO(a["out_bytes"].decode("utf-8-sig"), newline="")))
            out["observation_unclosed_quote"] = {
                "input": c["content"].decode(), "url_rows_in_input": 2, "data_rows_in_output": len(got) - 1,
                "stderr": a["stderr"].strip()[-200:],
                "note": "same in both editions: an unterminated quote swallows the rest of the file into one cell "
                        "(csv strict=False), so later URLs are silently not scored"}
        out["cases"].append(row)
        flag ="OK " if row["sa"]["exit_code_equal"] and row["sa"]["output_bytes_equal"] and row["sa"]["stderr_equal_normalised"] and row["sa"]["stdout_equal_normalised"] else "DIFF"
        xflag = ""
        if cross:
            xflag = " | sys-python: " + ("OK" if row["sa_sys"]["output_bytes_equal"] and row["sa_sys"]["exit_code_equal"] else "DIFF")
        print(f"  [{flag}] {c['name']:<34} rc={a['rc']} rows={row['output_rows']}{xflag}", flush=True)
    return out


# ------------------------------------------------------------------ step 2: enriched path, in-process
class FakeEnricher:
    """Stands in for enrich.Enricher: answers from the cached records only (no network)."""

    def __init__(self, dns, rdap):
        self.dns, self.rdap = dns, rdap

    def run(self, items, progress=None):
        hosts, regs = {}, set()
        for host, reg, is_ip, private in items:
            if is_ip or not host:
                continue
            hosts[host] = reg
            if reg and not private:
                regs.add(reg)
        return ({h: self.dns[h] for h in hosts if h in self.dns}, {r: self.rdap[r] for r in regs if r in self.rdap})


def step2(fus):
    from fraudurl import cli as pcli, enrich as penrich
    from fraudurl.lexical import ParsedURL
    dns, rdap = load_cache("dns.jsonl"), load_cache("rdap.jsonl")
    out = {"dns_records": len(dns), "rdap_records": len(rdap), "now": NOW.isoformat()}
    if len(dns) < 1000:
        problem("step 2", ">= 1,000 cached URLs", f"only {len(dns)} DNS records in {CACHE}", "", "", "major")
    tpl = ["https://{h}/", "http://{h}/login.php?id=1", "{h}/account/verify", "https://{h}/wp-admin/update.html",
           "https://{h}:8443/secure/signin?next=/home"]
    urls = [tpl[i % len(tpl)].format(h=h) for i, h in enumerate(sorted(dns))]
    urls += [f"https://login.{r}/verify" for r in sorted(rdap)]  # RDAP hit, DNS miss
    n_cached = len(urls)
    urls += AWK + ["", None, "   "]
    # feature dicts built by BOTH implementations' dns_features / rdap_features (fixed now)
    full, feat_mismatch = [], []
    n_dns_hit = n_rdap_hit = 0
    for u in urls:
        try:
            p = ParsedURL(str(u)) if u else None
        except Exception:  # noqa: BLE001
            p = None
        d = dns.get(p.host) if p else None
        r = rdap.get(p.reg) if p else None
        n_dns_hit += d is not None
        n_rdap_hit += r is not None
        fa = {**penrich.dns_features(d), **penrich.rdap_features(r, NOW)}
        fb = {**fus.dns_features(d), **fus.rdap_features(r, NOW)}
        if not feats_equal(fa, fb):
            feat_mismatch.append({"url": u, "package": repr(fa), "standalone": repr(fb)})
        full.append(fa)
    out.update(n_urls=len(urls), n_urls_from_cache=n_cached, n_with_dns_record=n_dns_hit,
               n_with_rdap_record=n_rdap_hit, feature_dict_mismatches=len(feat_mismatch))
    if feat_mismatch:
        problem("step 2 dns_features/rdap_features", "identical feature extraction",
                f"{len(feat_mismatch)} feature dicts differ", json.dumps(feat_mismatch[:3])[:3000], "", "major")
    # mixed variants: full, DNS only, RDAP only, empty
    mixed = []
    for i, f in enumerate(full):
        v = i % 4
        mixed.append(f if v == 0 else {k: x for k, x in f.items() if k.startswith("dns_")} if v == 1
                     else {k: x for k, x in f.items() if not k.startswith("dns_")} if v == 2 else {})
    comparisons = []
    for label, feats in (("full dns+rdap feats", full), ("mixed full/dns-only/rdap-only/empty feats", mixed),
                         ("extra_feats=None", None)):
        for br in (None, 0.01, 0.5):
            pcli._init_worker(True, br)
            fus._init_worker(True, br)
            ra, rb = pcli.score_rows(urls, feats), fus.score_rows(urls, feats)
            ca = cb = []
            if br is None:  # _chunk_job = score_rows + registrable_domain; once per feature set is enough
                ca, cb = pcli._chunk_job((urls, feats)), fus._chunk_job((urls, feats))
            bad = [{"url": urls[i], "package": ra[i], "standalone": rb[i]} for i in range(len(urls)) if ra[i] != rb[i]]
            badc = [i for i in range(len(ca)) if ca[i] != cb[i]]
            verdicts = {}
            for x in ra:
                verdicts[x["fraud_verdict"]] = verdicts.get(x["fraud_verdict"], 0) + 1
            comparisons.append({"extra_feats": label, "base_rate": br, "rows": len(urls), "score_rows_mismatches": len(bad),
                                "chunk_job_mismatches": len(badc), "verdicts": verdicts})
            if bad or badc:
                problem(f"step 2 score_rows enrich=True, {label}, base_rate={br}", "identical result dicts",
                        f"{len(bad)} score_rows and {len(badc)} _chunk_job results differ",
                        json.dumps(bad[:3], ensure_ascii=False)[:3000], "", "major")
    # safe-mode init as well
    for br in (None, 0.01):
        pcli._init_worker(False, br)
        fus._init_worker(False, br)
        ra, rb = pcli.score_rows(urls, full), fus.score_rows(urls, full)
        n = sum(ra[i] != rb[i] for i in range(len(urls)))
        comparisons.append({"extra_feats": "full feats but enrich=False", "base_rate": br, "rows": len(urls),
                            "score_rows_mismatches": n})
        if n:
            problem(f"step 2 score_rows enrich=False base_rate={br}", "identical", f"{n} rows differ", "", "", "major")
    out["score_rows_comparisons"] = comparisons
    # non-vacuity: how many rows did the enrichment model actually change?
    pcli._init_worker(True, None)
    enr, safe = pcli.score_rows(urls, full), pcli.score_rows(urls, None)
    out["rows_where_enrichment_changed_probability"] = sum(
        a.get("fraud_probability") != b.get("fraud_probability") for a, b in zip(enr, safe))
    out["rows_where_enrichment_changed_verdict"] = sum(a["fraud_verdict"] != b["fraud_verdict"] for a, b in zip(enr, safe))

    # _enrich_chunk (platform / IP / dead-domain logic) with a fake enricher fed from the cache
    fake = FakeEnricher(dns, rdap)
    with fixed_now(NOW):
        fa, sa_ = pcli._enrich_chunk(fake, urls)
        fb, sb = fus._enrich_chunk(fake, urls)
    n_bad = sum(not feats_equal(x, y) for x, y in zip(fa, fb)) + sum(x != y for x, y in zip(sa_, sb))
    status_kinds = {}
    for s in sa_:
        k = re.sub(r"\(.*", "", s).strip()[:60]
        status_kinds[k] = status_kinds.get(k, 0) + 1
    out["enrich_chunk"] = {"rows": len(urls), "mismatches": n_bad, "rows_with_enriched_feats": sum(bool(f) for f in fa),
                           "status_counts": dict(sorted(status_kinds.items(), key=lambda kv: -kv[1])[:15])}
    if n_bad:
        problem("step 2 _enrich_chunk", "identical", f"{n_bad} feats/status differ", "", "", "major")
    pcli._init_worker(True, None)
    fus._init_worker(True, None)
    ra, rb = pcli.score_rows(urls, fa), fus.score_rows(urls, fb)
    n = sum(x != y for x, y in zip(ra, rb))
    out["enrich_chunk"]["score_rows_mismatches"] = n
    if n:
        problem("step 2 score_rows on _enrich_chunk feats", "identical", f"{n} rows differ", "", "", "major")

    # end-to-end run(enrich=True, workers=1) of both, against private copies of the real cache,
    # with sockets blocked in this process; every lookup must be a cache hit (cache files unchanged)
    e2e_dir = os.path.join(SCRATCH, "enrich_e2e")
    os.makedirs(e2e_dir, exist_ok=True)
    keep = []
    for u in urls:
        if u is None:
            continue
        try:
            p = ParsedURL(str(u)) if u and not any(c.isspace() for c in str(u).strip()) else None
        except Exception:  # noqa: BLE001
            p = None
        if p is None or not p.host or not ("." in p.host or p.ip) or p.ip or pcli._platform(p):
            keep.append(u)  # skipped before any lookup
        elif p.host in dns and (p.private_suffix or not p.reg or p.reg in rdap):
            keep.append(u)  # every lookup is a cache hit
    inp = os.path.join(e2e_dir, "enrich_in.csv")
    write(inp, csv_bytes([["id", "url"]] + [[str(i), u] for i, u in enumerate(keep)]))
    e2e = {"rows": len(keep)}
    for br in (None, 0.01):
        outs = {}
        for impl, mod in (("package", pcli), ("standalone", fus)):
            cdir = os.path.join(e2e_dir, f"cache_{impl}_{br}")
            os.makedirs(cdir, exist_ok=True)
            t_now = time.time()
            for name in ("dns.jsonl", "rdap.jsonl"):  # refresh 't' so the TTL never expires on a rerun
                with open(os.path.join(CACHE, name), encoding="utf-8") as fi, \
                        open(os.path.join(cdir, name), "w", encoding="utf-8", newline="\n") as fo:
                    for line in fi:
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            continue
                        rec["t"] = t_now
                        fo.write(json.dumps(rec, separators=(",", ":")) + "\n")
            bs = os.path.join(cdir, "rdap_bootstrap_dns.json")
            shutil.copyfile(os.path.join(CACHE, "rdap_bootstrap_dns.json"), bs)
            os.utime(bs, None)  # fresh -> never re-downloaded
            before = {n: sha(read(os.path.join(cdir, n))) for n in os.listdir(cdir)}
            ev0 = len(NET_EVENTS)
            outp = os.path.join(e2e_dir, f"out_{impl}_{br}.csv")
            with fixed_now(NOW):
                summ = mod.run(inp, outp, enrich=True, workers=1, base_rate=br, cache_dir=cdir, quiet=True)
            after = {n: sha(read(os.path.join(cdir, n))) for n in os.listdir(cdir)}
            outs[impl] = read(outp)
            e2e[f"{impl}_base_rate_{br}"] = {"summary_verdicts": summ["verdicts"], "cache_unchanged": before == after,
                                             "blocked_network_events": NET_EVENTS[ev0:]}
            if before != after or NET_EVENTS[ev0:]:
                problem(f"step 2 e2e run(enrich=True) {impl}", "offline with a warm cache",
                        "cache changed or a network call was attempted",
                        json.dumps({"before": before, "after": after, "events": NET_EVENTS[ev0:]}), "", "major")
        c = cmp_bytes(outs["package"], outs["standalone"])
        rows = list(csv.DictReader(io.StringIO(outs["package"].decode("utf-8-sig"))))
        modes = {}
        for r in rows:
            modes[r["analysis_mode"]] = modes.get(r["analysis_mode"], 0) + 1
        e2e[f"base_rate_{br}"] = {"output_bytes_identical": c["identical"], "analysis_modes": modes,
                                  "output_sha256": sha(outs["package"])[:16]}
        if not c["identical"]:
            problem(f"step 2 e2e run(enrich=True, base_rate={br})", "identical output bytes", c.get("cmp", ""),
                    c.get("diff", "")[:3000], "", "major")
    out["e2e_run_enrich"] = e2e
    out["network_events_total"] = len(NET_EVENTS)
    return out


# ------------------------------------------------------------------ step 3: self-containment and safety
WRAPPER = r'''
import json, os, runpy, socket, sys
script, csv_in, csv_out, report = sys.argv[1:5]
events, writes, fs_events, patched_calls = [], [], [], []
NET = ("socket.", "urllib.Request", "http.client.", "ftplib.", "smtplib.", "poplib.", "imaplib.", "nntplib.",
       "telnetlib.", "webbrowser.")
PROC = ("subprocess.Popen", "os.system", "os.startfile", "os.posix_spawn", "os.spawn", "os.exec", "os.fork",
        "_winapi.CreateProcess", "ctypes.dlopen")
FS = ("os.mkdir", "os.rename", "os.replace", "os.remove", "os.rmdir", "os.truncate", "os.chmod", "os.utime",
      "os.link", "os.symlink", "shutil.")
WFLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
def hook(ev, args):
    if ev == "open":
        path, mode, flags = (tuple(args) + (None, None, None))[:3]
        if (isinstance(mode, str) and any(c in mode for c in "wax+")) or (isinstance(flags, int) and flags & WFLAGS):
            writes.append(os.path.abspath(path) if isinstance(path, (str, bytes)) else repr(path))
    elif ev.startswith(NET) and ev != "socket.gethostname":
        events.append(ev)
        raise ConnectionRefusedError("network blocked by wrapper: " + ev)
    elif ev.startswith(PROC):
        events.append(ev)
        raise PermissionError("process creation blocked by wrapper: " + ev)
    elif ev.startswith(FS):
        fs_events.append([ev, repr(args)[:200]])
def blocked(*a, **k):
    patched_calls.append("called")
    raise ConnectionRefusedError("network blocked by wrapper (monkeypatch)")
class BlockedSocket(socket.socket):
    def __init__(self, *a, **k):
        blocked()
socket.socket = BlockedSocket
socket.create_connection = blocked
socket.getaddrinfo = blocked
socket.gethostbyname = blocked
sys.addaudithook(hook)
sys.argv = [script, csv_in, "-o", csv_out, "--workers", "1"]
code = 0
try:
    runpy.run_path(script, run_name="__main__")
except SystemExit as e:
    code = e.code if isinstance(e.code, int) else (0 if e.code is None else str(e.code))
except BaseException as e:
    code = "exception: %s: %s" % (type(e).__name__, e)
run_events, run_writes, run_fs, run_patched = list(events), list(writes), list(fs_events), list(patched_calls)
fraud_mods = sorted(m for m in sys.modules if m == "fraudurl" or m.startswith("fraudurl."))
controls = {}
import urllib.request, _socket
for name, fn in [("socket.socket()", lambda: socket.socket()),
                 ("_socket.socket() (C level)", lambda: _socket.socket()),
                 ("socket.create_connection", lambda: socket.create_connection(("127.0.0.1", 9), timeout=1)),
                 ("socket.getaddrinfo", lambda: socket.getaddrinfo("localhost", 80)),
                 ("urllib.request.urlopen", lambda: urllib.request.urlopen("http://127.0.0.1:9/", timeout=1))]:
    try:
        fn()
        controls[name] = "NOT BLOCKED"
    except Exception as e:
        controls[name] = "blocked (%s)" % type(e).__name__
with open(report, "w", encoding="utf-8") as fh:
    json.dump({"python": sys.version, "exit_code": code, "network_or_process_events_during_run": run_events,
               "monkeypatched_socket_calls_during_run": len(run_patched), "files_opened_for_writing": run_writes,
               "fs_events": run_fs, "fraudurl_modules_imported": fraud_mods, "positive_controls": controls}, fh, indent=1)
'''


def step3(mix, sys_py):
    out = {}
    iso = os.path.join(SCRATCH, "isolated")
    if os.path.exists(iso):
        shutil.rmtree(iso)
    os.makedirs(iso)
    shutil.copyfile(SA, os.path.join(iso, "fraudurl_standalone.py"))
    small = csv_bytes([["id", "url", "note"]] + [[str(i), u, "s"] for i, u in enumerate(mix)])
    write(os.path.join(iso, "small.csv"), small)
    # reference: the package, venv Python, from the project root
    ref_in = os.path.join(SCRATCH, "small_ref.csv")
    write(ref_in, small)
    ref_out = os.path.join(SCRATCH, "small_ref.out.csv")
    r = run_proc([PY, "-m", "fraudurl", ref_in, "-o", ref_out], cwd=ROOT, env=child_env(ROOT))
    ref = read(ref_out)
    out["reference"] = {"rc": r["rc"], "rows": ref.count(b"\n"), "sha256": sha(ref)[:16]}
    out["isolated_dir_initial_listing"] = listing(iso)
    runs = []
    variants = [("sys-python, default workers (4)", [sys_py, "fraudurl_standalone.py", "small.csv", "-o", "o1.csv"], "o1.csv"),
                ("sys-python -I (isolated mode), --workers 1", [sys_py, "-I", "fraudurl_standalone.py", "small.csv", "-o", "o2.csv", "--workers", "1"], "o2.csv"),
                ("sys-python -I -S (no site-packages), default workers", [sys_py, "-I", "-S", "fraudurl_standalone.py", "small.csv", "-o", "o3.csv"], "o3.csv")]
    env = child_env()
    env.pop("PYTHONUTF8", None)  # as a stranger would run it
    env.pop("PYTHONIOENCODING", None)
    for label, cmd, o in variants:
        before = listing(iso)
        rr = run_proc(cmd, cwd=iso, env=env)
        after = listing(iso)
        new = sorted(set(after) - set(before))
        got = read(os.path.join(iso, o)) if os.path.exists(os.path.join(iso, o)) else b""
        c = cmp_bytes(ref, got)
        runs.append({"run": label, "rc": rr["rc"], "stderr_tail": rr["stderr"][-200:], "new_files": new,
                     "identical_to_package": c["identical"]})
        if rr["rc"] != 0 or not c["identical"] or new != [o]:
            problem(f"step 3 {label}", "self-contained; same bytes as the package; writes only the output",
                    f"rc={rr['rc']}, identical={c['identical']}, new files={new}",
                    (c.get("cmp", "") + "\n" + c.get("diff", "") + "\n" + rr["stderr"][-1500:])[:3000], "", "critical")
    # socket-blocked, in-process run via runpy.run_path, safe mode, --workers 1
    wrapper = os.path.join(SCRATCH, "netblock_wrapper.py")
    write(wrapper, WRAPPER.encode("utf-8"))
    for label, py in (("sys-python -I -B", [sys_py, "-I", "-B"]), ("venv python -I -B", [PY, "-I", "-B"])):
        o = f"netblock_{'sys' if py[0] == sys_py else 'venv'}.csv"
        rep = os.path.join(SCRATCH, o + ".report.json")
        before = listing(iso)
        rr = run_proc(py + [wrapper, "fraudurl_standalone.py", "small.csv", o, rep], cwd=iso, env=env)
        after = listing(iso)
        new = sorted(set(after) - set(before))
        report = json.loads(read(rep)) if os.path.exists(rep) else {"error": rr["stderr"][-2000:]}
        got = read(os.path.join(iso, o)) if os.path.exists(os.path.join(iso, o)) else b""
        c = cmp_bytes(ref, got)
        expected_write = [os.path.abspath(os.path.join(iso, o))]
        ok = (report.get("exit_code") == 0 and c["identical"] and new == [o]
              and not report.get("network_or_process_events_during_run")
              and report.get("monkeypatched_socket_calls_during_run") == 0
              and [os.path.normcase(x) for x in report.get("files_opened_for_writing", [])] == [os.path.normcase(x) for x in expected_write]
              and not report.get("fs_events") and not report.get("fraudurl_modules_imported")
              and all(v.startswith("blocked") for v in report.get("positive_controls", {}).values()))
        runs.append({"run": f"network-blocked wrapper ({label}), runpy.run_path, --workers 1", "wrapper_rc": rr["rc"],
                     "report": report, "new_files": new, "identical_to_package": c["identical"], "passed": ok})
        if not ok:
            problem(f"step 3 network-blocked run ({label})", "no network, writes only the output, same bytes",
                    "check failed", json.dumps({"report": report, "new": new, "cmp": c.get("cmp")})[:3000], "", "critical")
    out["runs"] = runs
    # CPython builds can lack optional C modules (e.g. pyenv without xz / OpenSSL headers). Simulate that by
    # poisoning sys.modules and run SAFE mode (--workers 1) of both implementations.
    opt = {}
    for mod in ("_lzma", "_ssl"):
        opt[mod] = {}
        for impl in ("standalone", "package"):
            o = f"without{mod}_{impl}.csv"
            if impl == "standalone":
                launch = ("sys.argv=['fraudurl_standalone.py','small.csv','-o',%r,'--workers','1'];"
                          "runpy.run_path('fraudurl_standalone.py',run_name='__main__')") % o
                e = child_env()
            else:
                launch = ("sys.argv=['fraudurl','small.csv','-o',%r,'--workers','1'];"
                          "runpy.run_module('fraudurl',run_name='__main__',alter_sys=True)") % o
                e = child_env(ROOT)
            rr = run_proc([PY, "-B", "-c", f"import sys,runpy;sys.modules[{mod!r}]=None;" + launch], cwd=iso, env=e)
            got = read(os.path.join(iso, o)) if os.path.exists(os.path.join(iso, o)) else None
            last = [ln for ln in rr["stderr"].replace("\r", "\n").splitlines() if ln.strip()]
            opt[mod][impl] = {"rc": rr["rc"], "output_identical_to_reference": got == ref if got is not None else None,
                              "last_stderr_line": last[-1] if last else ""}
            if os.path.exists(os.path.join(iso, o)):
                os.remove(os.path.join(iso, o))
        if opt[mod]["package"]["rc"] == 0 and opt[mod]["standalone"]["rc"] != 0:
            problem(f"step 3 Python build without {mod}",
                    "standalone 'needs only Python 3.9+ (standard library)' / behaves like the package",
                    f"safe mode of the standalone fails when the optional C module {mod} is missing; the package's safe mode works",
                    json.dumps(opt[mod]),
                    ("fraudurl/enrich.py: move `import ssl` into _doh_conn (its only use, ssl.create_default_context) "
                     "and rebuild; http.client and urllib.request already import without _ssl")
                    if mod == "_ssl" else
                    ("experiments/build_single_file.py: embed the data with zlib instead of lzma (+53,176 bytes) or catch "
                     "ImportError in _embedded_text and exit with a clear message; in cli.run load the models before "
                     "opening the output file so a failure does not leave a header-only CSV"), "minor")
    out["optional_c_modules_missing"] = opt
    final = listing(iso)
    out["isolated_dir_final_listing"] = final
    out["fraudurl_cache_created"] = any(".fraudurl_cache" in k for k in final)
    out["pycache_created"] = any("__pycache__" in k for k in final)
    return out


# ------------------------------------------------------------------ step 4: Python 3.9 (static)
API_PATTERNS = {
    "zip(strict=) [3.10]": r"\bzip\([^\n]*\bstrict\s*=",
    "int.bit_count() [3.10]": r"\.bit_count\(",
    "itertools.pairwise [3.10]": r"\bpairwise\(",
    "bisect/insort key= [3.10]": r"\b(bisect\w*|insort\w*)\([^\n]*\bkey\s*=",
    "dataclass slots=/kw_only= [3.10]": r"\b(slots|kw_only)\s*=\s*True",
    "aiter()/anext() [3.10]": r"\b(aiter|anext)\(",
    "sys.orig_argv / sys.stdlib_module_names [3.10]": r"sys\.(orig_argv|stdlib_module_names)",
    "open(encoding='locale') / EncodingWarning [3.10]": r"encoding\s*=\s*[\"']locale|EncodingWarning",
    "inspect.get_annotations / glob root_dir= [3.10]": r"get_annotations\(|\broot_dir\s*=",
    "typing names added in 3.10+": r"\b(TypeAlias|ParamSpec|Concatenate|TypeGuard|LiteralString|assert_never|reveal_type|NotRequired|TypeVarTuple|Unpack|override)\b",
    "datetime.UTC [3.11]": r"\bdatetime\.UTC\b|from datetime import[^\n]*\bUTC\b",
    "tomllib / StrEnum / TaskGroup [3.11]": r"\b(tomllib|StrEnum|TaskGroup)\b",
    "ExceptionGroup / except* [3.11]": r"\bExceptionGroup\b|\bexcept\s*\*",
    "contextlib.chdir / hashlib.file_digest [3.11]": r"contextlib\.chdir|file_digest\(",
    "math.cbrt/exp2 [3.11], sumprod [3.12], fma [3.13]": r"math\.(cbrt|exp2|sumprod|fma)\(",
    "itertools.batched / os.path.splitroot / Path.walk [3.12]": r"\bbatched\(|splitroot\(|\.walk\(",
    "csv.QUOTE_STRINGS/QUOTE_NOTNULL [3.12]": r"QUOTE_(STRINGS|NOTNULL)",
    "copy.replace [3.13]": r"copy\.replace\(",
    "sys.set_int_max_str_digits [3.11/3.10.7/3.9.14]": r"int_max_str_digits",
    "str.removeprefix/removesuffix [3.9 - allowed]": r"\.remove(prefix|suffix)\(",
    "functools.cache [3.9 - allowed]": r"\bfunctools\.cache\b|from functools import[^\n]*\bcache\b",
}
_TYPE_NAMES = {"int", "str", "float", "bool", "bytes", "list", "dict", "tuple", "set", "frozenset", "type",
               "object", "complex", "bytearray"}


class _RuntimeUnions(ast.NodeVisitor):
    """`X | Y` between types OUTSIDE annotations (evaluated at run time -> needs 3.10)."""

    def __init__(self):
        self.hits = []

    def visit_arg(self, node):
        pass

    def visit_FunctionDef(self, node):
        for d in node.decorator_list + node.args.defaults + [x for x in node.args.kw_defaults if x]:
            self.visit(d)
        for s in node.body:
            self.visit(s)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_AnnAssign(self, node):
        self.visit(node.target)
        if node.value:
            self.visit(node.value)

    def visit_BinOp(self, node):
        def typey(x):
            return ((isinstance(x, ast.Name) and x.id in _TYPE_NAMES) or (isinstance(x, ast.Constant) and x.value is None)
                    or (isinstance(x, ast.Subscript) and isinstance(x.value, ast.Name) and x.value.id in _TYPE_NAMES))
        if isinstance(node.op, ast.BitOr) and (typey(node.left) or typey(node.right)):
            self.hits.append(node.lineno)
        self.generic_visit(node)


def fstring_pep701_issues(src):
    """Constructs only legal since 3.12 (PEP 701): inside an f-string replacement field, reusing the
    enclosing quote character, any backslash, or a comment."""
    issues = []
    stack = []  # quotes of the open f-strings
    for t in tokenize.generate_tokens(io.StringIO(src).readline):
        if t.type == tokenize.FSTRING_START:
            q = t.string.lstrip("rRfFbBuU")
            if stack:
                issues += _quote_clash(q, stack, t)
            stack.append(q)
        elif t.type == tokenize.FSTRING_END:
            stack.pop()
        elif stack and t.type == tokenize.STRING:
            q = re.match(r"[rRbBuU]*('''|\"\"\"|'|\")", t.string).group(1)
            issues += _quote_clash(q, stack, t)
            if "\\" in t.string:
                issues.append(f"line {t.start[0]}: backslash inside an f-string expression")
        elif stack and t.type == tokenize.COMMENT:
            issues.append(f"line {t.start[0]}: comment inside an f-string expression")
    return issues


def _quote_clash(q, stack, t):
    out = []
    for outer in stack:
        if (len(outer) == 1 and q[0] == outer) or (len(outer) == 3 and q.startswith(outer)):
            out.append(f"line {t.start[0]}: nested string reuses the enclosing f-string quote {outer!r}")
    return out


def step4():
    files = [SA] + [os.path.join(PKG, f"{m}.py") for m in ["__init__", "__main__"] + ORDER]
    res = {}
    for p in files:
        src = read(p).decode("utf-8")
        code = src.split("\n_EMBEDDED = {", 1)[0]
        e = {}
        try:
            ast.parse(src, filename=p, feature_version=(3, 9))
            e["ast_parse_feature_version_3_9"] = "ok"
        except SyntaxError as ex:
            e["ast_parse_feature_version_3_9"] = f"SyntaxError line {ex.lineno}: {ex.msg}"
        e["pep701_fstring_issues"] = fstring_pep701_issues(src)
        v = _RuntimeUnions()
        v.visit(ast.parse(src))
        e["runtime_type_unions_outside_annotations"] = v.hits
        hits = {}
        for label, pat in API_PATTERNS.items():
            lines = [i + 1 for i, ln in enumerate(code.splitlines()) if re.search(pat, ln) and not ln.lstrip().startswith("#")]
            if lines:
                hits[label] = lines
        e["api_hits"] = hits
        tree = ast.parse(src)
        body = tree.body[1:] if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(getattr(tree.body[0], "value", None), ast.Constant) else tree.body
        e["future_annotations_first"] = bool(body and isinstance(body[0], ast.ImportFrom) and body[0].module == "__future__"
                                             and any(a.name == "annotations" for a in body[0].names))
        n_pipe_ann = 0
        for node in ast.walk(tree):
            anns = []
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                anns = [a.annotation for a in node.args.args + node.args.kwonlyargs + node.args.posonlyargs if a.annotation] + ([node.returns] if node.returns else [])
            elif isinstance(node, ast.AnnAssign):
                anns = [node.annotation]
            n_pipe_ann += sum(1 for a in anns if any(isinstance(x, ast.BinOp) and isinstance(x.op, ast.BitOr) for x in ast.walk(a)))
        e["annotations_using_X_or_Y"] = n_pipe_ann
        rel = os.path.relpath(p, ROOT)
        res[rel] = e
        bad_api = {k: v for k, v in hits.items() if "allowed" not in k}
        if e["ast_parse_feature_version_3_9"] != "ok" or e["pep701_fstring_issues"] or v.hits or bad_api or \
                (n_pipe_ann and not e["future_annotations_first"] and p != SA):
            problem(f"step 4 {rel}", "runs on Python 3.9+", "3.9-incompatible construct",
                    json.dumps(e)[:3000], "", "major")
    # positive controls: each checker must flag a construct that really needs 3.10+ / 3.12+
    def _ast39(code):
        try:
            ast.parse(code, feature_version=(3, 9))
            return "not flagged"
        except SyntaxError:
            return "flagged"
    v = _RuntimeUnions()
    v.visit(ast.parse("ok = isinstance(x, int | None)\ndef f(a: int | None) -> str | None: pass\n"))
    controls = {
        "match statement (3.10) via ast feature_version": _ast39("match x:\n    case 1:\n        pass\n"),
        "except* (3.11) via ast feature_version": _ast39("try:\n    pass\nexcept* ValueError:\n    pass\n"),
        "same quote inside f-string (3.12)": "flagged" if fstring_pep701_issues('x = f"{d["a"]}"\n') else "not flagged",
        "backslash inside f-string expression (3.12)":
            "flagged" if fstring_pep701_issues("x = f\"{'\\n'.join(y)}\"\n") else "not flagged",
        "runtime int | None (3.10), annotation ignored": "flagged" if v.hits == [1] else f"wrong: {v.hits}",
        "zip(strict=True) (3.10) via API scan":
            "flagged" if re.search(API_PATTERNS["zip(strict=) [3.10]"], "for a, b in zip(x, y, strict=True):") else "not flagged",
    }
    res["checker_positive_controls"] = controls
    if any(x != "flagged" for x in controls.values()):
        problem("step 4 checkers", "static checks are able to detect 3.10+ code", "a positive control was not flagged",
                json.dumps(controls), "fix the checker", "major")
    # the standalone must carry `from __future__ import annotations` (its X | None annotations need it on 3.9)
    if not res[os.path.relpath(SA, ROOT)]["future_annotations_first"]:
        problem("step 4 fraudurl_standalone.py", "3.9", "missing leading `from __future__ import annotations`", "", "", "major")
    # optional stdlib module used only by the standalone
    sa_src = read(SA).decode("utf-8")
    res["standalone_needs_lzma_module"] = "import lzma" in sa_src
    res["vermin"] = ("not run: vermin is not installed in the venv and installing it needs PyPI (network), "
                     "which this verification forbids")
    res["note"] = ("ast feature_version is best-effort (CPython docs); no Python 3.9/3.10/3.11 interpreter is "
                   "installed on this machine, so 3.9 support is verified statically only")
    # a cross-version behaviour difference that the 3.12 interpreter can demonstrate: Python <= 3.9.13 /
    # 3.10.6 had no int-string-conversion limit, so 5000-digit hosts parse as an integer IPv4 there.
    from fraudurl import cli as pcli
    pcli._init_worker(False, None)
    url = "http://" + "1" * 5000 + "/"
    with_limit = pcli.score_rows([url])[0]
    old = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(0)
    try:
        without_limit = pcli.score_rows([url])[0]
    finally:
        sys.set_int_max_str_digits(old)
    res["int_digit_limit_demo"] = {"url": "http://" + "1" * 12 + "...(5000 digits)/", "python_3_12_default": with_limit,
                                   "no_limit_like_py_3_9_0_to_3_9_13": without_limit,
                                   "differs": with_limit != without_limit}
    if with_limit != without_limit:
        problem("fraudurl/lexical.py _parse_ip (both editions)",
                "same results on every Python 3.9+",
                "a host made of >4300 decimal digits is 'not a URL' (ERROR) on Python with the int-string limit "
                "(3.9.14+, 3.10.7+, 3.11+) but an integer IPv4 scored FRAUD on 3.9.0-3.9.13 / 3.10.0-3.10.6; "
                "shown on 3.12 by disabling the limit with sys.set_int_max_str_digits(0)",
                json.dumps(res["int_digit_limit_demo"])[:1500],
                "in _parse_ip, treat a decimal part longer than 4300 digits as 'not an IP' before calling int(), "
                "which reproduces today's 3.12 behaviour on every version", "minor")
    return res


# ------------------------------------------------------------------ step 5: build reproducibility
def top_level_bindings(src):
    out = {}
    for node in ast.parse(src).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out[node.name] = "def"
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            for t in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                for n in ast.walk(t):
                    if isinstance(n, ast.Name):
                        out[n.id] = "assign"
        elif isinstance(node, ast.Import):
            for a in node.names:
                out[a.asname or a.name.split(".")[0]] = f"import {a.name}"
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            for a in node.names:
                out[a.asname or a.name] = f"from {node.module} import {a.name}"
    return out


def step5(sys_py):
    out = {}
    build = load_module("build_single_file_verify", BUILD)
    orig = read(SA)
    backup = os.path.join(SCRATCH, "fraudurl_standalone.orig.py")
    write(backup, orig)
    out["original_sha256"] = sha(orig)
    # (a) the literal rebuild, in place, as a user would run it
    r = run_proc([PY, BUILD], cwd=ROOT, env=child_env())
    new = read(SA)
    c = cmp_bytes(orig, new)
    out["rebuild_in_place"] = {"rc": r["rc"], "stdout": r["stdout"].strip(), "identical": c["identical"],
                               "cmp": c.get("cmp"), "rebuilt_sha256": sha(new)}
    if not c["identical"]:
        problem("step 5 rebuild", "build is reproducible", c.get("cmp", ""), c.get("diff", "")[:3000],
                "rebuild and commit fraudurl_standalone.py from the current package", "major")
    if read(SA) != orig:
        write(SA, orig)  # never leave a changed file behind
    out["original_restored_and_verified"] = read(SA) == orig
    # (b) build to a scratch path with the second interpreter (liblzma / Python version independence)
    tgt = os.path.join(SCRATCH, "rebuild_sys.py")
    snippet = ("import importlib.util,sys;sys.dont_write_bytecode=True;"
               f"s=importlib.util.spec_from_file_location('b',{BUILD!r});m=importlib.util.module_from_spec(s);"
               f"s.loader.exec_module(m);m.OUT={tgt!r};m.main()")
    r2 = run_proc([sys_py, "-c", snippet], cwd=ROOT, env=child_env())
    got = read(tgt) if os.path.exists(tgt) else b""
    c2 = cmp_bytes(orig, got)
    out["rebuild_with_sys_python_to_scratch"] = {"rc": r2["rc"], "identical": c2["identical"], "cmp": c2.get("cmp"),
                                                 "stderr_tail": r2["stderr"][-300:]}
    if not c2["identical"]:
        problem(f"step 5 rebuild with {sys_py}", "reproducible across interpreters", c2.get("cmp", ""),
                c2.get("diff", "")[:2000], "", "minor")
    # (c) embedded data == package data; each code section == the build's transformation of the package
    fus_mod = load_module("fus_embedded_check", SA); fus_emb = fus_mod._EMBEDDED
    data = {}
    for d in DATA:
        raw = read(os.path.join(PKG, "data", d))
        dec = fus_mod._embedded_text(d).encode("utf-8")  # format-agnostic (zlib or lzma)
        data[d] = {"package_bytes": len(raw), "embedded_decompressed_identical": dec == raw}
        if dec != raw:
            problem(f"step 5 embedded {d}", "embedded data == package data", "differs", "", "rebuild", "critical")
    out["embedded_data"] = data
    src = orig.decode("utf-8")
    sections = {}
    for m in ORDER:
        ms = build.module_source(m)
        sections[m] = ms in src
        if ms not in src:
            problem(f"step 5 section {m}.py", "standalone code == package code", "section differs from the package", "", "rebuild", "major")
    out["code_sections_match_package"] = sections
    h = hashlib.sha256()
    for m in ["__init__"] + ORDER:
        h.update(read(os.path.join(PKG, f"{m}.py")))
    for d in DATA:
        h.update(read(os.path.join(PKG, "data", d)))
    out["header_source_hash_current"] = f"source sha256 {h.hexdigest()[:16]}" in src
    # (d) name collisions between the concatenated modules (the later one would silently win)
    seen, coll = {}, []
    for m in ORDER:
        b = top_level_bindings(read(os.path.join(PKG, f"{m}.py")).decode("utf-8"))
        for name, kind in b.items():
            if name in seen and not (kind.startswith(("import", "from")) and kind == seen[name][1]):
                coll.append({"name": name, "first": seen[name], "again": [m, kind]})
            seen.setdefault(name, [m, kind])
    out["top_level_name_collisions"] = coll
    if coll:
        problem("step 5 namespace", "concatenation is safe", "top-level names bound in two modules", json.dumps(coll), "", "major")
    out["size_bytes"] = len(orig)
    return out


# ------------------------------------------------------------------ step 6: speed
def step6(repeats):
    out = {"input": os.path.relpath(BENCH, ROOT)}
    if not os.path.exists(BENCH):
        out["skipped"] = "bench file missing"
        problem("step 6", "speed", "bench_200000.csv missing", BENCH, "", "minor")
        return out
    runs = {"package": [], "standalone": []}
    outs = {}
    order = (["package", "standalone", "standalone", "package"] * ((repeats + 1) // 2))[:2 * repeats]
    for impl in order:
        o = os.path.join(SCRATCH, f"speed_{impl}.csv")
        cmd = [PY, "-m", "fraudurl", BENCH, "-o", o] if impl == "package" else [PY, SA, BENCH, "-o", o]
        r = run_proc(cmd, cwd=ROOT, env=child_env(ROOT if impl == "package" else None))
        m = re.search(r"Done: ([\d,]+) URLs in ([\d.]+)s", r["stderr"])
        runs[impl].append({"wall_s": round(r["wall"], 2), "reported_s": float(m.group(2)) if m else None, "rc": r["rc"]})
        outs[impl] = sha(read(o))
        print(f"  {impl:<10} wall {r['wall']:.1f}s", flush=True)
    med = {k: statistics.median(x["wall_s"] for x in v) for k, v in runs.items()}
    out.update(runs=runs, median_wall_s=med, ratio_standalone_over_package=round(med["standalone"] / med["package"], 4),
               outputs_identical=outs["package"] == outs["standalone"], workers="default (4)", cpu_count=os.cpu_count())
    if abs(med["standalone"] / med["package"] - 1) > 0.10:
        problem("step 6 speed", "within ~10%", f"ratio {med['standalone'] / med['package']:.3f}", json.dumps(runs), "", "minor")
    if outs["package"] != outs["standalone"]:
        problem("step 6 200k outputs", "identical", "200k outputs differ", "", "", "major")
    # cold start: 10 URLs, 1 process
    small = os.path.join(SCRATCH, "cold10.csv")
    write(small, csv_bytes([["url"]] + [[u] for u in AWK[:10]]))
    cold = {"package": [], "standalone": []}
    for _ in range(5):
        for impl in ("package", "standalone"):
            o = os.path.join(SCRATCH, "cold10.out.csv")
            cmd = [PY, "-m", "fraudurl", small, "-o", o, "--workers", "1"] if impl == "package" else [PY, SA, small, "-o", o, "--workers", "1"]
            cold[impl].append(run_proc(cmd, cwd=ROOT, env=child_env(ROOT if impl == "package" else None))["wall"])
    out["cold_start_10_urls_1_worker_median_s"] = {k: round(statistics.median(v), 3) for k, v in cold.items()}
    return out


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--steps", default="1,2,3,4,5,6")
    ap.add_argument("--sys-python", default=shutil.which("python3") or shutil.which("python") or sys.executable,
                    help="a second Python interpreter (e.g. a system Python outside the virtualenv)")
    ap.add_argument("--no-cross", action="store_true", help="step 1: skip the second-interpreter battery")
    ap.add_argument("--speed-repeats", type=int, default=2)
    ap.add_argument("--keep", action="store_true", help="keep the scratch folder")
    ap.add_argument("--out", default=OUT_JSON)
    a = ap.parse_args()
    steps = {int(s) for s in a.steps.split(",") if s.strip()}
    if os.path.exists(SCRATCH):
        shutil.rmtree(SCRATCH)
    os.makedirs(SCRATCH)
    t0 = time.time()
    fus = load_module("fus", SA)
    dns = load_cache("dns.jsonl")
    sample = []
    ex = os.path.join(ROOT, "examples", "sample_urls.csv")
    if os.path.exists(ex):
        with open(ex, encoding="utf-8-sig", newline="") as fh:
            sample = [r["url"] for r in csv.DictReader(fh)]
    hosts = sorted(dns)
    tpl = ["https://{h}/", "http://{h}/login.php?id=1", "{h}/account/verify", "https://{h}:8443/x?next=/home"]
    mix = sample + [tpl[i % 4].format(h=h) for i, h in enumerate(hosts[:120])] + AWK + synth(100, 1, hosts)
    big45 = synth(45000, 45, hosts)
    big25 = synth(25000, 25, hosts)
    sys_py = a.sys_python
    sys_ver = subprocess.run([sys_py, "-c", "import sys;print(sys.version.split()[0])"], capture_output=True, text=True).stdout.strip() \
        if os.path.exists(sys_py) else None
    report = {"generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "harness": "experiments/verify_standalone.py", "python_venv": sys.version.split()[0],
              "python_second": sys_ver, "second_python_path": sys_py,
              "standalone": {"path": "fraudurl_standalone.py", "bytes": os.path.getsize(SA), "sha256": sha(read(SA))},
              "steps": {}}
    names = {1: "cli_equivalence", 2: "enriched_path_in_process", 3: "self_containment_and_safety",
             4: "python_3_9_static", 5: "build_reproducibility", 6: "speed"}
    for s in sorted(steps):
        print(f"== step {s}: {names[s]}", flush=True)
        t = time.time()
        if s == 1:
            r = step1(mix, big45, big25, sys_py, cross=not a.no_cross and sys_ver is not None)
        elif s == 2:
            r = step2(fus)
        elif s == 3:
            r = step3(mix, sys_py)
        elif s == 4:
            r = step4()
        elif s == 5:
            r = step5(sys_py)
        else:
            r = step6(a.speed_repeats)
        r["seconds"] = round(time.time() - t, 1)
        report["steps"][names[s]] = r
        print(f"   done in {r['seconds']}s; problems so far: {len(PROBLEMS)}", flush=True)
    report["network_events_in_harness_process"] = NET_EVENTS
    report["problems"] = PROBLEMS
    report["verdict"] = "no mismatches found" if not PROBLEMS else f"{len(PROBLEMS)} problem(s) found"
    report["seconds"] = round(time.time() - t0, 1)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(report, fh, indent=1, ensure_ascii=False, default=str)
    print(f"wrote {a.out}: {report['verdict']}")
    if not a.keep:
        shutil.rmtree(SCRATCH, ignore_errors=True)
    return 1 if PROBLEMS else 0


if __name__ == "__main__":
    sys.exit(main())
