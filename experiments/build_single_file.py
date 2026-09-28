"""Build fraudurl_standalone.py: the whole fraudurl package in ONE Python file.

The package modules (psl, lexical, model, reasons, cache, enrich, cli) are concatenated in
dependency order, relative imports are removed (everything shares one namespace), and the three
data files (model_safe.json, model_enrich.json, public_suffix_list.dat) are embedded as
zlib-compressed base64 text (zlib, unlike lzma, is present in every CPython build). The result
needs nothing but Python 3.9+.

    python experiments/build_single_file.py            # writes fraudurl_standalone.py in the repo root

Edit the package, never the generated file, then rebuild. The code is copied verbatim apart
from the few substitutions listed in SUBS below (each must match exactly once).

Rebuilds are byte-identical with the same Python; a different Python may bundle a different zlib
and produce different compressed bytes that decompress to exactly the same data (verified by
experiments/verify_standalone.py).
"""
from __future__ import annotations

import ast
import base64
import hashlib
import os
import re
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "fraudurl")
OUT = os.path.join(ROOT, "fraudurl_standalone.py")
ORDER = ["psl", "lexical", "model", "reasons", "cache", "enrich", "cli"]
DATA = ["public_suffix_list.dat", "model_safe.json", "model_enrich.json"]

# (module, old, new): data files are read from the embedded blobs instead of the data/ folder.
SUBS = [
    ("psl", '_PSL_PATH = os.path.join(os.path.dirname(__file__), "data", "public_suffix_list.dat")',
     '_PSL_PATH = "public_suffix_list.dat"  # embedded (see _EMBEDDED at the end of this file)'),
    ("psl", 'with open(_PSL_PATH, encoding="utf-8") as fh:',
     'with io.StringIO(_embedded_text(_PSL_PATH)) as fh:'),
    ("model", 'with open(path, encoding="utf-8") as fh:',
     'with io.StringIO(_embedded_text(path)) as fh:'),
    ("cli", 'HERE = os.path.dirname(os.path.abspath(__file__))\n', ''),
    ("cli", 'MODEL_SAFE = os.path.join(HERE, "data", "model_safe.json")', 'MODEL_SAFE = "model_safe.json"'),
    ("cli", 'MODEL_ENRICH = os.path.join(HERE, "data", "model_enrich.json")', 'MODEL_ENRICH = "model_enrich.json"'),
    ("cli", 'if enrich and not os.path.exists(MODEL_ENRICH):', 'if enrich and MODEL_ENRICH not in _EMBEDDED:'),
    ("cli", 'ap = argparse.ArgumentParser(prog="fraudurl",', 'ap = argparse.ArgumentParser(prog="fraudurl_standalone.py",'),
    ("cli", 'if __name__ == "__main__":\n    main()\n', ''),
]

HEADER = '''#!/usr/bin/env python3
# SPDX-License-Identifier: MIT AND MPL-2.0
# fraudurl - https://github.com/amruth112/fraudurl-detector
# Copyright (c) 2026 Amruthjithraj V.R. MIT License (see LICENSE in the repository).
# The embedded Public Suffix List is licensed separately under the Mozilla Public License 2.0 (see the
# note above _EMBEDDED near the end of this file); third-party data credits are in NOTICE.md.
"""fraudurl (single-file edition) - check every URL in a CSV for phishing/fraud, offline.

    python fraudurl_standalone.py my_urls.csv                    # -> my_urls.fraudurl.csv
    python fraudurl_standalone.py my_urls.csv -o results.csv
    python fraudurl_standalone.py my_urls.csv --url-column Website
    python fraudurl_standalone.py my_urls.csv --enrich-review    # + DNS / registration lookups for REVIEW rows
    python fraudurl_standalone.py my_urls.csv --enrich           # + DNS / registration lookups for every URL
    python fraudurl_standalone.py my_urls.csv --block-list block.txt --allow-list allow.txt
    python fraudurl_standalone.py my_urls.csv --base-rate 0.01   # expect ~1% fraud
    python fraudurl_standalone.py --url https://example.com/login   # one URL -> one JSON line

Needs only Python 3.9+ (standard library). Nothing to install. In the default mode it never
touches the network; it never visits, downloads or submits anything at any URL.

What happens to each URL (full plain-English explanation: HOW_IT_WORKS.md in the repository):
  1. the CSV is read (text encoding, separator, header row and the URL column are detected),
  2. the URL is read the way a browser would, and the domain its real owner controls is found
     with the Public Suffix List (the official list of domain endings, embedded below),
  3. 83 clues are measured from the URL text (length, symbols, randomness, http vs https,
     brand names in odd places, login/payment words, free-hosting platforms, domain ending...),
  4. [--enrich / --enrich-review only] DNS records and the domain's registration dates are looked up,
  5. a model made of 400 small decision flowcharts ("trees", each built to fix the previous
     ones' mistakes) scores the clues; the score is turned into an honest probability; two
     cut-offs turn it into FRAUD / REVIEW (a person should look) / LEGITIMATE,
  6. the three clues that moved the score most are written out as plain-English reasons,
  7. the original rows are written back with 8 result columns added.

For developers: this file is generated from the fraudurl/ package by
experiments/build_single_file.py (fraudurl {version}, source sha256 {src_hash}).
Do not edit it by hand; edit the package and rebuild.
"""
from __future__ import annotations

import io

__version__ = "{version}"


def _embedded_text(name: str) -> str:
    """Decompress one embedded data file (model or Public Suffix List). Cached per process."""
    cache = _embedded_text.__dict__.setdefault("cache", {{}})
    if name not in cache:
        import base64
        import zlib
        cache[name] = zlib.decompress(base64.b64decode(_EMBEDDED[name])).decode("utf-8")
    return cache[name]

'''

FOOTER = '''

if __name__ == "__main__":
    main()
'''

_REL_IMPORT = re.compile(r"^[ \t]*from \.[A-Za-z_]* import [^\n]*\n", re.M)


def module_source(name: str) -> str:
    src = open(os.path.join(PKG, f"{name}.py"), encoding="utf-8").read()
    for mod, old, new in SUBS:
        if mod == name:
            assert src.count(old) == 1, (name, old)
            src = src.replace(old, new)
    src = src.replace("from __future__ import annotations\n", "", 1)
    src = _REL_IMPORT.sub("", src)
    # the module docstring becomes a section banner
    tree = ast.parse(src)
    doc = ast.get_docstring(tree, clean=False)
    if doc and isinstance(tree.body[0], ast.Expr):
        end = tree.body[0].end_lineno
        lines = src.splitlines(keepends=True)
        banner = "".join("# " + ln if ln.strip() else "#\n" for ln in doc.strip("\n").splitlines(keepends=True))
        src = banner.rstrip("\n") + "\n" + "".join(lines[end:])
    return src


def main():
    ns = {}
    exec(open(os.path.join(PKG, "__init__.py"), encoding="utf-8").read(), ns)
    version = ns["__version__"]
    h = hashlib.sha256()
    for m in ["__init__"] + ORDER:  # line endings normalised: same hash on Windows and Linux checkouts
        h.update(open(os.path.join(PKG, f"{m}.py"), "rb").read().replace(b"\r\n", b"\n"))
    for d in DATA:
        h.update(open(os.path.join(PKG, "data", d), "rb").read().replace(b"\r\n", b"\n"))
    parts = [HEADER.format(version=version, src_hash=h.hexdigest()[:16])]
    for m in ORDER:
        bar = "#" * 100
        parts.append(f"\n\n{bar}\n# ---- {m}.py\n{bar}\n")
        parts.append(module_source(m))
    psl_head = open(os.path.join(PKG, "data", "public_suffix_list.dat"), encoding="utf-8").read(4000)
    ver = re.search(r"// VERSION: (\S+)", psl_head)
    com = re.search(r"// COMMIT: (\S+)", psl_head)
    parts.append(f"\n\n{'#' * 100}\n# ---- embedded data files (zlib-compressed, base64)\n{'#' * 100}\n"
                 "# public_suffix_list.dat: the Public Suffix List (https://publicsuffix.org/),\n"
                 f"#   VERSION {ver.group(1) if ver else 'unknown'}, COMMIT {com.group(1) if com else 'unknown'}, unmodified.\n"
                 "#   Licensed under the Mozilla Public License 2.0 (https://mozilla.org/MPL/2.0/). Source:\n"
                 "#   https://publicsuffix.org/list/public_suffix_list.dat (also fraudurl/data/ in the repository).\n"
                 "# model_safe.json / model_enrich.json: the trained models (MIT, like the rest of this file).\n"
                 "_EMBEDDED = {\n")
    for d in DATA:
        raw = open(os.path.join(PKG, "data", d), "rb").read()
        b = base64.b64encode(zlib.compress(raw, 9)).decode("ascii")
        lines = "\n".join(b[i:i + 96] for i in range(0, len(b), 96))
        parts.append(f'    "{d}": """\n{lines}\n""",\n')
    parts.append("}\n")
    parts.append(FOOTER)
    out = "".join(parts)
    compile(out, OUT, "exec")  # syntax check before writing
    leftovers = [ln for ln in out.splitlines() if re.match(r"^\s*from \.", ln)]
    assert not leftovers, leftovers
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(out)
    print(f"wrote {OUT}: {len(out.encode('utf-8')):,} bytes, {out.count(chr(10)):,} lines")


if __name__ == "__main__":
    sys.exit(main())
