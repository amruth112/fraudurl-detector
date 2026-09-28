"""Minimal, dependency-free Public Suffix List (PSL) lookup.

Splits a hostname into (subdomain, registrable domain, public suffix) using the
vendored ``data/public_suffix_list.dat``. Implements the standard PSL algorithm:
longest matching rule wins, ``*`` wildcards, ``!`` exceptions, and the implicit
``*`` default rule. Rules from the PRIVATE section (e.g. ``github.io``,
``web.app``, ``blogspot.com``) are honoured and flagged, because free hosting
platforms are a common home for phishing pages.
"""
from __future__ import annotations

import os
from functools import lru_cache

_PSL_PATH = os.path.join(os.path.dirname(__file__), "data", "public_suffix_list.dat")

# rule (ascii, lowercase) -> (kind, is_private); kind in {"normal", "wildcard", "exception"}
_RULES: dict[str, tuple[str, bool]] | None = None


def _to_ascii(label_str: str) -> str:
    try:
        return label_str.encode("idna").decode("ascii")
    except UnicodeError:
        # stdlib IDNA 2003 rejects some IDNA 2008 names; fall back per label.
        out = []
        for lab in label_str.split("."):
            try:
                out.append(lab.encode("idna").decode("ascii") if lab else lab)
            except UnicodeError:
                out.append("xn--" + lab.encode("punycode").decode("ascii"))
        return ".".join(out)


def _load() -> dict[str, tuple[str, bool]]:
    global _RULES
    if _RULES is not None:
        return _RULES
    rules: dict[str, tuple[str, bool]] = {}
    private = False
    with open(_PSL_PATH, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if line.startswith("//"):
                if "===BEGIN PRIVATE DOMAINS===" in line:
                    private = True
                continue
            rule = line.split()[0].lower()
            kind = "normal"
            if rule.startswith("!"):
                kind, rule = "exception", rule[1:]
            elif rule.startswith("*."):
                kind, rule = "wildcard", rule[2:]
            ascii_rule = _to_ascii(rule) if not rule.isascii() else rule
            rules[f"{kind}:{ascii_rule}"] = (kind, private)
    _RULES = rules
    return rules


@lru_cache(maxsize=32768)
def split_host(host: str) -> tuple[str, str, str, bool]:
    """Return (subdomain, registrable_domain, public_suffix, suffix_is_private).

    ``host`` must be lowercase ASCII (punycode for IDNs) without a trailing dot.
    For hosts that *are* a public suffix, registrable_domain is ''.
    """
    rules = _load()
    labels = host.split(".")
    n = len(labels)
    suffix_len, private = 1, False  # implicit "*" rule
    for i in range(n):
        cand = ".".join(labels[i:])
        hit = rules.get(f"exception:{cand}")
        if hit:  # exception: suffix is the candidate minus its leftmost label
            suffix_len, private = n - i - 1, hit[1]
            break
        hit = rules.get(f"normal:{cand}")
        if hit:
            suffix_len, private = n - i, hit[1]
            break
        if i + 1 < n:
            hit = rules.get(f"wildcard:{'.'.join(labels[i + 1:])}")
            if hit:
                suffix_len, private = n - i, hit[1]
                break
    suffix = ".".join(labels[n - suffix_len:]) if suffix_len else ""
    if suffix_len >= n:
        return "", "", suffix, private
    reg = ".".join(labels[n - suffix_len - 1:])
    sub = ".".join(labels[: n - suffix_len - 1])
    return sub, reg, suffix, private


def icann_split(host: str) -> tuple[str, str, str]:
    """Like split_host but ignoring PRIVATE rules (so 'x.github.io' -> reg 'github.io')."""
    sub, reg, suffix, private = split_host(host)
    if not private:
        return sub, reg, suffix
    # Walk up until an ICANN suffix is found.
    labels = host.split(".")
    rules = _load()
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        for kind in ("exception", "normal"):
            hit = rules.get(f"{kind}:{cand}")
            if hit and not hit[1]:
                s_len = len(labels) - i - (1 if kind == "exception" else 0)
                if s_len >= len(labels):
                    return "", "", cand
                return (".".join(labels[: len(labels) - s_len - 1]),
                        ".".join(labels[len(labels) - s_len - 1:]),
                        ".".join(labels[len(labels) - s_len:]))
        if i + 1 < len(labels):
            hit = rules.get(f"wildcard:{'.'.join(labels[i + 1:])}")
            if hit and not hit[1]:
                s_len = len(labels) - i
                if s_len >= len(labels):
                    return "", "", cand
                return (".".join(labels[: len(labels) - s_len - 1]),
                        ".".join(labels[len(labels) - s_len - 1:]),
                        ".".join(labels[len(labels) - s_len:]))
    return ".".join(labels[:-2]), ".".join(labels[-2:]), labels[-1]
