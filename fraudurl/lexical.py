"""Offline (safe-mode) URL features: computed from the URL string alone.

Nothing here touches the network. The same code is used for training and for
inference so there is no train/serve skew.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from functools import lru_cache
from urllib.parse import urlsplit, unquote

from .psl import split_host, _to_ascii

# ---------------------------------------------------------------- word lists
# Brands most frequently impersonated in phishing (APWG / vendor brand reports).
# Short ambiguous tokens (e.g. "ups", "ing", "irs") are only matched as whole tokens.
BRANDS = (
    "paypal apple icloud itunes microsoft office365 office outlook hotmail live onedrive sharepoint "
    "google gmail youtube amazon aws prime facebook instagram whatsapp meta messenger linkedin "
    "netflix spotify twitter telegram discord steam steamcommunity roblox epicgames "
    "dhl fedex ups usps royalmail evri correos laposte postnl auspost canadapost "
    "chase wellsfargo bankofamerica citibank citi hsbc barclays lloyds natwest santander "
    "ing rabobank abnamro bnpparibas societegenerale creditagricole deutschebank sparkasse "
    "commbank westpac anz nab scotiabank rbc tdbank bmo capitalone americanexpress amex "
    "visa mastercard discover coinbase binance kraken metamask blockchain ledger trezor "
    "opensea uniswap walmart ebay alibaba aliexpress adobe dropbox docusign wetransfer "
    "yahoo aol att verizon xfinity comcast tmobile vodafone orange swisscom booking airbnb "
    "irs hmrc govuk mygov bradesco itau caixa bancodobrasil nubank mercadolibre mercadopago "
    "sbi hdfc icici paytm phonepe allegro olx"
).split()
_BRAND_SET = frozenset(BRANDS)
_LONG_BRANDS = tuple(b for b in BRANDS if len(b) >= 5)

SUSPICIOUS_WORDS = (
    "login logon signin signon verify verification validate account accounts update secure security "
    "banking confirm password passwd credential wallet recover recovery unlock suspend suspended "
    "locked billing invoice payment pay support service alert webscr cmd auth authenticate "
    "session limited restore reactivate customer helpdesk bonus gift prize winner claim refund "
    "tax delivery parcel package track tracking shipment webmail mail admin portal token "
    "seed airdrop giveaway free promo reward redeem kyc 2fa otp"
).split()
_SUS_SET = frozenset(SUSPICIOUS_WORDS)

SHORTENERS = frozenset((
    "bit.ly bitly.com tinyurl.com t.co goo.gl ow.ly is.gd buff.ly rebrand.ly cutt.ly shorturl.at "
    "rb.gy tiny.cc t.ly s.id lnkd.in v.gd shorte.st adf.ly bl.ink soo.gd x.co u.to qr.ae "
    "shorturl.com tiny.one clck.ru urlz.fr 1url.com surl.li short.gy linktr.ee t.me wa.me"
).split())

# Legitimate platforms that host arbitrary user content under paths (not covered by
# the PSL private section, which already marks e.g. *.github.io, *.web.app).
USER_CONTENT_HOSTS = frozenset((
    "sites.google.com docs.google.com drive.google.com forms.gle storage.googleapis.com "
    "firebasestorage.googleapis.com ipfs.io dweb.link cloudflare-ipfs.com gateway.pinata.cloud "
    "onedrive.live.com 1drv.ms dropbox.com dl.dropboxusercontent.com wetransfer.com "
    "notion.site notion.so canva.com webflow.io weebly.com wixsite.com wix.com "
    "square.site mystrikingly.com godaddysites.com jimdosite.com yolasite.com "
    "000webhostapp.com blogspot.com wordpress.com tumblr.com medium.com "
    "s3.amazonaws.com amazonaws.com azurewebsites.net blob.core.windows.net "
    "github.io gitlab.io pages.dev workers.dev r2.dev netlify.app vercel.app herokuapp.com "
    "glitch.me replit.app repl.co ngrok.io ngrok-free.app ngrok.app trycloudflare.com "
    "duckdns.org formstack.com typeform.com jotform.com surveymonkey.com"
).split())

RISKY_EXTS = frozenset("exe scr zip rar 7z apk msi bat cmd js jar vbs iso img dll ps1 lnk hta".split())
SERVER_EXTS = frozenset("php asp aspx jsp cgi pl".split())
PAGE_EXTS = frozenset("html htm shtml xhtml".split())

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_HEX_RE = re.compile(r"%[0-9a-fA-F]{2}")
_VOWELS = frozenset("aeiou")
_FALLBACK_RE = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.\-]*:)?//([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?$", re.S)
_GOV_EDU_RE = re.compile(r"(^|\.)(gov|edu|mil|gob|gouv|govt|go|ac|gv|nic)(\.|$)")
_BAD_HOST_RE = re.compile(r"[^a-z0-9.\-_]")
_REDIRECT_PARAMS = frozenset("url redirect redirect_uri redir next goto dest destination continue return returnurl target link u r".split())


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _parse_ip(host: str) -> int:
    """0 = not an IP, 4 = IPv4 (incl. hex/octal/integer forms), 6 = IPv6."""
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h).version
    except ValueError:
        pass
    parts = h.split(".")
    if not 1 <= len(parts) <= 4:
        return 0
    try:
        vals = []
        for p in parts:
            if not p:
                return 0
            if p.lower().startswith("0x"):
                vals.append(int(p, 16))
            elif len(p) > 1 and p.startswith("0"):
                vals.append(int(p, 8))
            else:
                if len(p) > 4300:  # int() refuses these on 3.10.7+/3.11+; keep every version identical
                    return 0
                vals.append(int(p, 10))
    except ValueError:
        return 0
    return 4 if all(v >= 0 for v in vals) and (len(parts) > 1 or vals[0] > 16777215) else 0


def normalize_url(raw: str) -> tuple[str, str]:
    """Return (url_for_parsing, scheme). Adds '//' when the scheme is missing."""
    s = raw.strip().strip('"').strip("'")
    s = s.replace("\\", "/")
    m = re.match(r"^(https?|ftp|wss?)\s*:/*", s, re.I)  # browsers accept 'http:/x' and 'http:\\\\x'
    if m:
        return m.group(1).lower() + "://" + s[m.end():], m.group(1).lower()
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://", s)
    if m:
        return s, m.group(1).lower()
    return "//" + s.lstrip("/"), ""


class ParsedURL:
    __slots__ = ("raw", "url", "scheme", "netloc", "userinfo", "host", "host_unicode", "port", "port_error",
                 "path", "query", "fragment", "sub", "reg", "suffix", "private_suffix", "ip")

    def __init__(self, raw: str):
        self.raw = raw
        self.url, self.scheme = normalize_url(raw)
        try:
            parts = urlsplit(self.url)
            netloc, path, query, fragment = parts.netloc, parts.path, parts.query, parts.fragment
        except ValueError:  # e.g. malformed "[...]" hosts: fall back to a plain split
            m = _FALLBACK_RE.match(self.url)
            netloc, path, query, fragment = (m.group(1) or ""), (m.group(2) or ""), (m.group(3) or ""), (m.group(4) or "")
            netloc = netloc.replace("[", "").replace("]", "")
        self.netloc = netloc
        self.userinfo = ""
        if "@" in netloc:
            self.userinfo, _, netloc = netloc.rpartition("@")
        host = netloc
        self.port, self.port_error = None, False
        if host.startswith("["):
            end = host.find("]")
            rest = host[end + 1:]
            host = host[: end + 1]
            if rest.startswith(":"):
                self.port = rest[1:]
        elif host.count(":") == 1:
            host, self.port = host.split(":")
            if self.port == "":  # 'host:' with an empty port means the default port
                self.port = None
        if self.port is not None:
            if not self.port.isdigit() or not 0 < int(self.port) < 65536:
                self.port_error = True
        host = host.strip().rstrip(".").lower()
        if "%" in host:  # browsers percent-decode the host before resolving it
            host = unquote(host)
        self.host_unicode = host
        if host and not host.isascii():
            host = _to_ascii(host)
        self.host = host
        self.path, self.query, self.fragment = path, query, fragment
        self.ip = _parse_ip(host) if host else 0
        if self.ip or not host:
            self.sub, self.reg, self.suffix, self.private_suffix = "", host, "", False
        else:
            self.sub, self.reg, self.suffix, self.private_suffix = split_host(host)


@lru_cache(maxsize=4096)
def _deletes(word: str) -> frozenset:
    return frozenset(word[:i] + word[i + 1:] for i in range(len(word)))


class TypoIndex:
    """SymSpell-style index: finds names within ~1 edit of a popular name in O(len)."""

    def __init__(self, names):
        self.names = frozenset(n for n in names if len(n) >= 5)
        self.index: dict[str, set] = {}
        for n in self.names:
            self.index.setdefault(n, set()).add(n)
            for d in _deletes(n):
                self.index.setdefault(d, set()).add(n)

    def near(self, word: str) -> str:
        """Return a popular name within edit distance 1 of ``word`` (but not equal), else ''."""
        if len(word) < 5 or len(word) > 40 or word in self.names:  # no brand is > 40 chars
            return ""
        hits = set(self.index.get(word, ()))
        for d in _deletes(word):
            hits |= self.index.get(d, set())
        # Keep only distance-1 matches (insert/delete/substitute).
        for h in sorted(hits):
            if abs(len(h) - len(word)) <= 1 and _lev_le1(h, word):
                return h
        return ""


def _lev_le1(a: str, b: str) -> bool:
    if a == b:
        return False
    la, lb = len(a), len(b)
    if la == lb:
        return sum(x != y for x, y in zip(a, b)) == 1
    if la + 1 == lb:
        a, b, la, lb = b, a, lb, la
    if la != lb + 1:
        return False
    i = 0
    while i < lb and a[i] == b[i]:
        i += 1
    return a[i + 1:] == b[i:]


_BRAND_TYPO = TypoIndex(BRANDS)

# homoglyph / leetspeak folding used to detect 'paypa1', 'g00gle', 'rnicrosoft'
_FOLD = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})


# Cyrillic/Greek letters that render like Latin ones (IDN homograph attacks).
_CONFUSABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ј": "j", "һ": "h", "ԁ": "d", "ԛ": "q",
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "ρ": "p", "τ": "t", "υ": "u", "ɡ": "g", "ı": "i", "ɩ": "i",
})


def _fold(s: str) -> str:
    if "xn--" in s:
        try:
            s = s.encode("ascii").decode("idna")
        except UnicodeError:
            pass
    s = s.translate(_CONFUSABLE)
    return s.translate(_FOLD).replace("rn", "m").replace("vv", "w")


def _max_run(s: str, charset) -> int:
    best = cur = 0
    for ch in s:
        if ch in charset:
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


_CONSONANTS = frozenset("bcdfghjklmnpqrstvwxyz")


def extract(raw: str, popular: "TypoIndex | None" = None, popular_rank: "dict | None" = None) -> dict:
    """Extract all lexical features for one URL. Always returns a dict (never raises)."""
    try:
        p = ParsedURL(raw)
    except Exception:  # noqa: BLE001 - malformed input must still yield a row
        p = None
    f: dict[str, float] = {}
    if p is None or not p.host:
        f["parse_error"] = 1.0
        return f
    f["parse_error"] = 0.0
    # Features are computed on the browser-canonical URL: scheme://netloc + path (an empty path is "/",
    # exactly as browsers treat it) + ?query. The #fragment is never sent to the server and is ignored.
    # (Datasets record "https://x.com" and "https://x.com/" inconsistently between classes - an artifact.)
    url = f"{p.scheme or 'https'}://{p.netloc}{p.path or '/'}" + (f"?{p.query}" if p.query else "")
    host, sub, reg, suffix = p.host, p.sub, p.reg, p.suffix
    sld = reg[: -len(suffix) - 1] if suffix and reg.endswith("." + suffix) else reg
    path, query = p.path or "/", p.query
    rest = path + ("?" + query if query else "")
    rest_l = unquote(rest).lower()

    L = len(url) or 1
    f["url_len"] = len(url)
    # Only an *explicit* http:// counts. A missing scheme is treated like https, because in
    # training data only legitimate URLs lacked a scheme (an artifact), while real input
    # CSVs often omit it.
    f["scheme_http"] = 1.0 if p.scheme == "http" else 0.0
    f["has_userinfo"] = 1.0 if p.userinfo else 0.0
    f["n_at"] = url.count("@")
    f["has_port"] = 1.0 if p.port is not None else 0.0
    f["port_nonstd"] = 1.0 if p.port not in (None, "80", "443") else 0.0
    for name, ch in (("dot", "."), ("hyphen", "-"), ("underscore", "_"), ("slash", "/"),
                     ("qmark", "?"), ("equal", "="), ("amp", "&"), ("semicolon", ";"),
                     ("tilde", "~"), ("percent", "%"), ("plus", "+"), ("hash", "#"),
                     ("comma", ","), ("exclaim", "!"), ("star", "*"), ("dollar", "$")):
        f[f"n_{name}"] = url.count(ch)
    n_digit = sum(c.isdigit() for c in url)
    n_alpha = sum(c.isalpha() for c in url)
    f["digit_ratio"] = n_digit / L
    f["letter_ratio"] = n_alpha / L
    f["upper_ratio"] = sum(c.isupper() for c in url) / L
    f["special_ratio"] = (L - n_digit - n_alpha) / L
    f["url_entropy"] = entropy(url)
    f["n_pct_encoded"] = len(_HEX_RE.findall(url))
    f["non_ascii"] = sum(ord(c) > 127 for c in url)
    f["double_slash_in_path"] = 1.0 if "//" in path else 0.0
    f["embedded_url"] = 1.0 if ("http:" in rest_l or "https:" in rest_l or "www." in rest_l) else 0.0
    params = [kv.split("=", 1)[0].lower() for kv in query.split("&") if kv] if query else []
    f["n_params"] = len(params)
    f["redirect_param"] = 1.0 if any(k in _REDIRECT_PARAMS for k in params) else 0.0

    # ---- host
    labels = host.split(".")
    f["host_len"] = len(host)
    f["host_n_labels"] = len(labels)
    f["n_sub_labels"] = len(sub.split(".")) if sub else 0
    f["sub_len"] = len(sub)
    f["www_prefix"] = 1.0 if labels[0] == "www" else 0.0
    f["host_n_hyphens"] = host.count("-")
    f["host_n_digits"] = sum(c.isdigit() for c in host)
    f["host_digit_ratio"] = f["host_n_digits"] / len(host)
    f["host_is_ip"] = 1.0 if p.ip else 0.0
    f["host_is_ipv6"] = 1.0 if p.ip == 6 else 0.0
    f["host_punycode"] = 1.0 if "xn--" in host else 0.0
    f["host_invalid_chars"] = 1.0 if (not p.ip and _BAD_HOST_RE.search(host)) else 0.0
    f["host_entropy"] = entropy(host)
    f["host_max_label_len"] = max(len(x) for x in labels)
    f["sub_has_digit"] = 1.0 if any(c.isdigit() for c in sub) else 0.0
    f["sub_has_hyphen"] = 1.0 if "-" in sub else 0.0

    # ---- registrable domain / TLD
    f["sld_len"] = len(sld)
    f["sld_entropy"] = entropy(sld)
    f["sld_n_digits"] = sum(c.isdigit() for c in sld)
    f["sld_n_hyphens"] = sld.count("-")
    letters = [c for c in sld if c.isalpha()]
    f["sld_vowel_ratio"] = (sum(c in _VOWELS for c in letters) / len(letters)) if letters else 0.0
    f["sld_max_consonant_run"] = _max_run(sld, _CONSONANTS)
    f["sld_max_digit_run"] = _max_run(sld, "0123456789")
    f["sld_digit_letter_switches"] = sum(1 for a, b in zip(sld, sld[1:]) if a.isdigit() != b.isdigit())
    tld = suffix.rsplit(".", 1)[-1] if suffix else ""
    f["tld_len"] = len(tld)
    f["suffix_n_labels"] = suffix.count(".") + 1 if suffix else 0
    f["private_suffix"] = 1.0 if p.private_suffix else 0.0
    f["user_content_host"] = 1.0 if (host in USER_CONTENT_HOSTS or reg in USER_CONTENT_HOSTS
                                      or suffix in USER_CONTENT_HOSTS) else 0.0
    f["shortener"] = 1.0 if (host in SHORTENERS or reg in SHORTENERS) else 0.0

    # ---- path / query
    segs = [s for s in path.split("/") if s]
    f["path_len"] = len(path)
    f["path_depth"] = len(segs)
    f["path_max_seg_len"] = max((len(s) for s in segs), default=0)
    f["path_digit_ratio"] = (sum(c.isdigit() for c in path) / len(path)) if path else 0.0
    f["path_entropy"] = entropy(path)
    f["query_len"] = len(query)
    last = segs[-1].lower() if segs else ""
    ext = last.rsplit(".", 1)[-1] if "." in last else ""
    f["ext_server"] = 1.0 if ext in SERVER_EXTS else 0.0
    f["ext_page"] = 1.0 if ext in PAGE_EXTS else 0.0
    f["ext_risky"] = 1.0 if ext in RISKY_EXTS else 0.0
    f["is_homepage"] = 1.0 if (not segs and not query) else 0.0

    # ---- semantic: suspicious words & brand impersonation
    host_tokens = _TOKEN_RE.findall(sub + " " + sld)
    rest_tokens = _TOKEN_RE.findall(rest_l)
    f["sus_words_host"] = sum(t in _SUS_SET for t in host_tokens) + sum(
        1 for w in ("login", "signin", "verify", "secure", "account", "update") if w in host and w not in host_tokens)
    f["sus_words_path"] = sum(t in _SUS_SET for t in rest_tokens)
    f["wp_path"] = 1.0 if ("wp-content" in rest_l or "wp-includes" in rest_l or "wp-admin" in rest_l) else 0.0

    def brand_hits(tokens, text):
        hits = {t for t in tokens if t in _BRAND_SET}
        hits.update(b for b in _LONG_BRANDS if b in text)
        return hits

    sld_brand = sld in _BRAND_SET
    sub_brands = brand_hits(_TOKEN_RE.findall(sub), sub)
    sld_brands = brand_hits(_TOKEN_RE.findall(sld), sld)
    path_brands = brand_hits(rest_tokens, rest_l)
    f["brand_is_sld"] = 1.0 if sld_brand else 0.0
    f["brand_in_sld_not_equal"] = 1.0 if (sld_brands and not sld_brand) else 0.0
    f["brand_in_sub"] = 1.0 if (sub_brands - {sld}) else 0.0
    f["brand_in_path"] = 1.0 if (path_brands - {sld}) else 0.0
    folded = _fold(sld)
    f["brand_typo"] = 1.0 if (not sld_brand and (_BRAND_TYPO.near(sld) or (folded != sld and folded in _BRAND_SET))) else 0.0
    f["n_host_tokens"] = len(host_tokens)

    # ---- popularity-list derived (optional; see report on circularity)
    if popular is not None:
        f["popular_typo"] = 1.0 if popular.near(sld) else 0.0
    if popular_rank is not None:
        r = popular_rank.get(reg)
        f["popular_rank_log"] = math.log10(r) if r else 7.0
        f["is_popular"] = 1.0 if r else 0.0
    f["suffix_gov_edu"] = 1.0 if _GOV_EDU_RE.search(suffix or "") else 0.0
    # Reputation key = the FULL public suffix ("gov.br", "com.br", "co.uk", "pages.dev"); the model layer
    # falls back to the last label ("br") and then to the global rate when a suffix is rare.
    f["_tld"] = suffix if suffix else ""
    return f
