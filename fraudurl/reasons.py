"""Plain-English wording for every signal the models use.

The *choice* of which signals to show is not made here: it comes from the model's own
per-feature contributions (see model.py). This module only phrases a signal for the value
this particular URL has, e.g. "no 'www.' prefix" vs "has a 'www.' prefix".
"""
from __future__ import annotations

import math


def _n(v, one, many, zero=None):
    k = int(round(v))
    if k == 0 and zero:
        return zero
    return (one if k == 1 else many).format(k=k)


def _chars(v):
    k = int(v)
    return f"{k} character" + ("" if k == 1 else "s")


def _pct(v):
    return f"{max(0.0, v) * 100:.0f}%"


def _bits(v):
    return f"{max(0.0, v):.1f}"


def _days(v):
    d = max(0, int(round(10 ** v - 1)))
    if d < 60:
        return f"{d} day{'s' if d != 1 else ''}"
    if d < 730:
        return f"about {d // 30} months"
    return f"about {d // 365} years"


PHRASES = {
    # --- scheme / structure
    "scheme_http": lambda v, f: "uses unencrypted http://" if v >= .5 else "uses https:// (or no scheme given)",
    "www_prefix": lambda v, f: "has a 'www.' prefix" if v >= .5 else "no 'www.' prefix",
    "is_homepage": lambda v, f: "bare landing page (no path)" if v >= .5 else "points to a specific page",
    "has_userinfo": lambda v, f: "contains 'user@' before the host (hides the real site)" if v >= .5 else "no user@ part",
    "n_at": lambda v, f: _n(v, "an '@' in the URL", "{k} '@' signs in the URL", "no '@' in the URL"),
    "has_port": lambda v, f: "explicit port number" if v >= .5 else "no explicit port",
    "port_nonstd": lambda v, f: "unusual port number" if v >= .5 else "standard port",
    "url_len": lambda v, f: f"URL is {_chars(v)} long",
    "host_len": lambda v, f: f"hostname is {_chars(v)} long",
    "path_len": lambda v, f: "no path" if v <= 1 else f"path is {_chars(v)} long",
    "query_len": lambda v, f: "no query string" if v == 0 else f"query string of {_chars(v)}",
    "n_params": lambda v, f: _n(v, "1 query parameter", "{k} query parameters", "no query parameters"),
    "path_depth": lambda v, f: _n(v, "1 path level", "{k} path levels", "no path levels"),
    "path_max_seg_len": lambda v, f: "no path segments" if v == 0 else f"longest path segment is {_chars(v)}",
    "double_slash_in_path": lambda v, f: "'//' inside the path (redirect trick)" if v >= .5 else "no '//' in the path",
    "embedded_url": lambda v, f: "another URL or 'www.' is embedded in the path/query" if v >= .5 else "no embedded URL",
    "redirect_param": lambda v, f: "has a redirect parameter (url=, next=, ...)" if v >= .5 else "no redirect parameter",
    "ext_server": lambda v, f: "server-script page (.php/.asp/.jsp)" if v >= .5 else "not a .php/.asp page",
    "ext_page": lambda v, f: "static .html page" if v >= .5 else "not a static .html page",
    "ext_risky": lambda v, f: "links to a downloadable executable/archive" if v >= .5 else "not an executable download",
    "wp_path": lambda v, f: "WordPress directory in the path (often a hacked site)" if v >= .5 else "no WordPress directory in path",
    # --- character composition
    "digit_ratio": lambda v, f: f"{_pct(v)} of characters are digits",
    "letter_ratio": lambda v, f: f"{_pct(v)} of characters are letters",
    "upper_ratio": lambda v, f: f"{_pct(v)} of characters are upper-case",
    "special_ratio": lambda v, f: f"{_pct(v)} of characters are symbols",
    "url_entropy": lambda v, f: f"URL randomness {_bits(v)} bits/char",
    "host_entropy": lambda v, f: f"hostname randomness {_bits(v)} bits/char",
    "path_entropy": lambda v, f: "no path" if v <= 0 else f"path randomness {_bits(v)} bits/char",
    "sld_entropy": lambda v, f: f"domain-name randomness {_bits(v)} bits/char",
    "n_pct_encoded": lambda v, f: _n(v, "1 percent-encoded character", "{k} percent-encoded characters", "no percent-encoding"),
    "non_ascii": lambda v, f: _n(v, "1 non-ASCII character", "{k} non-ASCII characters", "only ASCII characters"),
    "path_digit_ratio": lambda v, f: f"{_pct(v)} of the path is digits",
    "host_digit_ratio": lambda v, f: f"{_pct(v)} of the hostname is digits",
    # --- host / domain
    "host_n_labels": lambda v, f: f"hostname has {int(v)} parts",
    "n_sub_labels": lambda v, f: _n(v, "1 subdomain level", "{k} subdomain levels", "no subdomain"),
    "sub_len": lambda v, f: "no subdomain" if v == 0 else f"subdomain is {_chars(v)} long",
    "host_n_hyphens": lambda v, f: _n(v, "1 hyphen in the hostname", "{k} hyphens in the hostname", "no hyphens in the hostname"),
    "host_n_digits": lambda v, f: _n(v, "1 digit in the hostname", "{k} digits in the hostname", "no digits in the hostname"),
    "host_is_ip": lambda v, f: "raw IP address instead of a domain name" if v >= .5 else "uses a domain name",
    "host_is_ipv6": lambda v, f: "raw IPv6 address" if v >= .5 else "not an IPv6 address",
    "host_punycode": lambda v, f: "punycode hostname (possible look-alike characters)" if v >= .5 else "no punycode",
    "host_invalid_chars": lambda v, f: "hostname contains invalid characters" if v >= .5 else "valid hostname characters",
    "host_max_label_len": lambda v, f: f"longest hostname part is {_chars(v)}",
    "sub_has_digit": lambda v, f: "digits in the subdomain" if v >= .5 else "no digits in the subdomain",
    "sub_has_hyphen": lambda v, f: "hyphen in the subdomain" if v >= .5 else "no hyphen in the subdomain",
    "sld_len": lambda v, f: f"domain name is {_chars(v)} long",
    "sld_n_digits": lambda v, f: _n(v, "1 digit in the domain name", "{k} digits in the domain name", "no digits in the domain name"),
    "sld_n_hyphens": lambda v, f: _n(v, "1 hyphen in the domain name", "{k} hyphens in the domain name", "no hyphens in the domain name"),
    "sld_vowel_ratio": lambda v, f: f"domain name is {_pct(v)} vowels" + (" (unpronounceable)" if v < 0.15 else ""),
    "sld_max_consonant_run": lambda v, f: f"up to {int(v)} consonants in a row in the domain name",
    "sld_max_digit_run": lambda v, f: f"up to {int(v)} digits in a row in the domain name",
    "sld_digit_letter_switches": lambda v, f: f"domain name switches between letters and digits {int(v)} times",
    "tld_len": lambda v, f: f"domain ending is {_chars(v)} long",
    "suffix_n_labels": lambda v, f: f"public suffix has {int(v)} part(s)",
    "suffix_gov_edu": lambda v, f: "government/education domain ending" if v >= .5 else "not a government/education domain",
    "private_suffix": lambda v, f: "hosted as a subdomain of a free hosting platform" if v >= .5 else "not on a free-subdomain platform",
    "user_content_host": lambda v, f: "on a user-content platform (sites/forms/file sharing)" if v >= .5 else "not on a user-content platform",
    "shortener": lambda v, f: "URL shortener hides the real destination" if v >= .5 else "not a URL shortener",
    # --- counts of characters
    **{f"n_{k}": (lambda one, many: (lambda v, f: _n(v, f"1 {one}", f"{{k}} {many}", f"no {many}")))(o, m) for k, o, m in (
        ("dot", "dot", "dots"), ("hyphen", "hyphen", "hyphens"), ("underscore", "underscore", "underscores"),
        ("slash", "slash", "slashes"), ("qmark", "'?'", "'?' characters"), ("equal", "'='", "'=' characters"),
        ("amp", "'&'", "'&' characters"), ("semicolon", "';'", "';' characters"), ("tilde", "'~'", "'~' characters"),
        ("percent", "'%'", "'%' characters"), ("plus", "'+'", "'+' characters"), ("hash", "'#'", "'#' characters"),
        ("comma", "comma", "commas"), ("exclaim", "'!'", "'!' characters"), ("star", "'*'", "'*' characters"),
        ("dollar", "'$'", "'$' characters"))},
    # --- words / brands
    "sus_words_host": lambda v, f: _n(v, "a login/payment word in the hostname", "{k} login/payment words in the hostname",
                                      "no login/payment words in the hostname"),
    "sus_words_path": lambda v, f: _n(v, "a login/payment word in the path", "{k} login/payment words in the path",
                                      "no login/payment words in the path"),
    "brand_is_sld": lambda v, f: "domain is a well-known brand's own domain" if v >= .5 else "not a major brand's own domain",
    "brand_in_sld_not_equal": lambda v, f: "brand name embedded in an unrelated domain" if v >= .5 else "no brand embedded in the domain",
    "brand_in_sub": lambda v, f: "well-known brand name in the subdomain (impersonation pattern)" if v >= .5 else "no brand name in the subdomain",
    "brand_in_path": lambda v, f: "well-known brand name in the path" if v >= .5 else "no brand name in the path",
    "brand_typo": lambda v, f: "look-alike spelling of a well-known brand" if v >= .5 else "not a brand look-alike",
    "n_host_tokens": lambda v, f: f"hostname has {int(v)} word parts",
    # --- enrichment
    "dns_n_a": lambda v, f: _n(v, "1 IPv4 address", "{k} IPv4 addresses", "no IPv4 address"),
    "dns_has_aaaa": lambda v, f: "has IPv6 addresses" if v >= .5 else "no IPv6 address",
    "dns_has_cname": lambda v, f: "hostname is an alias (CNAME)" if v >= .5 else "hostname is not an alias",
    "dns_ttl_a_log": lambda v, f: f"DNS cache time about {max(0, int(round(10 ** v - 1)))} s",
    "dns_private_ip": lambda v, f: "resolves to a private/internal IP" if v >= .5 else "resolves to a public IP",
    "dns_n_ns": lambda v, f: _n(v, "1 nameserver", "{k} nameservers", "no nameservers"),
    "dns_has_mx": lambda v, f: "domain receives email (MX records)" if v >= .5 else "domain has no email (MX) records",
    "domain_age_days_log": lambda v, f: f"domain registered {_days(v)} ago",
    "days_to_expiry_log": lambda v, f: f"registration expires in {_days(v)}",
    "reg_period_years": lambda v, f: f"registered for a {v:.0f}-year period" if v >= 1.5 else "registered for about 1 year",
    "days_since_changed_log": lambda v, f: f"registration last changed {_days(v)} ago",
    "status_n": lambda v, f: f"{int(v)} registry status flag(s)",
}


def describe(name: str, value: float, contrib: float, feats: dict | None = None) -> str:
    """One reason, e.g. 'uses unencrypted http:// (raises risk)'."""
    direction = "raises risk" if contrib > 0 else "lowers risk"
    feats = feats or {}
    if name == "tld_logit":
        tld = feats.get("_tld", "")
        rate = 1 / (1 + math.exp(-value)) if value == value else 0.5
        if not tld:
            label = "no domain name (raw IP address)"
        else:
            label = f"domain ending '.{tld}' ({rate:.0%} of training URLs with it were phishing)"
    elif value != value:
        return ""  # a missing value is not a reason a person can act on
    else:
        fn = PHRASES.get(name)
        try:
            label = fn(value, feats) if fn else f"{name.replace('_', ' ')} = {value:g}"
        except (ValueError, OverflowError):
            label = f"{name.replace('_', ' ')} = {value:g}"
    return f"{label} ({direction})"
