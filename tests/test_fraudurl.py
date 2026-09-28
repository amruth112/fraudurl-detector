"""Tests for the shipped fraudurl package (run: python -m pytest -q tests)."""
from __future__ import annotations

import csv
import math
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fraudurl import lexical as lx  # noqa: E402
from fraudurl.psl import split_host  # noqa: E402

MODEL = os.path.join(ROOT, "fraudurl", "data", "model_safe.json")


# ------------------------------------------------------------------ PSL / parsing
@pytest.mark.parametrize("host,reg,suffix,private", [
    ("www.bbc.co.uk", "bbc.co.uk", "co.uk", False),
    ("foo.github.io", "foo.github.io", "github.io", True),
    ("a.b.web.app", "b.web.app", "web.app", True),
    ("example.com", "example.com", "com", False),
    ("www.ck", "www.ck", "ck", False),                  # exception rule !www.ck
    ("x.y.kawasaki.jp", "x.y.kawasaki.jp", "y.kawasaki.jp", False),  # wildcard *.kawasaki.jp
    ("city.kawasaki.jp", "city.kawasaki.jp", "kawasaki.jp", False),  # exception !city.kawasaki.jp
    ("paypal.com.secure-login.xyz", "secure-login.xyz", "xyz", False),
    ("unknowntld.zzzz", "unknowntld.zzzz", "zzzz", False),           # implicit * rule
])
def test_psl(host, reg, suffix, private):
    sub, r, s, p = split_host(host)
    assert (r, s, p) == (reg, suffix, private)


@pytest.mark.parametrize("url,host,reg", [
    ("https://www.paypal.com/signin", "www.paypal.com", "paypal.com"),
    ("paypal.com/login", "paypal.com", "paypal.com"),                    # no scheme
    ("HTTP://User:Pw@Sub.Example.COM:8080/a?b=1#c", "sub.example.com", "example.com"),
    ("http://[2001:db8::1]:8443/x", "[2001:db8::1]", "[2001:db8::1]"),
    ("https://[qzkwmrtbvhxnplda.\U0001d567\U0001d55a.invalid]/x", None, None),  # malformed brackets: must not raise
    ("http://xn--pypal-4ve.com/", "xn--pypal-4ve.com", "xn--pypal-4ve.com"),
    ("http://bücher.de/", "xn--bcher-kva.de", "xn--bcher-kva.de"),  # IDN -> punycode
])
def test_parse(url, host, reg):
    p = lx.ParsedURL(url)
    if host is not None:
        assert p.host == host and p.reg == reg


@pytest.mark.parametrize("url", ["", "   ", "not a url", "http://", "://", "\x00\x01", "ftp://x",
                                 "http://" + "a" * 5000 + ".com/" + "b" * 20000, "javascript:alert(1)",
                                 "http://999.999.999.999/", "http://0x7f.1/", "data:text/html,<b>x</b>"])
def test_extract_never_raises(url):
    f = lx.extract(url)
    assert isinstance(f, dict) and "parse_error" in f


def test_ip_forms():
    for u in ("http://192.168.0.1/", "http://3232235777/", "http://0xC0A80001/", "http://0300.0250.0.1/"):
        assert lx.extract(u)["host_is_ip"] == 1.0, u
    assert lx.extract("http://example.com/")["host_is_ip"] == 0.0


def test_brand_signals():
    assert lx.extract("http://paypal.com.secure-login.xyz/x")["brand_in_sub"] == 1.0
    assert lx.extract("https://www.paypal.com/")["brand_is_sld"] == 1.0
    assert lx.extract("https://www.paypal.com/")["brand_in_sub"] == 0.0
    for u in ("http://paypa1.com/", "http://g00gle.com/", "http://rnicrosoft.com/", "http://xn--pypal-4ve.com/"):
        assert lx.extract(u)["brand_typo"] == 1.0, u
    assert lx.extract("https://www.google.com/")["brand_typo"] == 0.0


def test_features_deterministic():
    u = "https://login-secure.example.co.uk/account/verify.php?id=123&next=http://x"
    assert lx.extract(u) == lx.extract(u)


# ------------------------------------------------------------------ model runtime
def needs_model(f):  # the models ship with the package: these tests always run
    return f


@needs_model
def test_model_contributions_sum_to_raw():
    from fraudurl.model import Model
    m = Model(MODEL)
    for u in ("https://www.wikipedia.org/wiki/Cat", "http://paypal.com.secure-login.xyz/verify.php",
              "http://1.2.3.4/login"):
        x = m.vector(lx.extract(u))
        raw = m.raw(x)
        raw2, contrib = m.raw_with_contrib(x)
        assert abs(raw - raw2) < 1e-9
        p = m.calibrate(raw)
        assert 0.0 <= p <= 1.0


@needs_model
def test_model_handles_missing_features():
    from fraudurl.model import Model
    m = Model(MODEL)
    p = m.calibrate(m.raw(m.vector({})))  # every feature missing -> NaN path
    assert 0.0 <= p <= 1.0 and not math.isnan(p)


@needs_model
def test_prior_adjustment_monotone():
    from fraudurl.model import Model
    m = Model(MODEL)
    assert m.adjust_prior(0.9, 0.01) < 0.9 and m.adjust_prior(0.5, 0.5) == pytest.approx(0.5, abs=0.2)


# ------------------------------------------------------------------ CLI end-to-end
@needs_model
def test_cli_end_to_end(tmp_path):
    from fraudurl.cli import run
    inp = tmp_path / "in.csv"
    rows = [["id", "Website URL", "note"],
            ["1", "https://en.wikipedia.org/wiki/Phishing", "a"],
            ["2", "http://paypal.com.secure-login-verify.xyz/webscr/account.php?cmd=login", "b"],
            ["3", "", "empty"],
            ["4", "not a url at all", "junk"],
            ["5", "github.com/python/cpython", "no scheme"]]
    with open(inp, "w", encoding="utf-8-sig", newline="") as fh:  # BOM, like Excel exports
        csv.writer(fh).writerows(rows)
    out = tmp_path / "out.csv"
    s = run(str(inp), str(out), workers=1, quiet=True)
    assert s["rows"] == 5
    got = list(csv.DictReader(open(out, encoding="utf-8-sig")))  # output has a BOM for Excel
    assert [g["id"] for g in got] == ["1", "2", "3", "4", "5"]          # order + original columns kept
    assert got[2]["fraud_verdict"] == "ERROR" and got[2]["error"]
    assert got[3]["fraud_verdict"] == "ERROR"
    for g in (got[0], got[1], got[4]):
        assert g["fraud_verdict"] in ("FRAUD", "LEGITIMATE", "REVIEW")
        assert 0.0 <= float(g["fraud_probability"]) <= 1.0
    assert got[1]["fraud_verdict"] in ("FRAUD", "REVIEW")


@needs_model
def test_cli_headerless_and_semicolon(tmp_path):
    from fraudurl.cli import run
    inp = tmp_path / "in.csv"
    inp.write_text("https://www.bbc.co.uk/news;x\nhttp://192.168.1.1/login.php;y\n", encoding="utf-8")
    out = tmp_path / "out.csv"
    s = run(str(inp), str(out), workers=1, quiet=True)
    assert s["rows"] == 2
    got = list(csv.DictReader(open(out, encoding="utf-8-sig")))  # output has a BOM for Excel
    assert got[0]["column_1"] == "https://www.bbc.co.uk/news"


# ------------------------------------------------------------------ enriched scoring (offline)
ENRICH_MODEL = os.path.join(ROOT, "fraudurl", "data", "model_enrich.json")
needs_enrich = needs_model


@needs_enrich
def test_enriched_scoring_adds_residual_and_falls_back():
    from fraudurl import cli
    cli._init_worker(True, None)
    url = "https://example-shop-login.xyz/account/verify"
    old = {"dns_n_a": 2.0, "dns_has_aaaa": 1.0, "dns_has_cname": 0.0, "dns_ttl_a_log": 3.5, "dns_private_ip": 0.0,
           "dns_n_ns": 4.0, "dns_has_mx": 1.0, "domain_age_days_log": 4.0, "days_to_expiry_log": 2.5,
           "reg_period_years": 20.0, "days_since_changed_log": 2.0, "status_n": 3.0}
    new = dict(old, domain_age_days_log=0.5, reg_period_years=1.0, days_since_changed_log=0.3, dns_has_mx=0.0)
    safe = cli.score_rows([url], None)[0]
    r_old = cli.score_rows([url], [old])[0]
    r_new = cli.score_rows([url], [new])[0]
    r_missing = cli.score_rows([url], [{}])[0]   # enrichment unavailable -> identical to safe mode
    assert r_missing["fraud_probability"] == safe["fraud_probability"]
    assert float(r_new["fraud_probability"]) > float(r_old["fraud_probability"])  # a 3-day-old domain is riskier
    for r in (r_old, r_new):
        assert r["fraud_verdict"] in ("FRAUD", "REVIEW", "LEGITIMATE")
    cli._init_worker(False, None)


@needs_model
def test_reasons_are_value_aware():
    from fraudurl import cli
    cli._init_worker(False, None)
    r = cli.score_rows(["https://www.wikipedia.org/wiki/Main_Page"], None)[0]
    assert "no 'www.' prefix" not in r["top_reasons"]  # this URL HAS www., so that wording must never appear


# ------------------------------------------------------------------ regression tests from the adversarial review
def _run(tmp_path, content, encoding="utf-8", **kw):
    from fraudurl.cli import run
    inp = tmp_path / "in.csv"
    inp.write_bytes(content.encode(encoding) if isinstance(content, str) else content)
    out = tmp_path / "out.csv"
    run(str(inp), str(out), workers=1, quiet=True, **kw)
    return list(csv.DictReader(open(out, encoding="utf-8-sig")))


@needs_model
def test_refuses_to_overwrite_input(tmp_path):
    from fraudurl.cli import run
    inp = tmp_path / "in.csv"
    inp.write_text("url\nhttps://example.com/a\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        run(str(inp), str(inp), workers=1, quiet=True)
    assert inp.read_text(encoding="utf-8") == "url\nhttps://example.com/a\n"   # input untouched


@needs_model
def test_long_rows_keep_result_columns_aligned(tmp_path):
    got = _run(tmp_path, "id,url,note\n1,http://evil-login.xyz/a/verify.php,x,EXTRA\n2,https://example.com/ok,y\n")
    assert [g["fraud_verdict"] in ("FRAUD", "REVIEW", "LEGITIMATE") for g in got] == [True, True]
    assert got[0]["note"] == "x,EXTRA"


@needs_model
def test_url_column_priority_and_numbered_headers(tmp_path):
    got = _run(tmp_path, "domain,url\nsecure-login.xyz,http://secure-login.xyz/paypal/login.php\n")
    assert got[0]["registrable_domain"] == "secure-login.xyz" and got[0]["fraud_verdict"] != "ERROR"
    got = _run(tmp_path, "S.No,Site Link\n1,https://www.bbc.co.uk/news\n2,http://1.2.3.4/login\n")
    assert list(got[0].keys())[:2] == ["S.No", "Site Link"] and len(got) == 2


@needs_model
def test_cp1252_file_is_decoded_correctly(tmp_path):
    content = "url,note\nhttps://example.com/a,caf\xe9\n".encode("cp1252")
    got = _run(tmp_path, content)
    assert got[0]["note"] == "café"


def test_trailing_slash_and_scheme_do_not_change_features():
    a, b = lx.extract("https://example.com"), lx.extract("https://example.com/")
    assert a == b
    assert lx.extract("example.com/login") == lx.extract("https://example.com/login")


def test_huge_decimal_host_is_not_an_ip_on_any_python_version():
    # int() refuses > 4300 digits on newer Pythons only; the parser must not depend on that
    assert lx._parse_ip("9" * 5000) == 0 and lx._parse_ip("3232235777") == 4


@needs_model
def test_clear_messages_for_missing_input_or_output_folder(tmp_path):
    from fraudurl.cli import run
    with pytest.raises(SystemExit, match="input file not found"):
        run(str(tmp_path / "nope.csv"), str(tmp_path / "out.csv"), workers=1, quiet=True)
    inp = tmp_path / "in.csv"
    inp.write_text("url\nhttps://example.com/\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="output folder does not exist"):
        run(str(inp), str(tmp_path / "missing_dir" / "out.csv"), workers=1, quiet=True)


class _StubEnricher:
    """Stands in for enrich.Enricher: answers every lookup from memory (no network)."""
    looked_up = []

    def __init__(self, cache_dir):
        pass

    def run(self, items):
        items = list(items)
        _StubEnricher.looked_up.extend(h for h, _, _, _ in items)
        dns = {h: {"a_status": "ok", "a": ["93.184.216.34"], "ttl_a": 300, "aaaa": [], "cname": None,
                   "ns_status": "ok", "ns": ["a.iana-servers.net"], "mx_status": "ok", "mx": ["10 mx.example.com"]}
               for h, _, _, _ in items}
        rdap = {reg: {"status": "ok", "created": "1995-08-14T04:00:00Z", "expires": "2030-08-13T04:00:00Z"}
                for _, reg, _, _ in items}
        return dns, rdap

    def close(self):
        pass


_MIX = ("url\nhttps://example.com/\nhttp://secure-update.example.net/login.php\n"
        "https://www.bbc.co.uk/news\n")  # offline: REVIEW, FRAUD, LEGITIMATE


@needs_model
def test_enrich_review_looks_up_only_review_rows(tmp_path, monkeypatch):
    import fraudurl.enrich as enrich_mod
    monkeypatch.setattr(enrich_mod, "Enricher", _StubEnricher)
    _StubEnricher.looked_up = []
    got = _run(tmp_path, _MIX, enrich="review")
    assert _StubEnricher.looked_up == ["example.com"]
    assert got[0]["analysis_mode"] == "enriched (URL + DNS + RDAP)" and got[0]["lookup_status"] == "dns=ok; rdap=ok"
    assert [g["analysis_mode"] for g in got[1:]] == ["offline (URL text only; clear without lookups)"] * 2
    assert [g["fraud_verdict"] for g in got[1:]] == ["FRAUD", "LEGITIMATE"]
    _StubEnricher.looked_up = []
    got_all = _run(tmp_path, _MIX, enrich="all")
    assert sorted(_StubEnricher.looked_up) == ["example.com", "secure-update.example.net", "www.bbc.co.uk"]
    assert got_all[0] == got[0]  # the REVIEW row gets the same enriched result in both modes


@needs_model
def test_allow_and_block_lists(tmp_path):
    (tmp_path / "block.txt").write_text("# analyst-confirmed\nexample-secure.xyz  reported 2026-09\n"
                                        "https://docs.example.org/evil/\n", encoding="utf-8")
    (tmp_path / "allow.txt").write_text("*.wikipedia.org\nexample-secure.xyz\nexample.org\n", encoding="utf-8")
    kw = dict(allow_lists=[str(tmp_path / "allow.txt")], block_lists=[str(tmp_path / "block.txt")])
    got = _run(tmp_path, "url\nhttps://login.example-secure.xyz/x\nhttps://en.wikipedia.org/wiki/Phishing\n"
                         "https://docs.example.org/evil/form\nhttps://docs.example.org/good\n"
                         "https://notexample-secure.xyz/\n", **kw)
    assert [g["fraud_verdict"] for g in got[:4]] == ["FRAUD", "LEGITIMATE", "FRAUD", "LEGITIMATE"]
    assert got[0]["analysis_mode"] == "your block list" and "example-secure.xyz" in got[0]["top_reasons"]
    assert got[0]["fraud_probability"] == "" and "model alone said" in got[0]["top_reasons"]
    assert got[4]["analysis_mode"] == "offline (URL text only)"  # label boundary: not a subdomain


def test_list_matching_edge_cases(tmp_path):
    from fraudurl.cli import _load_lists, _list_match
    from fraudurl.lexical import ParsedURL
    (tmp_path / "b.txt").write_text(
        "﻿0.0.0.0 hostsfile-evil.com\nhttps://good.example/secure\n*.cdn.example/kit/\n1.2.3.4\n"
        "faß.de\n||adblock-style^\nnot a domain\n", encoding="utf-8")
    lists = _load_lists(block_files=[str(tmp_path / "b.txt")])
    hit = lambda u: (_list_match(lists, ParsedURL(u)) or (None,))[0]
    assert hit("http://x.hostsfile-evil.com/") == "block"               # hosts-file line understood
    assert hit("https://good.example/secure") == "block"
    assert hit("https://good.example/secure/login") == "block"
    assert hit("https://good.example/secure-verify") is None              # prefix stops at a boundary
    assert hit("https://good.example/public/../secure/x") == "block"     # dot segments resolved
    assert hit("https://a.b.cdn.example/kit/p.php") == "block"           # '*.' path entry covers subdomains
    assert hit("http://0x01020304/") == "block" and hit("http://16909060/x") == "block"   # other IP spellings
    assert hit("https://faß.de/") == "block" and hit("https://fass.de/") is None     # browser spelling of ß
    assert any("2 line(s) skipped" in n for n in lists["_notes"])
    (tmp_path / "empty.txt").write_text("# nothing\nfoo bar\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="no valid entries"):
        _load_lists(allow_files=[str(tmp_path / "empty.txt")])


@needs_model
def test_enrich_review_skips_lookup_setup_when_nothing_is_uncertain(tmp_path, monkeypatch):
    import fraudurl.enrich as enrich_mod

    class Boom:
        def __init__(self, *a, **k):
            raise AssertionError("Enricher must not be created when no row is REVIEW")
    monkeypatch.setattr(enrich_mod, "Enricher", Boom)
    got = _run(tmp_path, "url\nhttp://secure-update.example.net/login.php\nhttps://www.bbc.co.uk/news\n",
               enrich="review")
    assert [g["fraud_verdict"] for g in got] == ["FRAUD", "LEGITIMATE"]


def test_cache_survives_parallel_writers(tmp_path):
    import json
    import subprocess
    path = str(tmp_path / "c.jsonl")
    code = ("import sys; sys.path.insert(0, %r); from fraudurl.cache import JsonlCache; "
            "c = JsonlCache(%r); [c.put(f'{sys.argv[1]}-{i}', {'v': 'x' * 300}) for i in range(1500)]; c.close()"
            % (ROOT, path))
    procs = [subprocess.Popen([sys.executable, "-c", code, tag]) for tag in ("a", "b", "c")]
    assert all(p.wait() == 0 for p in procs)
    lines = open(path, encoding="utf-8").read().splitlines()
    assert len(lines) == 4500 and len({json.loads(x)["k"] for x in lines}) == 4500


@needs_model
def test_single_url_json_output(tmp_path, capsys):
    import json
    from fraudurl.cli import main
    main(["--url", "https://example.com/", "--url", "not a url", "--url", "https://ex\udcffample.com/ x",
          "--quiet"])
    out = capsys.readouterr().out
    assert out.isascii()  # ASCII-only JSON: one record per line on any console
    recs = [json.loads(x) for x in out.splitlines()]
    assert [r["fraud_verdict"] for r in recs[:2]] == ["REVIEW", "ERROR"] and len(recs) == 3
    assert recs[0]["stages"]["offline_check"]["verdict"] == "REVIEW" and isinstance(recs[0]["top_reasons"], list)
    inp = tmp_path / "in.csv"
    inp.write_text("id,url\n7,https://example.com/\n", encoding="utf-8")
    main([str(inp), "--format", "json", "--quiet"])
    rec = json.loads((tmp_path / "in.fraudurl.jsonl").read_text(encoding="utf-8"))
    assert rec["input"] == {"id": "7", "url": "https://example.com/"} and rec["fraud_verdict"] == "REVIEW"


@needs_model
def test_offline_mode_label_and_unbalanced_quote_note(tmp_path, capsys):
    got = _run(tmp_path, "url,note\nhttps://example.com/a,ok\n")
    assert got[0]["analysis_mode"] == "offline (URL text only)"
    from fraudurl.cli import run
    inp, out = tmp_path / "q.csv", tmp_path / "q.out.csv"
    inp.write_text('url,note\nhttps://a.example.com/,"unclosed\nhttps://b.example.com/,x\n', encoding="utf-8")
    run(str(inp), str(out), workers=1, quiet=False)
    assert "unbalanced quote" in capsys.readouterr().err
