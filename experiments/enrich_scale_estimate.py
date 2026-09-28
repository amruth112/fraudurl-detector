"""Estimate what `python -m fraudurl <1M-row csv> --enrich` would cost - WITHOUT any network access.

Nothing here talks to the network: a guard installed at import time makes every socket connect,
DNS resolution and urllib/http.client request raise immediately. Everything is derived from
  * the shipped code (fraudurl/enrich.py, fraudurl/cache.py, fraudurl/cli.py), read via inspect,
  * the 1M-URL scale-test input/output (.cache/tmp/scale_1000000.csv[.out.csv]),
  * the real enrichment cache (.cache/fraudurl_cache/*.jsonl, whose per-record timestamps record
    when two earlier 1,000-homepage --enrich runs stored each result), and
  * local measurements (JsonlCache load time / RAM on synthetic cache files, offline scoring).

Sections of the output JSON (results/benchmark/enrich_scale_estimate.json):
  code_facts        - what the enrichment path does, with constants read from the code
  workload_1m       - hosts / registrable domains the 1M file would look up, per RDAP registry, per chunk
  calibration       - the two real 1,000-homepage runs reconstructed from cache timestamps, vs the model
  timing_1m         - discrete-event simulation of the 8-thread pool + per-registry throttle, per chunk
  review_only       - same for "enrich only the REVIEW rows of a safe-mode run"
  rule_of_thumb     - time per 100k unique registrable domains
  memory            - JsonlCache load time and RAM per entry (synthetic caches, fresh process)
  failed_lookups    - what the output rows look like when DNS / RDAP fail (offline, stubbed enricher)
  output_size       - estimated growth of the output CSV from the extra status text
  risks, advice     - summary

Usage:  python experiments/enrich_scale_estimate.py
"""
from __future__ import annotations

# ------------------------------------------------------------------ network guard (must come first)
NET_GUARD = r'''
import socket as _s, urllib.request as _u, http.client as _h
class NetworkDisabled(ConnectionRefusedError):
    pass
def _blocked(*a, **k):
    raise NetworkDisabled("network access is disabled in enrich_scale_estimate.py")
_s.socket.connect = _blocked
_s.socket.connect_ex = _blocked
_s.create_connection = _blocked
_s.getaddrinfo = _blocked
_s.gethostbyname = _blocked
_h.HTTPConnection.connect = _blocked
_u.urlopen = _blocked
'''
exec(NET_GUARD)  # noqa: S102  (defines the guard in this process; children get the same text)

import csv  # noqa: E402
import gc  # noqa: E402
import heapq  # noqa: E402
import inspect  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import random  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
from collections import Counter  # noqa: E402
from concurrent.futures import ThreadPoolExecutor  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import psutil  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from fraudurl import cli  # noqa: E402
from fraudurl.enrich import Enricher, RdapClient, _dns_query, dns_lookup  # noqa: E402
from fraudurl.lexical import SHORTENERS, USER_CONTENT_HOSTS, ParsedURL  # noqa: E402

TMP = os.path.join(ROOT, ".cache", "tmp")
REAL_CACHE = os.path.join(ROOT, ".cache", "fraudurl_cache")
BOOT = os.path.join(REAL_CACHE, "rdap_bootstrap_dns.json")
SCALE_IN = os.path.join(TMP, "scale_1000000.csv")
SCALE_OUT = SCALE_IN + ".out.csv"
SCALE_JSON = os.path.join(ROOT, "results", "benchmark", "scale_1000000.json")
OUT_JSON = os.path.join(ROOT, "results", "benchmark", "enrich_scale_estimate.json")
SAMPLES = {"tranco_home_1000": os.path.join(TMP, "tranco_home_1000.csv"),
           "homepage_check_1000": os.path.join(TMP, "homepage_check_1000.csv")}
SEED = 0


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def r1(x, n=1):
    return None if x is None else round(float(x), n)


# ------------------------------------------------------------------ A. code facts
def code_facts():
    probe = os.path.join(TMP, "enrich_scale_probe")
    e = Enricher(probe, bootstrap_path=BOOT)  # bootstrap is read from disk; the guard blocks any download
    q_sig = inspect.signature(_dns_query).parameters
    facts = {
        "thread_pool_workers": e.workers,
        "rdap_min_interval_s_per_registry": e.rdap.min_interval,
        "rdap_max_requests_per_s_per_registry": round(1 / e.rdap.min_interval, 3),
        "rdap_timeout_s": e.rdap.timeout,
        "dns_cache_ttl_days": e.dns_cache.ttl / 86400,
        "rdap_cache_ttl_days": e.rdap_cache.ttl / 86400,
        "doh_servers": list(e.resolver),
        "doh_queries_per_host": inspect.getsource(dns_lookup).count("_dns_query("),
        "doh_query_timeout_s": q_sig["timeout"].default,
        "doh_attempts_per_query": q_sig["attempts"].default,
        "cli_chunk_rows": inspect.signature(cli.run).parameters["chunk"].default,
        "rdap_bootstrap_tlds": len(e.rdap._servers),
        "rdap_bootstrap_file": os.path.relpath(BOOT, ROOT),
    }
    # NB: Enricher.close() skips EMPTY caches (`if c:` is False because JsonlCache defines __len__), which leaves
    # the two empty files open on Windows; close them directly so the probe directory can be removed.
    facts["enricher_close_skips_empty_caches"] = not bool(e.dns_cache)
    e.dns_cache.close()
    e.rdap_cache.close()
    shutil.rmtree(probe, ignore_errors=True)
    facts["mechanics"] = {
        "per_unique_host (DNS, DoH to Cloudflare 1.1.1.1/1.0.0.1)":
            "4 sequential DoH GET queries in one job: A and AAAA for the host, NS and MX for the registrable domain "
            "(NS/MX skipped only when the host has no registrable domain). NS/MX are NOT de-duplicated per domain: "
            "two hosts on the same domain query its NS and MX twice. Each query: timeout 3 s, up to 3 attempts "
            "(alternating 1.1.1.1 / 1.0.0.1), persistent TLS connection per thread and server.",
        "per_unique_registrable_domain (RDAP)":
            "one GET <registry RDAP base>/domain/<domain>; the base URL comes from the IANA bootstrap file by the last "
            "label (TLD) only. No server for the TLD -> immediate 'no_rdap_server' (no request).",
        "skipped (no lookup at all)":
            "empty/whitespace values and values without a dotted host ('skipped (no domain)'); IP-address hosts "
            "('skipped (IP host)'); shared platforms (cli._platform): PSL private suffixes (e.g. *.github.io), "
            "USER_CONTENT_HOSTS (e.g. docs.google.com, blogspot.com) matched on host, registrable domain or suffix, and "
            "SHORTENERS (e.g. bit.ly) matched on host or registrable domain.",
        "thread_pool":
            "Enricher.run builds a NEW ThreadPoolExecutor(8) for every CLI chunk; all DNS jobs of the chunk are "
            "submitted first, then all RDAP jobs (set order, i.e. effectively random). DNS and RDAP share the 8 "
            "threads, so the RDAP phase of a chunk only starts when the DNS queue is drained, and the chunk ends "
            "only when its slowest lookup ends (barrier per chunk).",
        "rdap_throttle":
            "RdapClient._throttle: one lock per registry base URL; a thread takes the lock, sleeps until "
            "last_request + 0.5 s, stamps the time and releases it -> <= 2 requests/s per registry. Threads waiting for a "
            "busy registry's lock (or sleeping inside it) are blocked, so when one registry (Verisign .com) holds a large "
            "share of the queue, most of the 8 threads end up queued on its lock and the whole pool advances at that "
            "registry's 2 req/s.",
        "rdap_429_and_errors":
            "HTTP 429: sleep Retry-After seconds (numeric) or 5 s, capped at 15 s, while still occupying the thread, "
            "then retry through the throttle again; 3 attempts total, then status 'http_429'. Other HTTP errors -> "
            "'http_<code>' immediately (404 -> 'not_found'). Network errors/timeouts (8 s): 2 attempts, then "
            "'error:<Type>'. The final 'rate_limited' return is unreachable with the current loop.",
        "caching":
            "JsonlCache: whole JSONL file loaded into a dict at start; each new result appended + flushed immediately. "
            "DNS cached 7 days for a_status ok/nodata/nxdomain/servfail/refused/bad_name (timeouts/errors NOT cached); "
            "RDAP cached 28 days for ok/not_found/no_rdap_server (429, 403, 5xx, timeouts, bad JSON NOT cached). "
            "Expired or failed keys are looked up again and appended again (file only grows, never compacted).",
        "chunking":
            "the CLI reads 20,000 rows, enriches them in the MAIN process (the 4 scoring worker processes are idle "
            "meanwhile), then scores the chunk in the process pool and writes it. A host/domain seen in an earlier chunk "
            "is a cache hit; one whose lookup FAILED is looked up again in every later chunk that contains it. No "
            "progress callback is passed to Enricher.run, so the progress line only moves once per finished chunk.",
        "resume_after_interrupt":
            "the cache persists (every successful result is flushed as it is collected), so a re-run skips everything "
            "already cached; the OUTPUT file is reopened with 'w' and restarts from row 1 (re-scoring is fast). Results "
            "of lookups still queued or finished-but-not-yet-collected when the run stops are lost. On an exception "
            "inside the chunk loop the `with ThreadPoolExecutor` exit still waits for every queued lookup of the chunk "
            "(see executor_exit_demo) and those results are not written to the cache.",
    }
    return facts


def executor_exit_demo():
    """Show that leaving `with ThreadPoolExecutor(...)` via an exception waits for ALL queued jobs."""
    n_jobs, d, w = 64, 0.25, 8
    t0 = time.perf_counter()
    try:
        with ThreadPoolExecutor(max_workers=w) as ex:
            futs = [ex.submit(time.sleep, d) for _ in range(n_jobs)]
            for f in futs:
                f.result()
                raise RuntimeError("simulated interrupt after the first result")
    except RuntimeError:
        pass
    return {"jobs": n_jobs, "job_seconds": d, "workers": w,
            "seconds_until_with_block_exited": round(time.perf_counter() - t0, 2),
            "seconds_if_it_stopped_immediately": d, "seconds_if_all_jobs_run": n_jobs * d / w}


# ------------------------------------------------------------------ B. workload
def classify(u):
    """Mirror of cli._enrich_chunk + Enricher.run skip logic. Returns a tuple."""
    s = "" if u is None else str(u)
    if not u or any(c.isspace() for c in s.strip()):
        return ("no_domain",)
    try:
        p = ParsedURL(s)
    except Exception:  # noqa: BLE001
        return ("no_domain",)
    if not (p.host and ("." in p.host or p.ip)):
        return ("no_domain",)
    if p.ip:
        return ("ip",)
    if cli._platform(p):
        if p.private_suffix:
            why = "psl_private_suffix"
        elif p.host in SHORTENERS or p.reg in SHORTENERS:
            why = "shortener"
        else:
            why = "user_content_host"
        return ("platform", why)
    return ("lookup", p.host, p.reg or "")


def workload(urls, parsed, rc, chunk, rng):
    """Replicates what the CLI would submit, chunk by chunk, assuming every lookup succeeds (and is cached)."""
    rows = Counter()
    platform_why = Counter()
    seen_h, seen_r = set(), set()
    chunks = []
    reg_chunk_appearances = 0
    for c0 in range(0, len(urls), chunk):
        new_h, new_r, regs_here = {}, set(), set()
        for u in urls[c0:c0 + chunk]:
            k = parsed[u]
            rows[k[0]] += 1
            if k[0] == "platform":
                platform_why[k[1]] += 1
            if k[0] != "lookup":
                continue
            h, g = k[1], k[2]
            if h not in seen_h and h not in new_h:
                new_h[h] = g
            if g:
                regs_here.add(g)
                if g not in seen_r:
                    new_r.add(g)
        reg_chunk_appearances += len(regs_here)
        seen_h.update(new_h)
        seen_r.update(new_r)
        rlist = sorted(new_r)
        rng.shuffle(rlist)  # set iteration order in the real run is effectively random
        chunks.append({"rows": min(chunk, len(urls) - c0),
                       "dns_nq": [4 if g else 2 for g in new_h.values()],
                       "rdap_bases": [rc.server_for(g) for g in rlist]})
    n_h = len(seen_h)
    host_regs = {}
    for u in set(urls):
        k = parsed[u]
        if k[0] == "lookup":
            host_regs[k[1]] = k[2]
    hosts_no_reg = sum(1 for g in host_regs.values() if not g)
    base = Counter(rc.server_for(g) for g in seen_r)
    nosrv_tld = Counter(g.rsplit(".", 1)[-1] for g in seen_r if rc.server_for(g) is None)
    doh = 4 * (n_h - hosts_no_reg) + 2 * hosts_no_reg
    return {
        "rows": len(urls),
        "rows_by_enrichment_path": {"lookup": rows["lookup"], "skipped_platform": rows["platform"],
                                    "skipped_ip_host": rows["ip"], "skipped_no_domain": rows["no_domain"]},
        "platform_rows_by_reason": dict(platform_why),
        "unique_hosts_dns_jobs": n_h,
        "hosts_without_registrable_domain": hosts_no_reg,
        "unique_registrable_domains_rdap_jobs": len(seen_r),
        "doh_queries_total": doh,
        "redundant_ns_mx_queries_(same_domain_queried_again_for_another_host)": 2 * ((n_h - hosts_no_reg) - len(seen_r)),
        "rdap_domains_per_registry_top15": [{"rdap_base": b, "domains": n, "share": round(n / len(seen_r), 4)}
                                            for b, n in base.most_common() if b][:15],
        "rdap_registries_used": sum(1 for b in base if b),
        "rdap_domains_with_rdap_server": sum(n for b, n in base.items() if b),
        "rdap_domains_without_rdap_server": base.get(None, 0),
        "no_rdap_server_top_tlds": dict(nosrv_tld.most_common(12)),
        "domain_chunk_appearances": reg_chunk_appearances,
        "_chunks": chunks,
        "_busiest": max((b for b in base if b), key=base.get),
        "_base_counts": base,
    }


# ------------------------------------------------------------------ C/D. discrete-event model of Enricher.run
def simulate_chunk(dns_nq, rdap_bases, q, R, interval=0.5, threads=8, rng=None,
                   p429=0.0, p429_bases=None, retry_after=5.0, dead_bases=(), rdap_timeout=8.0,
                   p_dns_fail=0.0, dns_fail_s=9.0):
    """Faithful to the code's structure: FIFO queue (DNS jobs then RDAP jobs), `threads` workers, per-registry
    throttle slot = max(arrival, last + interval) taken in arrival order (the lock is held while sleeping),
    429 -> sleep retry_after and go through the throttle again (3 attempts), network timeout -> 2 attempts.
    q = seconds per DoH query, R = seconds per RDAP HTTP request. Returns (seconds, stats)."""
    ev, seq = [], 0
    jobs = [("d", n) for n in dns_nq] + [("r", b) for b in rdap_bases]
    ji = 0
    last = {}
    wait_total = 0.0
    n429_final = 0
    n_dead_final = 0

    def push(t, kind, data):
        nonlocal seq
        heapq.heappush(ev, (t, seq, kind, data))
        seq += 1

    for _ in range(threads):
        push(0.0, "free", None)
    end = 0.0
    while ev:
        t, _, kind, data = heapq.heappop(ev)
        end = max(end, t)
        if kind == "free":
            if ji >= len(jobs):
                continue
            jk, jv = jobs[ji]
            ji += 1
            if jk == "d":
                dur = 0.0
                for _q in range(jv):
                    dur += dns_fail_s if (p_dns_fail and rng.random() < p_dns_fail) else q
                push(t + dur, "free", None)
            elif jv is None:
                push(t, "free", None)  # no RDAP server for the TLD: instant
            else:
                push(t, "arrive", (jv, 0))
        elif kind == "arrive":
            base, attempt = data
            slot = max(t, last.get(base, -1e18) + interval)
            last[base] = slot
            wait_total += slot - t
            if base in dead_bases:
                t2 = slot + rdap_timeout
                if attempt < 1:
                    push(t2, "arrive", (base, attempt + 1))
                else:
                    n_dead_final += 1
                    push(t2, "free", None)
            elif p429 and (p429_bases is None or base in p429_bases) and rng.random() < p429:
                if attempt < 2:
                    push(slot + R + retry_after, "arrive", (base, attempt + 1))
                else:
                    n429_final += 1
                    push(slot + R, "free", None)
            else:
                push(slot + R, "free", None)
    return end, {"throttle_wait_thread_s": wait_total, "rdap_http_429_final": n429_final,
                 "rdap_timeout_final": n_dead_final}


def simulate_run(chunks, score_rate, **kw):
    per_chunk, tot, waits, f429, fdead = [], 0.0, 0.0, 0, 0
    rng = random.Random(SEED)
    for c in chunks:
        s, st = simulate_chunk(c["dns_nq"], c["rdap_bases"], rng=rng, **kw)
        s += c["rows"] / score_rate
        per_chunk.append(s)
        tot += s
        waits += st["throttle_wait_thread_s"]
        f429 += st["rdap_http_429_final"]
        fdead += st["rdap_timeout_final"]
    threads = kw.get("threads", 8)
    return {"hours": r1(tot / 3600, 2), "seconds": r1(tot, 0),
            "first_chunk_minutes": r1(per_chunk[0] / 60, 1),
            "median_chunk_minutes": r1(float(np.median(per_chunk)) / 60, 1),
            "last_chunk_minutes": r1(per_chunk[-1] / 60, 1),
            "share_of_thread_time_blocked_on_rdap_throttle": r1(waits / (threads * tot), 3),
            "rdap_domains_ending_http_429": f429, "rdap_domains_ending_timeout": fdead}


def analytic_bounds(chunks, q, interval=0.5, threads=8):
    """Per chunk: DNS phase >= total DoH queries * q / threads; RDAP phase >= busiest registry * interval."""
    dns, rd = 0.0, 0.0
    all_bases = Counter()
    for c in chunks:
        dns += sum(c["dns_nq"]) * q / threads
        cnt = Counter(b for b in c["rdap_bases"] if b)
        rd += (max(cnt.values()) if cnt else 0) * interval
        all_bases.update(cnt)
    return {"dns_phase_hours": r1(dns / 3600, 2), "rdap_phase_hours_sum_of_per_chunk_busiest_registry": r1(rd / 3600, 2),
            "rdap_hours_if_no_chunk_barriers_(busiest_registry_total_x_interval)":
                r1(max(all_bases.values()) * interval / 3600, 2)}


# ------------------------------------------------------------------ C. calibration against real runs
def calibration(rc, score_rate):
    recs = {}
    for kind in ("dns", "rdap"):
        with open(os.path.join(REAL_CACHE, f"{kind}.jsonl"), encoding="utf-8") as fh:
            recs[kind] = [json.loads(ln) for ln in fh]
    allt = sorted(r["t"] for k in recs for r in recs[k])
    sessions = [[allt[0], allt[0]]]
    for t in allt[1:]:
        if t - sessions[-1][1] > 120:
            sessions.append([t, t])
        else:
            sessions[-1][1] = t
    out = {"cache_sessions_found": len(sessions),
           "method": "put timestamps ('t') in .cache/fraudurl_cache/{dns,rdap}.jsonl; a session = puts with gaps < 120 s. "
                     "Puts happen in submission order in the main thread, so the last DNS put ~ end of the DNS phase "
                     "and the last RDAP put ~ end of the run's lookups.",
           "runs": []}
    for name, path in SAMPLES.items():
        urls = pd.read_csv(path, dtype=str, keep_default_na=False).url.tolist()
        ks = [classify(u) for u in urls]
        hosts = {k[1]: k[2] for k in ks if k[0] == "lookup"}
        regs = {k[2] for k in ks if k[0] == "lookup" and k[2]}
        dt = {r["k"]: r["t"] for r in recs["dns"]}
        rt = {r["k"]: r["t"] for r in recs["rdap"]}
        best = max(range(len(sessions)), key=lambda i: sum(sessions[i][0] <= dt.get(h, -1) <= sessions[i][1] for h in hosts))
        s0, s1 = sessions[best]
        cached_before_h = [h for h in hosts if dt.get(h, 1e30) < s0]
        cached_before_r = [g for g in regs if rt.get(g, 1e30) < s0]
        before = set(cached_before_h)
        new_h = [h for h in hosts if h not in before]
        new_r = sorted(set(regs) - set(cached_before_r))
        dns_t = sorted(dt[h] for h in new_h if h in dt and s0 <= dt[h] <= s1)
        rdap_t = sorted(rt[g] for g in new_r if g in rt and s0 <= rt[g] <= s1)
        base = Counter(rc.server_for(g) for g in new_r)
        busiest, n_busy = max(((b, n) for b, n in base.items() if b), key=lambda x: x[1])
        com_t = np.array(sorted(rt[g] for g in new_r if g in rt and rc.server_for(g) == busiest))
        nq = sum(4 if hosts[h] else 2 for h in new_h)
        dns_span = dns_t[-1] - dns_t[0]
        q_eff = dns_span * 8 / nq
        total_span = rdap_t[-1] - dns_t[0]
        rng = random.Random(SEED)
        rl = list(new_r)
        rng.shuffle(rl)
        dns_nq = [4 if hosts[h] else 2 for h in new_h]
        sims = {}
        for R in (0.3, 1.0):
            s, _ = simulate_chunk(dns_nq, [rc.server_for(g) for g in rl], q=q_eff, R=R, rng=rng)
            sims[f"R={R}s"] = r1(s)
        out["runs"].append({
            "sample_file": os.path.relpath(path, ROOT),
            "session_start_local": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s0)),
            "hosts_looked_up": len(new_h), "hosts_already_cached_from_earlier_run": len(cached_before_h),
            "domains_looked_up": len(new_r), "domains_already_cached": len(cached_before_r),
            "domains_looked_up_but_not_in_cache_(failed/uncached_status)": len(new_r) - len(rdap_t),
            "domains_per_registry_top5": [{"rdap_base": b, "domains": n} for b, n in base.most_common(6) if b][:5],
            "domains_without_rdap_server": base.get(None, 0),
            "busiest_registry": busiest, "busiest_registry_domains": n_busy,
            "busiest_x_0.5s": n_busy * 0.5,
            "measured_dns_phase_s_(first_to_last_dns_put)": r1(dns_span),
            "measured_rdap_phase_s_(last_dns_put_to_last_rdap_put)": r1(rdap_t[-1] - dns_t[-1]),
            "measured_lookup_span_s_(first_dns_put_to_last_rdap_put)": r1(total_span),
            "busiest_registry_put_gap_median_s": r1(float(np.median(np.diff(com_t))), 3),
            "busiest_registry_put_slope_s_per_domain_(lstsq)": r1(float(np.polyfit(np.arange(len(com_t)), com_t, 1)[0]), 3),
            "effective_s_per_doh_query_(dns_span*8/queries)": r1(q_eff, 3),
            "model_predicted_lookup_seconds": sims,
        })
    out["reported_wall_seconds_(task brief, not in a result file)"] = "241-289 s for the cold-cache 1,000-homepage --enrich runs"
    return out


# ------------------------------------------------------------------ E. memory of JsonlCache
MEM_CHILD = NET_GUARD + r'''
import gc, json, sys, time, psutil
ARGS = json.loads(sys.argv[1])
sys.path.insert(0, ARGS["root"])
from fraudurl.cache import JsonlCache
proc = psutil.Process()
gc.collect()
r0 = proc.memory_info().rss
t = time.perf_counter()
caches = [JsonlCache(p, ARGS["ttl_days"]) for p in ARGS["paths"]]
dt = time.perf_counter() - t
gc.collect()
mi = proc.memory_info()
print(json.dumps({"entries": [len(c) for c in caches], "load_s": dt, "rss_before": r0, "rss_after": mi.rss,
                  "peak_working_set": getattr(mi, "peak_wset", None)}))
'''


MEM_PUT_CHILD = NET_GUARD + r'''
import gc, json, sys, time, psutil
ARGS = json.loads(sys.argv[1])
sys.path.insert(0, ARGS["root"])
from fraudurl.cache import JsonlCache
intern = sys.intern
def dns_v(v):  # same shape as enrich.dns_lookup(): constant keys, fresh value objects
    return {"a_status": intern(v["a_status"]), "a": v["a"], "ttl_a": v["ttl_a"], "aaaa": v["aaaa"], "cname": v["cname"],
            "ns_status": intern(v["ns_status"]), "ns": v["ns"], "mx_status": intern(v["mx_status"]), "mx": v["mx"],
            "resolver": "doh:" + v["resolver"][4:]}
def rdap_v(v):  # same shape as RdapClient.lookup()
    if v.get("status") != "ok":
        return {"status": intern(v["status"])}
    return {"status": "ok", "created": v.get("created"), "expires": v.get("expires"), "changed": v.get("changed"),
            "registrar": v.get("registrar"), "registrar_iana": v.get("registrar_iana"),
            "domain_status": v.get("domain_status"), "ns": v.get("ns")}
proc = psutil.Process()
gc.collect()
r0 = proc.memory_info().rss
t = time.perf_counter()
caches = []
for p, kind in zip(ARGS["paths"], ARGS["kinds"]):
    c = JsonlCache(None, ARGS["ttl_days"])  # in-memory only, no file
    f = dns_v if kind == "dns" else rdap_v
    with open(p, encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            c.put(rec["k"], f(rec["v"]))
    caches.append(c)
dt = time.perf_counter() - t
gc.collect()
mi = proc.memory_info()
print(json.dumps({"entries": [len(c) for c in caches], "load_s": dt, "rss_before": r0, "rss_after": mi.rss,
                  "peak_working_set": getattr(mi, "peak_wset", None)}))
'''


def measure_put(paths, kinds, repeats=2):
    args = json.dumps({"root": ROOT, "paths": paths, "kinds": kinds, "ttl_days": 7.0})
    runs = []
    for _ in range(repeats):
        p = subprocess.run([sys.executable, "-c", MEM_PUT_CHILD, args], capture_output=True, text=True, check=True)
        runs.append(json.loads(p.stdout.strip().splitlines()[-1]))
    return runs


def write_synthetic(path, n, sample_values, keys, rng):
    now = time.time()
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(n):
            p, j = divmod(i, len(keys))
            k = keys[j] if p == 0 else f"{p}{keys[j]}"  # extra passes: 1-2 char prefix keeps key lengths realistic
            rec = {"k": k, "t": now, "v": sample_values[rng.randrange(len(sample_values))]}
            fh.write(json.dumps(rec, separators=(",", ":"), default=str) + "\n")  # same as JsonlCache.put
    return os.path.getsize(path)


def measure_load(paths, repeats=2):
    args = json.dumps({"root": ROOT, "paths": paths, "ttl_days": 7.0})
    runs = []
    for _ in range(repeats):
        p = subprocess.run([sys.executable, "-c", MEM_CHILD, args], capture_output=True, text=True, check=True)
        runs.append(json.loads(p.stdout.strip().splitlines()[-1]))
    return runs


def memory_section(hosts, regs, n_hosts_1m, n_regs_1m):
    rng = random.Random(SEED)
    real = {}
    for kind in ("dns", "rdap"):
        with open(os.path.join(REAL_CACHE, f"{kind}.jsonl"), encoding="utf-8") as fh:
            lines = fh.readlines()
        real[kind] = {"values": [json.loads(ln)["v"] for ln in lines],
                      "real_bytes_per_line": sum(len(ln.encode("utf-8")) for ln in lines) / len(lines),
                      "real_lines": len(lines)}
    d = os.path.join(TMP, "enrich_scale_synth")
    os.makedirs(d, exist_ok=True)
    res = {"method": "synthetic JSONL written exactly like JsonlCache.put, values sampled (with replacement, seed 0) from "
                     "the real .cache/fraudurl_cache records, keys = real hosts / registrable domains of the 1M file "
                     "(1-2 char numeric prefix once the real keys run out); loaded with fraudurl.cache.JsonlCache in a "
                     "fresh python process; RSS measured with psutil before/after (gc.collect() both times); 2 runs each.",
           "real_cache_records": {k: {"lines": v["real_lines"], "bytes_per_line": r1(v["real_bytes_per_line"])}
                                  for k, v in real.items()},
           "per_file": [], "projected_1m_run": None}
    try:
        for kind, keys in (("dns", hosts), ("rdap", regs)):
            for n in (100_000, 1_000_000):
                path = os.path.join(d, f"{kind}_{n}.jsonl")
                size = write_synthetic(path, n, real[kind]["values"], keys, rng)
                runs = measure_load([path])
                inc = [x["rss_after"] - x["rss_before"] for x in runs]
                res["per_file"].append({
                    "cache": kind, "entries": n, "bytes_on_disk": size, "bytes_on_disk_per_entry": r1(size / n),
                    "load_seconds": [r1(x["load_s"], 2) for x in runs],
                    "rss_increase_MB": [r1(v / 1e6) for v in inc],
                    "rss_bytes_per_entry": r1(float(np.mean(inc)) / n, 0),
                    "process_rss_after_load_MB": [r1(x["rss_after"] / 1e6) for x in runs],
                    "process_peak_working_set_MB": [r1((x["peak_working_set"] or 0) / 1e6) for x in runs],
                })
                os.remove(path)
                log(f"  memory {kind} {n:,}: {res['per_file'][-1]}")
        # both caches at the exact size the 1M-URL run would leave behind, loaded together (start of a re-run)
        pd_ = os.path.join(d, "dns_proj.jsonl")
        pr_ = os.path.join(d, "rdap_proj.jsonl")
        s1 = write_synthetic(pd_, n_hosts_1m, real["dns"]["values"], hosts, rng)
        s2 = write_synthetic(pr_, n_regs_1m, real["rdap"]["values"], regs, rng)
        runs = measure_load([pd_, pr_])
        inc = [x["rss_after"] - x["rss_before"] for x in runs]
        pruns = measure_put([pd_, pr_], ["dns", "rdap"])
        pinc = [x["rss_after"] - x["rss_before"] for x in pruns]
        res["projected_1m_run"] = {
            "dns_entries": n_hosts_1m, "rdap_entries": n_regs_1m,
            "cache_bytes_on_disk_MB": r1((s1 + s2) / 1e6), "load_seconds": [r1(x["load_s"], 2) for x in runs],
            "rss_increase_MB_both_caches": [r1(v / 1e6) for v in inc],
            "rss_increase_MB_both_caches_built_by_put_(first_run)": [r1(v / 1e6) for v in pinc],
            "note": "measured, not extrapolated: both caches at the 1M run's final size in one fresh process. "
                    "'rss_increase_MB_both_caches' = loading the JSONL files with JsonlCache (start of a re-run / resumed "
                    "run; json.loads makes fresh key strings for every record). '..._built_by_put' = the same records "
                    "inserted with JsonlCache.put() using the dict shapes and constant keys of dns_lookup()/RdapClient."
                    "lookup() (what the first run accumulates by its end)."}
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return res


# ------------------------------------------------------------------ F. failed lookups: what the output rows look like
class StubEnricher:
    """Offline stand-in for Enricher: returns prepared lookup results instead of doing network lookups."""

    def __init__(self, dns_r, rdap_r):
        self.dns_r, self.rdap_r = dns_r, rdap_r

    def run(self, items, progress=None):
        return self.dns_r, self.rdap_r


def failed_lookups_section():
    path = SAMPLES["homepage_check_1000"]
    urls = pd.read_csv(path, dtype=str, keep_default_na=False).url.tolist()
    real = {}
    for kind in ("dns", "rdap"):
        with open(os.path.join(REAL_CACHE, f"{kind}.jsonl"), encoding="utf-8") as fh:
            real[kind] = {r["k"]: r["v"] for r in map(json.loads, fh)}
    cli._init_worker(True, None)
    scen = {
        "as_cached (real DNS+RDAP results from the cache)": (real["dns"], real["rdap"]),
        "RDAP failed for every domain (http_429, DNS as cached)": (real["dns"], {k: {"status": "http_429"} for k in real["rdap"]}),
        "DNS timed out for every host (RDAP as cached)": ({k: {"a_status": "timeout"} for k in real["dns"]}, real["rdap"]),
    }
    out = {"sample": os.path.relpath(path, ROOT) + " (1,000 legitimate Tranco homepages)",
           "method": "cli._enrich_chunk with an offline stub enricher, then cli.score_rows with the shipped enrich model "
                     "(no --base-rate), exactly as cli.run.flush does",
           "scenarios": {}}
    for name, (d, r) in scen.items():
        feats, status = cli._enrich_chunk(StubEnricher(d, r), urls)
        modes = ["enriched (URL + DNS + RDAP)" if e else "safe (enrichment unavailable for this URL)" for e in feats]
        res = cli.score_rows(urls, feats)
        out["scenarios"][name] = {
            "verdicts": dict(Counter(x["fraud_verdict"] for x in res)),
            "analysis_mode": dict(Counter(modes)),
            "lookup_status_top5": dict(Counter(status).most_common(5)),
        }
    # cross-check the 'as cached' scenario against the real enriched output file of that run
    enr = os.path.join(TMP, "homepage_check_1000.enrich.csv")
    if os.path.exists(enr):
        o = pd.read_csv(enr, encoding="utf-8-sig", keep_default_na=False)
        out["real_run_output_file_verdicts"] = o.fraud_verdict.value_counts().to_dict()
    base = out["scenarios"]["as_cached (real DNS+RDAP results from the cache)"]["verdicts"]
    fail = out["scenarios"]["RDAP failed for every domain (http_429, DNS as cached)"]["verdicts"]
    out["reading"] = (f"A transient RDAP failure (429/timeout) does NOT fall back to safe mode: the row is still labelled "
                      f"'enriched (URL + DNS + RDAP)' with lookup_status 'dns=ok; rdap=http_429', and the enrich model scores "
                      f"it with rdap_ok=0 and every RDAP feature missing - the same encoding as a TLD without RDAP. On these "
                      f"1,000 legitimate homepages that moves LEGITIMATE {base.get('LEGITIMATE', 0)} -> "
                      f"{fail.get('LEGITIMATE', 0)} and FRAUD {base.get('FRAUD', 0)} -> {fail.get('FRAUD', 0)}. A DNS "
                      f"failure falls back to the safe model and says so in analysis_mode.")
    return out


# ------------------------------------------------------------------ H. output size growth
def output_size_section(urls, parsed, rc):
    from functools import lru_cache

    @lru_cache(maxsize=None)
    def enc(s):
        b = io.StringIO()
        csv.writer(b).writerow([s])
        return len(b.getvalue().encode("utf-8")) - 2  # minus the \r\n
    safe_mode = enc("safe (URL text only)")
    plat = "skipped (shared hosting platform: domain data would describe the platform, not this page)"
    add = 0
    for u in urls:
        k = parsed[u]
        if k[0] == "lookup":
            rd = "ok" if (k[2] and rc.server_for(k[2])) else ("no_rdap_server" if k[2] else "unavailable")
            add += enc("enriched (URL + DNS + RDAP)") - safe_mode + enc(f"dns=ok; rdap={rd}")
        else:
            st = {"platform": plat, "ip": "skipped (IP host)", "no_domain": "skipped (no domain)"}[k[0]]
            add += enc("safe (enrichment unavailable for this URL)") - safe_mode + enc(st)
    return add


# ------------------------------------------------------------------ main
def main():
    t_start = time.time()
    scale = json.load(open(SCALE_JSON, encoding="utf-8"))
    score_rate = scale["urls_per_second"]
    rc = RdapClient(BOOT, allow_bootstrap_download=False)
    out = {"what": "estimate of `python -m fraudurl <1,000,000-row csv> --enrich` (default settings), made WITHOUT any "
                   "network access (sockets/DNS/urllib blocked in this process)",
           "inputs": {"scale_input": os.path.relpath(SCALE_IN, ROOT), "scale_output": os.path.relpath(SCALE_OUT, ROOT),
                      "scale_result": os.path.relpath(SCALE_JSON, ROOT),
                      "safe_mode_measured": {k: scale[k] for k in ("seconds", "urls_per_second", "peak_rss_MB_process_tree",
                                                                   "input_bytes", "output_bytes", "verdicts")}}}
    log("A. code facts")
    out["code_facts"] = code_facts()
    out["code_facts"]["executor_exit_demo"] = executor_exit_demo()
    chunk = out["code_facts"]["cli_chunk_rows"]
    interval = out["code_facts"]["rdap_min_interval_s_per_registry"]
    threads = out["code_facts"]["thread_pool_workers"]

    log("B. workload of the 1M file")
    df = pd.read_csv(SCALE_IN, dtype=str, keep_default_na=False, usecols=["url"])
    urls = df.url.tolist()
    t = time.time()
    parsed = {u: classify(u) for u in set(urls)}
    log(f"  parsed {len(parsed):,} unique URLs in {time.time() - t:.0f}s")
    wl = workload(urls, parsed, rc, chunk, random.Random(SEED))
    busiest = wl.pop("_busiest")
    base_counts = wl.pop("_base_counts")
    chunks = wl.pop("_chunks")
    wl["chunks"] = len(chunks)
    wl["per_chunk_new_hosts_first_median_last"] = [len(chunks[0]["dns_nq"]), int(np.median([len(c["dns_nq"]) for c in chunks])),
                                                   len(chunks[-1]["dns_nq"])]
    wl["per_chunk_new_domains_first_median_last"] = [len(chunks[0]["rdap_bases"]),
                                                     int(np.median([len(c["rdap_bases"]) for c in chunks])),
                                                     len(chunks[-1]["rdap_bases"])]
    wl["per_chunk_busiest_registry_domains_first_median_last"] = [
        sum(b == busiest for b in chunks[0]["rdap_bases"]),
        int(np.median([sum(b == busiest for b in c["rdap_bases"]) for c in chunks])),
        sum(b == busiest for b in chunks[-1]["rdap_bases"])]
    wl["busiest_registry"] = busiest
    wl["note"] = ("counts assume every lookup succeeds and is cached; a domain whose RDAP lookup keeps failing is retried "
                  "in every chunk it appears in (domain_chunk_appearances is that upper bound)")
    out["workload_1m"] = wl
    log(f"  hosts {wl['unique_hosts_dns_jobs']:,}  domains {wl['unique_registrable_domains_rdap_jobs']:,}  busiest {busiest}")

    log("C. calibration against the real 1,000-homepage runs")
    out["calibration"] = calibration(rc, score_rate)
    q_meas = sorted(r["effective_s_per_doh_query_(dns_span*8/queries)"] for r in out["calibration"]["runs"])

    log("D. timing model for the 1M file")
    scen = {
        "optimistic: 20 ms/DoH query, 0.3 s/RDAP request": dict(q=0.02, R=0.3),
        f"central: {q_meas[0] * 1000:.0f} ms/DoH query (faster measured run), 0.3 s/RDAP request": dict(q=q_meas[0], R=0.3),
        f"slow: {q_meas[-1] * 1000:.0f} ms/DoH query (slower measured run), 1.0 s/RDAP request": dict(q=q_meas[-1], R=1.0),
    }
    tm = {"assumptions": {
        "doh_query_seconds": "ASSUMPTION range 0.02-0.08 s per DoH query (cannot be measured offline); the two earlier real "
                             f"runs imply an effective {q_meas[0]:.3f}-{q_meas[-1]:.3f} s per query on the development "
                             "network (see calibration)",
        "rdap_request_seconds": "ASSUMPTION 0.3 or 1.0 s per RDAP HTTP request; matters little because the throttle binds",
        "rdap_interval_s": interval, "threads": threads,
        "scoring": f"{score_rate} URLs/s per chunk (measured safe-mode throughput; enrich-model scoring cost not measured)",
        "failures": "none in the base scenarios (every lookup answers once)"},
        "analytic_lower_bounds": {}, "simulated": {}, "failure_scenarios": {}}
    for name, kw in scen.items():
        tm["analytic_lower_bounds"][name] = analytic_bounds(chunks, kw["q"], interval, threads)
        tm["simulated"][name] = simulate_run(chunks, score_rate, interval=interval, threads=threads, **kw)
        log(f"  {name}: {tm['simulated'][name]}")
    cq = q_meas[0]
    fails = {
        "Verisign .com answers 429 to 5% of requests (Retry-After 5 s)":
            dict(q=cq, R=0.3, p429=0.05, p429_bases={busiest}),
        "Verisign .com answers 429 to 50% of requests (Retry-After 5 s)":
            dict(q=cq, R=0.3, p429=0.5, p429_bases={busiest}),
        "Verisign .com answers 429 to every request (sustained rate limit)":
            dict(q=cq, R=0.3, p429=1.0, p429_bases={busiest}),
        "Verisign .com RDAP stops answering (every request times out after 8 s)":
            dict(q=cq, R=0.3, dead_bases={busiest}),
        "DoH degraded: 5% of queries time out on all 3 attempts (9 s)":
            dict(q=cq, R=0.3, p_dns_fail=0.05),
    }
    for name, kw in fails.items():
        tm["failure_scenarios"][name] = simulate_run(chunks, score_rate, interval=interval, threads=threads, **kw)
        log(f"  {name}: {tm['failure_scenarios'][name]}")
    srt = sorted(urls, key=lambda u: (parsed[u][1][::-1] if parsed[u][0] == "lookup" else ""))
    ws = workload(srt, parsed, rc, chunk, random.Random(SEED))
    tm["input_sorted_by_host"] = {
        "what": "same 1M rows sorted by reversed host name (i.e. grouped by TLD, then domain) instead of the file order",
        "central": analytic_bounds(ws["_chunks"], q_meas[0], interval, threads),
        "simulated_central": simulate_run(ws["_chunks"], score_rate, interval=interval, threads=threads, q=q_meas[0], R=0.3)}
    log(f"  sorted input: {tm['input_sorted_by_host']['simulated_central']}")
    tm["failure_scenarios_note"] = ("failed lookups are not cached, so in reality each failing domain would ALSO be retried in "
                                    "every later chunk containing it; the simulation charges each domain once (optimistic)")
    out["timing_1m"] = tm

    log("G. REVIEW-only subset")
    o = pd.read_csv(SCALE_OUT, encoding="utf-8-sig", dtype=str, keep_default_na=False, usecols=["url", "fraud_verdict"])
    assert len(o) == len(urls) and (o.url.values == df.url.values).all()
    rev_urls = o.url[o.fraud_verdict == "REVIEW"].tolist()
    wr = workload(rev_urls, parsed, rc, chunk, random.Random(SEED))
    wr.pop("_busiest")
    wr.pop("_base_counts")
    rchunks = wr.pop("_chunks")
    rv = {k: wr[k] for k in ("rows", "rows_by_enrichment_path", "unique_hosts_dns_jobs",
                             "unique_registrable_domains_rdap_jobs", "rdap_domains_without_rdap_server")}
    rv["busiest_registry_domains"] = wr["rdap_domains_per_registry_top15"][0]
    rv["simulated"] = {n: simulate_run(rchunks, score_rate, interval=interval, threads=threads, **kw) for n, kw in scen.items()}
    out["review_only"] = rv

    log("rule of thumb")
    n_regs = wl["unique_registrable_domains_rdap_jobs"]
    n_hosts = wl["unique_hosts_dns_jobs"]
    share = base_counts[busiest] / n_regs
    hpr = n_hosts / n_regs
    qpr = wl["doh_queries_total"] / n_regs
    tranco = out["calibration"]["runs"][0]
    t_share = tranco["busiest_registry_domains"] / tranco["domains_looked_up"]
    rt = {"formula": "hours per 100k unique registrable domains ~= [100k x busiest-registry share x 0.5 s  +  100k x "
                     "DoH-queries-per-domain x q / 8] / 3600  (+ chunk-barrier overhead, see timing_1m)"}
    for label, sh, qd in ((f"1M-file mix: .com {share:.1%} of domains, {hpr:.2f} hosts and {qpr:.2f} DoH queries per domain",
                           share, qpr),
                          (f"Tranco-homepage mix: .com {t_share:.1%} of domains, 1 host and 4 DoH queries per domain", t_share, 4.0)):
        rt[label] = {f"q={q * 1000:.0f}ms": r1((100_000 * sh * interval + 100_000 * qd * q / threads) / 3600, 1)
                     for q in (0.02, q_meas[0], 0.08)}
        rt[label]["rdap_part_hours"] = r1(100_000 * sh * interval / 3600, 1)
    out["rule_of_thumb"] = rt

    log("E. memory")
    hosts = sorted({k[1] for k in parsed.values() if k[0] == "lookup"})
    regs = sorted({k[2] for k in parsed.values() if k[0] == "lookup" and k[2]})
    random.Random(SEED).shuffle(hosts)
    random.Random(SEED).shuffle(regs)
    mem = memory_section(hosts, regs, n_hosts, n_regs)
    dns_pe = np.mean([x["rss_bytes_per_entry"] for x in mem["per_file"] if x["cache"] == "dns"])
    rdap_pe = np.mean([x["rss_bytes_per_entry"] for x in mem["per_file"] if x["cache"] == "rdap"])
    mem["extrapolated_from_per_entry_MB"] = r1((n_hosts * dns_pe + n_regs * rdap_pe) / 1e6)
    proj = mem["projected_1m_run"]
    mem["projected_peak_process_tree_MB"] = {
        "safe_mode_measured_peak": scale["peak_rss_MB_process_tree"],
        "plus_both_caches_measured": r1(scale["peak_rss_MB_process_tree"] + float(np.mean(proj["rss_increase_MB_both_caches"]))),
        "first_run_plus_caches_built_by_put": r1(scale["peak_rss_MB_process_tree"] + float(
            np.mean(proj["rss_increase_MB_both_caches_built_by_put_(first_run)"]))),
        "note": "caches live only in the main process and grow during the run, so the peak is reached near the end; "
                "the per-chunk result dicts, futures and 8 threads add comparatively little (not measured)"}
    mem["machine_total_ram_GB"] = r1(psutil.virtual_memory().total / 1e9)
    out["memory"] = mem

    log("F. failed lookups")
    out["failed_lookups"] = failed_lookups_section()

    log("H. output size")
    add = output_size_section(urls, parsed, rc)
    out["output_size"] = {"safe_mode_output_bytes": scale["output_bytes"], "estimated_extra_bytes": add,
                          "estimated_enrich_output_MB": r1((scale["output_bytes"] + add) / 1e6),
                          "assumption": "every looked-up row gets 'dns=ok; rdap=ok' (or rdap=no_rdap_server); failures and "
                                        "dead domains have longer status text; top_reasons text differences ignored"}

    c = tm["simulated"]
    cen = [v for k, v in c.items() if k.startswith("central")][0]
    opt = [v for k, v in c.items() if k.startswith("optimistic")][0]
    slow = [v for k, v in c.items() if k.startswith("slow")][0]
    out["headline"] = {
        "wall_time_hours_range_no_failures": [opt["hours"], slow["hours"]],
        "wall_time_hours_central": cen["hours"],
        "vs_safe_mode_seconds": scale["seconds"],
        "why": f"{base_counts[busiest]:,} of {n_regs:,} registrable domains go to {busiest}, which the client throttles to "
               f"2 requests/s -> {base_counts[busiest] * interval / 3600:.1f} h for that registry alone; the DNS phase adds "
               f"{wl['doh_queries_total']:,} DoH queries over 8 threads",
        "first_progress_line_after_minutes": cen["first_chunk_minutes"],
        "memory_MB_process_tree_peak_projected_first_run_vs_rerun": [
            mem["projected_peak_process_tree_MB"]["first_run_plus_caches_built_by_put"],
            mem["projected_peak_process_tree_MB"]["plus_both_caches_measured"]],
        "cache_on_disk_MB": proj["cache_bytes_on_disk_MB"],
        "review_only_hours_central": [v for k, v in rv["simulated"].items() if k.startswith("central")][0]["hours"],
    }
    fs = tm["failure_scenarios"]
    fl = out["failed_lookups"]["scenarios"]
    v_ok = fl["as_cached (real DNS+RDAP results from the cache)"]["verdicts"]
    v_429 = fl["RDAP failed for every domain (http_429, DNS as cached)"]["verdicts"]
    ram = mem["projected_peak_process_tree_MB"]
    n_com = base_counts[busiest]
    rv_c = out["headline"]["review_only_hours_central"]
    f50 = fs["Verisign .com answers 429 to 50% of requests (Retry-After 5 s)"]
    f100 = fs["Verisign .com answers 429 to every request (sustained rate limit)"]
    fdead = fs["Verisign .com RDAP stops answering (every request times out after 8 s)"]
    fdns = fs["DoH degraded: 5% of queries time out on all 3 attempts (9 s)"]
    redundant = wl["redundant_ns_mx_queries_(same_domain_queried_again_for_another_host)"]
    out["risks"] = [
        f"TIME: {n_com:,} unique .com domains x 0.5 s (Verisign RDAP, throttled to 2 req/s by the client) = "
        f"{n_com * interval / 3600:.1f} h on its own; simulated total {opt['hours']}-{slow['hours']} h with no failures "
        f"(safe mode: {scale['seconds']} s). About {cen['share_of_thread_time_blocked_on_rdap_throttle']:.0%} of all thread "
        "time is spent blocked on the RDAP throttle; more threads would not help.",
        f"NO VISIBLE PROGRESS: the progress line only updates after a whole 20,000-row chunk is enriched and scored; the first "
        f"chunk takes ~{cen['first_chunk_minutes']:.0f} min, later ones ~{cen['median_chunk_minutes']:.0f} min, which looks "
        "like a hang.",
        "REGISTRY RATE LIMITS/BLOCKING: many hours of continuous 2 req/s traffic to one registry (Verisign .com) from one IP. "
        "Registry rate policies were not checked (no network). If it answers 429, each retry consumes another throttle slot "
        f"and holds the thread 5-15 s, so the run gets SLOWER while producing no data: 50% 429s -> {f50['hours']} h and "
        f"{f50['rdap_domains_ending_http_429']:,} domains without RDAP; sustained 429 -> {f100['hours']} h and no .com RDAP "
        f"at all; .com RDAP unresponsive (8 s timeouts x 2) -> {fdead['hours']} h. A 403 (ban) returns immediately and "
        "silently turns every later .com domain into 'rdap=http_403'. Earlier project enrichment runs "
        "(experiments/logs/enrich_fresh26e.log, an earlier code version, 8,000 URLs / 5,058 domains) already recorded URL "
        "rows with rdap status http_429 (24) and http_403 (12).",
        "MISSING RDAP IS NOT FLAGGED AS SAFE MODE: a row whose RDAP lookup failed is still labelled 'enriched (URL + DNS + "
        "RDAP)'; only lookup_status ('dns=ok; rdap=http_429') shows it, and the enrich model scores it like a TLD without "
        f"RDAP. Offline on 1,000 legitimate homepages: LEGITIMATE {v_ok.get('LEGITIMATE', 0)} -> {v_429.get('LEGITIMATE', 0)}, "
        f"REVIEW {v_ok.get('REVIEW', 0)} -> {v_429.get('REVIEW', 0)}, FRAUD {v_ok.get('FRAUD', 0)} -> {v_429.get('FRAUD', 0)} "
        "when every RDAP lookup fails. A DNS failure instead falls back to the safe model and says so in analysis_mode.",
        "FAILURES ARE NOT CACHED: DNS timeouts and RDAP 429/403/5xx/timeouts are retried in every later chunk that contains "
        f"the same host/domain (up to {wl['domain_chunk_appearances']:,} domain-chunk appearances vs {n_regs:,} unique "
        "domains) and again on every re-run.",
        f"DNS: {wl['doh_queries_total']:,} DoH queries to Cloudflare ({redundant:,} of them repeat NS/MX for a domain already "
        "queried via another host); a degraded resolver costs up to 9 s per query (3 attempts x 3 s): 5% failing queries -> "
        f"{fdns['hours']} h.",
        "INTERRUPTING: an exception raised inside a chunk (e.g. KeyboardInterrupt from Ctrl+C; its delivery timing on "
        "Windows was not tested) still waits for every queued lookup of that chunk (executor exit semantics, demonstrated "
        "offline: 64 x 0.25 s jobs on 8 threads took 2.0 s to exit, not 0.25 s) and those results are not cached; the output file restarts from row 1 on re-run (the cache makes the re-run skip finished "
        "lookups).",
        f"RAM: the two caches live in the main process as Python dicts (~{dns_pe / 1000:.1f} KB per host, ~{rdap_pe / 1000:.1f} "
        f"KB per domain after loading, 5-6x their size on disk). Projected process-tree peak ~"
        f"{ram['first_run_plus_caches_built_by_put']:.0f} MB at the end of the first run and ~{ram['plus_both_caches_measured']:.0f} "
        f"MB for a re-run/resume that loads the caches (safe mode: {scale['peak_rss_MB_process_tree']} MB). Fine on a "
        f"{mem['machine_total_ram_GB']:.0f} GB machine, but it grows linearly with unique hosts/domains and with every "
        "re-appended (expired/refreshed) key, because the JSONL files are append-only, never compacted and fully re-read at "
        "every start.",
        f"DISK: caches ~{proj['cache_bytes_on_disk_MB']:.0f} MB; output ~{out['output_size']['estimated_enrich_output_MB']:.0f} MB "
        f"(safe: {scale['output_bytes'] / 1e6:.0f} MB).",
        "PARALLEL RUNS: starting several --enrich processes (e.g. on split files) multiplies the per-registry request rate "
        "(each process has its own 2 req/s throttle) and makes them append to the same JSONL files without file locking "
        "(not tested here).",
        "NO KNOBS: the CLI exposes no option to skip RDAP, change the thread count or throttle, or report lookup progress "
        "(--workers only sets the scoring processes).",
        "STALE BOOTSTRAP: after 30 days the IANA RDAP bootstrap is re-downloaded; if that fails the stale copy is used.",
        "MINOR CODE ISSUE: Enricher.close() skips caches that are still empty (JsonlCache defines __len__, so `if c:` is "
        "False) and leaves their files open until exit.",
    ]
    out["advice"] = [
        f"Run safe mode first (measured {scale['seconds']} s for 1M URLs), then enrich only the rows where enrichment can "
        f"change the decision: the REVIEW rows ({rv['rows']:,} rows, {rv['unique_registrable_domains_rdap_jobs']:,} domains, "
        f"~{rv_c} h central estimate). Filter them into a new CSV and run --enrich on that.",
        "Do not expect de-duplication to help much: lookups are already de-duplicated per host/domain via the cache; "
        "de-duplicating URLs only halves the (minor) scoring time. Do not sort the input by TLD/domain: the mixed order lets "
        "the other registries run in the shadow of .com (see timing_1m.input_sorted_by_host).",
        "Budget ~0.5 s per unique .com domain plus DNS; keep the machine awake, keep the same --cache-dir so an interrupted "
        "run resumes from the cache, and do not run several enrich processes against the same registry at once.",
        "After the run, count lookup_status values containing 'http_', 'error' or 'timeout' and re-run --enrich with the same "
        "cache to retry only those; treat rows with failed RDAP as not fully enriched.",
        "If a registry starts answering 429/403, stop and resume later rather than letting the run continue: the rest of that "
        "registry's domains would get no RDAP data while still being labelled 'enriched'.",
    ]
    out["runtime_seconds_of_this_script"] = r1(time.time() - t_start)
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, default=str)
    log(json.dumps(out["headline"], indent=1))
    log(f"wrote {OUT_JSON}")


if __name__ == "__main__":
    main()
