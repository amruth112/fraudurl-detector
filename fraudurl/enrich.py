"""Optional network enrichment: DNS and RDAP. Never contacts the URL's web server.

* DNS  - A/AAAA/CNAME for the host, NS/MX for the registrable domain, via DNS-over-HTTPS
         to Cloudflare (unfiltered). Standard library only.
* RDAP - registration data for the registrable domain from the *registry's* RDAP
         server (found via the IANA bootstrap file). Standard library only.

Every lookup is cached per host / registrable domain in a JSONL file, has hard
timeouts, and failures are recorded as explicit statuses (never raised).
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import math
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from . import __version__
from .cache import JsonlCache

NAN = float("nan")
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_UA = f"fraudurl/{__version__} (+https://github.com/amruth112/fraudurl-detector; lookups are cached)"


# ------------------------------------------------------------------ DNS (over HTTPS)
# DNS is resolved with DNS-over-HTTPS (DoH) to Cloudflare's unfiltered resolver, using only the
# standard library. Why not plain UDP DNS: on the development network UDP/53 was intercepted
# (identical TTLs from "different" resolvers) and failed under load, and filtering resolvers
# (e.g. Quad9 9.9.9.9, many ISP resolvers) answer NXDOMAIN for domains already on threat lists,
# which would leak threat-intel into the features. Cloudflare 1.1.1.1 does not filter and does not
# forward the client's subnet (ECS) to the domain's own nameserver.
DOH_SERVERS = ("1.1.1.1", "1.0.0.1")
_RTYPE = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "AAAA": 28}
_RCODE = {0: "ok", 2: "servfail", 3: "nxdomain", 5: "refused"}
_tls = threading.local()


def _doh_conn(server, timeout):
    conns = getattr(_tls, "conns", None)
    if conns is None:
        conns = _tls.conns = {}
    c = conns.get(server)
    if c is None:
        import ssl  # imported here so offline mode never needs the ssl module
        c = http.client.HTTPSConnection(server, 443, timeout=timeout, context=ssl.create_default_context())
        conns[server] = c
    return c


def _dns_query(name, rtype, servers=DOH_SERVERS, timeout=3.0, attempts=3):
    """Return (status, values, min_ttl, canonical_name). Never raises."""
    q = "/dns-query?" + urllib.parse.urlencode({"name": name, "type": rtype})
    for a in range(attempts):
        server = servers[a % len(servers)]
        try:
            c = _doh_conn(server, timeout)
            c.request("GET", q, headers={"accept": "application/dns-json"})
            r = c.getresponse()
            body = r.read(262144)
            if r.status == 400:
                return "bad_name", [], None, None  # resolver rejected the name: a final answer
            if r.status != 200:
                raise OSError(f"DoH HTTP {r.status}")
            d = json.loads(body)
        except (OSError, http.client.HTTPException, ValueError):
            conns = getattr(_tls, "conns", {})
            if server in conns:
                try:
                    conns.pop(server).close()
                except Exception:  # noqa: BLE001
                    pass
            continue
        status = _RCODE.get(d.get("Status"), f"rcode_{d.get('Status')}")
        ans = d.get("Answer") or []
        want = _RTYPE[rtype]
        vals = [x.get("data", "") for x in ans if x.get("type") == want]
        ttls = [x.get("TTL") for x in ans if x.get("type") == want and x.get("TTL") is not None]
        canon = None
        cn = [x.get("data", "").rstrip(".") for x in ans if x.get("type") == _RTYPE["CNAME"]]
        if cn:
            canon = cn[-1]
        if status == "ok" and not vals:
            status = "nodata"
        return status, vals, (min(ttls) if ttls else None), canon
    return "timeout", [], None, None


def dns_lookup(resolver, host: str, reg: str) -> dict:
    """``resolver`` is a tuple of DoH server IPs (kept as a parameter for testability)."""
    servers = resolver or DOH_SERVERS
    st_a, a, ttl_a, canon = _dns_query(host, "A", servers)
    st_aaaa, aaaa, _, _ = _dns_query(host, "AAAA", servers)
    st_ns, ns, _, _ = _dns_query(reg, "NS", servers) if reg else ("skip", [], None, None)
    st_mx, mx, _, _ = _dns_query(reg, "MX", servers) if reg else ("skip", [], None, None)
    return {"a_status": st_a, "a": a[:8], "ttl_a": ttl_a, "aaaa": aaaa[:4], "cname": canon,
            "ns_status": st_ns, "ns": [n.rstrip(".").lower() for n in ns][:8], "mx_status": st_mx, "mx": mx[:8],
            "resolver": "doh:" + servers[0]}


def dns_features(d: dict | None) -> dict:
    if not d:
        return {}
    a = d.get("a") or []
    def _private(ip):
        try:
            x = ipaddress.ip_address(ip)
            return x.is_private or x.is_loopback or x.is_reserved or x.is_link_local or x.is_unspecified
        except ValueError:
            return False
    ok = d.get("a_status") in ("ok", "nodata", "nxdomain")  # got an authoritative answer
    return {
        "dns_ok": 1.0 if ok else 0.0,
        "dns_resolves": (1.0 if (a or d.get("aaaa")) else 0.0) if ok else NAN,
        "dns_nxdomain": 1.0 if d.get("a_status") == "nxdomain" else (0.0 if ok else NAN),
        "dns_n_a": float(len(a)) if ok else NAN,
        "dns_has_aaaa": (1.0 if d.get("aaaa") else 0.0) if ok else NAN,
        "dns_has_cname": (1.0 if d.get("cname") else 0.0) if ok else NAN,
        "dns_ttl_a_log": math.log10(1 + d["ttl_a"]) if d.get("ttl_a") is not None else NAN,
        "dns_private_ip": (1.0 if any(_private(x) for x in a) else 0.0) if a else NAN,
        "dns_n_ns": float(len(d.get("ns") or [])) if d.get("ns_status") in ("ok", "nodata", "nxdomain") else NAN,
        "dns_has_mx": (1.0 if d.get("mx") else 0.0) if d.get("mx_status") in ("ok", "nodata", "nxdomain") else NAN,
    }


# ------------------------------------------------------------------ RDAP
def _read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


class RdapClient:
    def __init__(self, bootstrap_path: str, timeout: float = 8.0, min_interval: float = 0.25,
                 allow_bootstrap_download: bool = True):
        self.timeout, self.min_interval = timeout, min_interval
        self._servers: dict[str, str] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._last: dict[str, float] = {}
        self._glock = threading.Lock()
        self._load_bootstrap(bootstrap_path, allow_bootstrap_download)

    def _load_bootstrap(self, path, allow_download):
        data = None
        fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < 30 * 86400
        if fresh:
            data = _read_json(path)  # None if the cached copy is corrupt -> re-download below
        if data is None and allow_download:
            try:
                req = urllib.request.Request(BOOTSTRAP_URL, headers={"User-Agent": _UA})
                with urllib.request.urlopen(req, timeout=15) as r:
                    raw = r.read(2_000_000)
                data = json.loads(raw)
            except (OSError, ValueError):
                data = None
            if data is not None:  # best-effort save; a unique temp name lets parallel runs save safely
                tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
                try:
                    with open(tmp, "wb") as fh:
                        fh.write(raw)
                    os.replace(tmp, path)  # atomic: a crash never leaves a truncated cache file
                except OSError:
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
        if data is None and os.path.exists(path):
            data = _read_json(path)  # stale but usable
        for tlds, urls in (data or {}).get("services", []):
            base = next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
            for t in tlds:
                self._servers[t.lower()] = base
        self.bootstrap_ok = bool(self._servers)

    def server_for(self, domain: str):
        return self._servers.get(domain.rsplit(".", 1)[-1].lower())

    def _throttle(self, base):
        with self._glock:
            lock = self._locks.setdefault(base, threading.Lock())
        lock.acquire()
        try:
            wait = self._last.get(base, 0) + self.min_interval - time.time()
            if wait > 0:
                time.sleep(wait)
            self._last[base] = time.time()
        finally:
            lock.release()

    def lookup(self, domain: str) -> dict:
        base = self.server_for(domain)
        if not base:
            # without a bootstrap file we cannot know; this status is not cached (retried next run)
            return {"status": "no_rdap_server" if self.bootstrap_ok else "rdap_bootstrap_unavailable"}
        url = base.rstrip("/") + "/domain/" + domain
        for attempt in range(3):
            self._throttle(base)
            try:
                req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json",
                                                           "User-Agent": _UA})
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    j = json.loads(r.read(1_000_000))
                return {"status": "ok", **parse_rdap(j)}
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return {"status": "not_found"}
                if e.code == 429 and attempt < 2:
                    ra = e.headers.get("Retry-After", "5")
                    time.sleep(min(float(ra) if ra.isdigit() else 5.0, 15.0))
                    continue
                return {"status": f"http_{e.code}"}
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                if attempt < 1:
                    continue
                return {"status": "error:" + type(e).__name__}
            except ValueError:
                return {"status": "bad_json"}
        return {"status": "rate_limited"}


def _vcard_fn(ent):
    try:
        for item in ent.get("vcardArray", [None, []])[1]:
            if item[0] == "fn":
                return item[3]
    except (IndexError, TypeError):
        pass
    return None


def parse_rdap(j: dict) -> dict:
    ev = {}
    for e in j.get("events", []) or []:
        ev.setdefault(e.get("eventAction", ""), e.get("eventDate"))
    registrar, iana_id = None, None
    for ent in j.get("entities", []) or []:
        if "registrar" in (ent.get("roles") or []):
            registrar = _vcard_fn(ent)
            for pid in ent.get("publicIds", []) or []:
                if "IANA" in pid.get("type", ""):
                    iana_id = pid.get("identifier")
    return {"created": ev.get("registration"), "expires": ev.get("expiration"),
            "changed": ev.get("last changed"), "registrar": registrar, "registrar_iana": iana_id,
            "domain_status": [s.lower() for s in (j.get("status") or [])][:12],
            "ns": [n.get("ldhName", "").lower() for n in (j.get("nameservers") or [])][:8]}


_DT_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?"
                    r"\s*(Z|[+-]\d{2}:?\d{2})?$", re.I)


def _parse_dt(s):
    """Parse RDAP timestamps identically on every Python version (3.9+)."""
    if not s or not isinstance(s, str):
        return None
    m = _DT_RE.match(s.strip())
    if not m:
        return None
    y, mo, d, hh, mi, ss, frac, tz = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(hh or 0), int(mi or 0), int(ss or 0),
                      int((frac or "0")[:6].ljust(6, "0")), tzinfo=timezone.utc)
    except ValueError:
        return None
    if tz and tz.upper() != "Z":
        sign = 1 if tz[0] == "+" else -1
        hours, minutes = int(tz[1:3]), int(tz[-2:])
        dt = dt - sign * timedelta(hours=hours, minutes=minutes)
    return dt


def rdap_features(d: dict | None, now: datetime | None = None) -> dict:
    if not d:
        return {}
    now = now or datetime.now(timezone.utc)
    st = d.get("status")
    f = {"rdap_ok": 1.0 if st == "ok" else 0.0,
         "rdap_not_found": 1.0 if st == "not_found" else (0.0 if st == "ok" else NAN)}
    if st != "ok":
        return {**f, "domain_age_days_log": NAN, "days_to_expiry_log": NAN, "reg_period_years": NAN,
                "days_since_changed_log": NAN, "status_hold": NAN, "status_n": NAN}
    c, e, ch = _parse_dt(d.get("created")), _parse_dt(d.get("expires")), _parse_dt(d.get("changed"))
    ds = d.get("domain_status") or []
    f["domain_age_days_log"] = math.log10(1 + max(0.0, (now - c).days)) if c else NAN
    f["days_to_expiry_log"] = math.log10(1 + max(0.0, (e - now).days)) if e else NAN
    f["reg_period_years"] = ((e - c).days / 365.25) if (c and e) else NAN
    f["days_since_changed_log"] = math.log10(1 + max(0.0, (now - ch).days)) if ch else NAN
    f["status_hold"] = 1.0 if any("hold" in s for s in ds) else 0.0
    f["status_n"] = float(len(ds))
    return f


# ------------------------------------------------------------------ orchestration
class Enricher:
    """Batch enrichment with per-domain caching. Use: Enricher(...).run(parsed_urls)."""

    def __init__(self, cache_dir: str, dns: bool = True, rdap: bool = True, workers: int = 8,
                 doh_servers=DOH_SERVERS, rdap_timeout: float = 8.0,
                 cache_ttl_days: float = 7.0, bootstrap_path: str | None = None):
        # >~12 parallel lookups made a home network drop DNS answers (measured), so keep it small.
        self.do_dns, self.do_rdap, self.workers = dns, rdap, workers
        self.dns_cache = JsonlCache(os.path.join(cache_dir, "dns.jsonl"), cache_ttl_days) if dns else None
        self.rdap_cache = JsonlCache(os.path.join(cache_dir, "rdap.jsonl"), cache_ttl_days * 4) if rdap else None
        self.resolver = tuple(doh_servers)
        self.rdap = None
        if rdap:
            bp = bootstrap_path or os.path.join(cache_dir, "rdap_bootstrap_dns.json")
            self.rdap = RdapClient(bp, timeout=rdap_timeout, min_interval=0.5)  # <= 2 req/s per registry

    def run(self, items, progress=None):
        """items: iterable of (host, reg, is_ip, private_suffix). Returns (dns_by_host, rdap_by_reg).

        RDAP is skipped for tenants of hosting platforms (PSL private suffixes such as
        *.github.io): the registry only knows the platform's domain, whose age would
        wrongly make every tenant look long-established."""
        hosts, regs = {}, set()
        for host, reg, is_ip, private in items:
            if is_ip or not host:
                continue
            hosts[host] = reg
            if reg and not private:
                regs.add(reg)
        dns_res, rdap_res = {}, {}
        jobs = []
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            if self.do_dns:
                for h, reg in hosts.items():
                    c = self.dns_cache.get(h)
                    if c is not None:
                        dns_res[h] = c
                    else:
                        jobs.append(("dns", h, ex.submit(dns_lookup, self.resolver, h, reg)))
            if self.do_rdap:
                for reg in regs:
                    c = self.rdap_cache.get(reg)
                    if c is not None:
                        rdap_res[reg] = c
                    else:
                        jobs.append(("rdap", reg, ex.submit(self.rdap.lookup, reg)))
            for i, (kind, key, fut) in enumerate(jobs):
                try:
                    v = fut.result()
                except Exception as e:  # noqa: BLE001
                    v = {"status": "error:" + type(e).__name__} if kind == "rdap" else {"a_status": "error"}
                if kind == "dns":
                    dns_res[key] = v
                    # timeouts are not cached so a later run retries them (DoH answers incl.
                    # SERVFAIL are authoritative enough to keep)
                    if v.get("a_status") in ("ok", "nodata", "nxdomain", "servfail", "refused", "bad_name"):
                        self.dns_cache.put(key, v)
                else:
                    rdap_res[key] = v
                    # transient failures are not cached so a later run can retry them
                    if v.get("status") in ("ok", "not_found", "no_rdap_server"):
                        self.rdap_cache.put(key, v)
                if progress and (i + 1) % 200 == 0:
                    progress(i + 1, len(jobs))
        return dns_res, rdap_res

    def close(self):
        for c in (self.dns_cache, self.rdap_cache):
            if c:
                c.close()
