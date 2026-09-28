"""Run DNS + RDAP enrichment for every URL in a processed dataset (cached per domain).

Never contacts the URLs' web servers: DNS goes to the configured resolver, RDAP to the
registry servers listed in the IANA bootstrap file.
"""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import DATA, save_json  # noqa: E402
from fraudurl.enrich import Enricher, dns_features, rdap_features  # noqa: E402
from fraudurl.lexical import ParsedURL  # noqa: E402

CACHE = os.path.join(DATA, "cache")


def main(name):
    df = pd.read_csv(os.path.join(DATA, "processed", f"{name}.csv"), dtype={"url": str})
    ps = [ParsedURL(u) for u in df.url]
    items = [(p.host, p.reg, p.ip, p.private_suffix) for p in ps]
    e = Enricher(CACHE, workers=8)  # >~12 parallel lookups caused fake SERVFAIL/timeouts (measured)
    t = time.time()
    dns_r, rdap_r = e.run(items, progress=lambda i, n: print(f"  {i}/{n} lookups {time.time() - t:.0f}s", flush=True))
    secs = time.time() - t
    e.close()
    now = datetime.now(timezone.utc)
    rows = []
    for p in ps:
        f = {}
        if not p.ip:
            f.update(dns_features(dns_r.get(p.host)))
            if not p.private_suffix:
                f.update(rdap_features(rdap_r.get(p.reg), now))
        rows.append(f)
    feats = pd.DataFrame(rows, index=df.index)
    feats["dns_status"] = [(dns_r.get(p.host) or {}).get("a_status", "skip") for p in ps]
    feats["rdap_status"] = [(rdap_r.get(p.reg) or {}).get("status", "skip") if not p.private_suffix else "skip_platform"
                            for p in ps]
    # raw registration date, so analyses can compute the domain's age at the time the URL was seen
    feats["rdap_created"] = [(rdap_r.get(p.reg) or {}).get("created") if not p.private_suffix else None for p in ps]
    feats["rdap_expires"] = [(rdap_r.get(p.reg) or {}).get("expires") if not p.private_suffix else None for p in ps]
    feats.to_pickle(os.path.join(DATA, "processed", f"enrich_{name}.pkl"))
    summ = {"dataset": name, "n_urls": len(df), "n_hosts": len(dns_r), "n_regs": len(rdap_r), "seconds": secs,
            "observed_at": now.isoformat(),
            "dns_status_by_label": pd.crosstab(feats.dns_status, df.label).to_dict(),
            "rdap_status_by_label": pd.crosstab(feats.rdap_status, df.label).to_dict()}
    save_json(summ, "enrichment", f"{name}_summary.json")
    print(summ, flush=True)


if __name__ == "__main__":
    main(sys.argv[1])
