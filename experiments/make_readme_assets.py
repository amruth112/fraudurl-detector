"""Generate the README images in docs/assets/ (light and dark variants) from real results.

Every number comes from results/ and every example row from a real run of the shipped tool, so the
pictures cannot drift from the measurements:

    python experiments/make_readme_assets.py

Outputs: hero, demo, stats and verdicts SVGs, each as *-light.svg / *-dark.svg.
Verdict colours (blue / amber / red) were checked for colour-vision-deficiency separation and contrast on
GitHub's light (#ffffff) and dark (#0d1117) backgrounds; amber always carries a visible label.
"""
from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import tempfile
from xml.sax.saxutils import escape

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "assets")
RES = os.path.join(ROOT, "results")

SANS = "-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif"
MONO = "ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace"

THEMES = {
    "light": dict(bg1="#ffffff", bg2="#f3f6fb", card="#ffffff", card2="#f6f8fa", border="#d0d7de", ink="#1f2328",
                  ink2="#59636e", muted="#818b98", grid="#e1e4e8", dot="#d8dee4", legit="#2a78d6",
                  review="#e8a200", fraud="#d03b3b", on_legit="#ffffff", on_review="#1f2328", on_fraud="#ffffff",
                  hl_review="#fff1c7", hl_fraud="#ffe1e1", hl_legit="#dcebfb", term="#f6f8fa", accent1="#2a78d6",
                  accent2="#7b4fd6"),
    "dark": dict(bg1="#0d1117", bg2="#121a2a", card="#151b23", card2="#1b2430", border="#3d444d", ink="#f0f6fc",
                 ink2="#9198a1", muted="#768390", grid="#2a313c", dot="#232b36", legit="#3987e5",
                 review="#c98500", fraud="#d03b3b", on_legit="#ffffff", on_review="#0d1117", on_fraud="#ffffff",
                 hl_review="#3d2e05", hl_fraud="#3f1719", hl_legit="#12294a", term="#0b0f14", accent1="#3987e5",
                 accent2="#9d7ce8"),
}
VERDICT_COLOR = {"FRAUD": "fraud", "REVIEW": "review", "LEGITIMATE": "legit"}


def J(*p):
    with open(os.path.join(RES, *p), encoding="utf-8") as fh:
        return json.load(fh)


def svg(w, h, body, title):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
            f'aria-label="{escape(title)}"><title>{escape(title)}</title>{body}</svg>\n')


def text(x, y, s, size, fill, weight=400, anchor="start", family=SANS, extra=""):
    return (f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" font-weight="{weight}" fill="{fill}" '
            f'text-anchor="{anchor}"{extra}>{escape(s)}</text>')


def mono_run(x, y, s, size, fill, char_w, weight=400):
    """Monospace text forced to an exact width, so highlights line up on every platform font."""
    return text(x, y, s, size, fill, weight, family=MONO,
                extra=f' textLength="{len(s) * char_w:.1f}" lengthAdjust="spacingAndGlyphs"')


def pill(x, y, label, t, h=26, size=13, pad=12):
    key = VERDICT_COLOR.get(label, "muted")
    fill = t.get(key, t["muted"])
    on = t.get("on_" + key, "#ffffff")
    w = pad * 2 + len(label) * size * 0.64
    return (f'<rect x="{x}" y="{y}" width="{w:.1f}" height="{h}" rx="{h / 2}" fill="{fill}"/>'
            + text(x + w / 2, y + h / 2 + size * 0.36, label, size, on, 700, "middle")), w


def logo(x, y, s, t):
    """Link + magnifier mark on a gradient tile."""
    k = s / 104
    g = (f'<g transform="translate({x},{y}) scale({k})">'
         f'<rect width="104" height="104" rx="26" fill="url(#brand)"/>'
         '<g fill="none" stroke="#ffffff" stroke-width="7" stroke-linecap="round">'
         '<path d="M44 58 L58 44"/>'
         '<path d="M40 50 L31 59 a10.5 10.5 0 0 0 14.8 14.8 L54.8 64.8"/>'
         '<path d="M62 54 L71 45 a10.5 10.5 0 0 0 -14.8 -14.8 L47.2 39.2"/>'
         '</g>'
         '<circle cx="74" cy="74" r="15" fill="#ffffff"/>'
         '<circle cx="74" cy="74" r="8.5" fill="none" stroke="url(#brand)" stroke-width="4"/>'
         '<path d="M80.5 80.5 L86 86" stroke="url(#brand)" stroke-width="4" stroke-linecap="round"/>'
         '</g>')
    return g


def defs(t):
    return (f'<defs><linearGradient id="brand" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0" stop-color="{t["accent1"]}"/><stop offset="1" stop-color="{t["accent2"]}"/></linearGradient>'
            f'<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{t["bg1"]}"/>'
            f'<stop offset="1" stop-color="{t["bg2"]}"/></linearGradient>'
            f'<pattern id="dots" width="22" height="22" patternUnits="userSpaceOnUse">'
            f'<circle cx="2" cy="2" r="1.2" fill="{t["dot"]}"/></pattern></defs>')


# ----------------------------------------------------------------------------------------------- real run
def real_run():
    """Score the README example URLs with the shipped single file and return its output rows."""
    urls = ["http://paypal.com.secure-login.test/webscr/login.php?cmd=verify", "https://www.wikipedia.org/",
            "github.com/python/cpython", "http://198.51.100.23/", "not a url"]
    with tempfile.TemporaryDirectory() as d:
        inp, outp = os.path.join(d, "urls.csv"), os.path.join(d, "urls.fraudurl.csv")
        with open(inp, "w", encoding="utf-8", newline="") as fh:
            csv.writer(fh).writerows([["url"]] + [[u] for u in urls])
        r = subprocess.run([sys.executable, os.path.join(ROOT, "fraudurl_standalone.py"), inp, "-o", outp],
                           capture_output=True, text=True, check=True)
        rows = list(csv.DictReader(open(outp, encoding="utf-8-sig")))
    summary = [ln for ln in r.stderr.replace("\r", "\n").splitlines() if ln.startswith(("Done:", "Verdicts:"))]
    summary = [s.replace(outp, "urls.fraudurl.csv") for s in summary]
    return rows, summary


# ----------------------------------------------------------------------------------------------- hero
def hero(t, row):
    W, H = 1200, 400
    b = [defs(t), f'<rect x="0.5" y="0.5" width="{W - 1}" height="{H - 1}" rx="18" fill="url(#bg)" stroke="{t["border"]}"/>',
         f'<rect x="0.5" y="0.5" width="{W - 1}" height="{H - 1}" rx="18" fill="url(#dots)" opacity="0.7"/>',
         logo(60, 70, 96, t),
         text(176, 136, "fraudurl", 72, t["ink"], 800, extra=' letter-spacing="-2"'),
         text(62, 214, "Fast, offline phishing-URL checker", 28, t["ink"], 600),
         text(62, 250, "CSV in. Verdict, calibrated probability and", 18, t["ink2"]),
         text(62, 276, "plain-English reasons out, for every row.", 18, t["ink2"])]
    x = 62
    for chip in ("One Python file", "Zero dependencies", "Never visits the sites"):
        w = 26 + len(chip) * 7.9
        b.append(f'<rect x="{x}" y="304" width="{w:.1f}" height="32" rx="16" fill="{t["card"]}" stroke="{t["border"]}"/>')
        b.append(text(x + w / 2, 325, chip, 14, t["ink2"], 600, "middle"))
        x += w + 10
    # inspection card
    cx, cy, cw, ch = 628, 52, 520, 296
    b.append(f'<rect x="{cx}" y="{cy}" width="{cw}" height="{ch}" rx="14" fill="{t["card"]}" stroke="{t["border"]}"/>')
    for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        b.append(f'<circle cx="{cx + 22 + i * 18}" cy="{cy + 22}" r="5.5" fill="{c}"/>')
    b.append(text(cx + 86, cy + 27, "fraudurl --url …", 13, t["muted"], 500, family=MONO))
    b.append(f'<line x1="{cx}" y1="{cy + 44}" x2="{cx + cw}" y2="{cy + 44}" stroke="{t["border"]}"/>')
    cw_char, fs = 8.9, 15
    y1, y2 = cy + 80, cy + 112
    segs1 = [("http://", "hl_fraud"), ("paypal.com.", "hl_review"), ("secure-login.test", "hl_legit")]
    segs2 = [("/webscr/", None), ("login", "hl_review"), (".php?cmd=", None), ("verify", "hl_review")]
    for segs, yy in ((segs1, y1), (segs2, y2)):
        xx = cx + 24
        for s, hl in segs:
            w = len(s) * cw_char
            if hl:
                b.append(f'<rect x="{xx - 2:.1f}" y="{yy - 17}" width="{w + 4:.1f}" height="24" rx="5" fill="{t[hl]}"/>')
            b.append(mono_run(xx, yy, s, fs, t["ink"], cw_char, 600 if hl == "hl_legit" else 400))
            xx += w
    # legend for the highlights (one row, no overlaps)
    lx, ly = cx + 24, cy + 146
    for label, hl, key in (("plain http", "hl_fraud", "fraud"), ("brand / login words", "hl_review", "review"),
                           ("the real owner's domain", "hl_legit", "legit")):
        b.append(f'<rect x="{lx}" y="{ly - 11}" width="14" height="14" rx="3" fill="{t[hl]}" stroke="{t[key]}" '
                 f'stroke-width="1.5"/>')
        b.append(text(lx + 20, ly, label, 12.5, t["ink2"], 500))
        lx += 20 + len(label) * 6.7 + 22
    b.append(f'<line x1="{cx + 24}" y1="{cy + 166}" x2="{cx + cw - 24}" y2="{cy + 166}" stroke="{t["border"]}"/>')
    # verdict
    vy = cy + 184
    p, pw = pill(cx + 24, vy, row["fraud_verdict"], t, h=34, size=16, pad=16)
    b.append(p)
    b.append(text(cx + 36 + pw, vy + 25, row["fraud_probability"], 24, t["ink"], 700, family=MONO))
    b.append(text(cx + 110 + pw, vy + 23, "probability of phishing", 13, t["muted"]))
    reasons = [r.replace(" (raises risk)", "") for r in row["top_reasons"].split("; ")][:2]
    for i, r in enumerate(reasons):
        ry = vy + 60 + i * 24
        b.append(f'<circle cx="{cx + 30}" cy="{ry - 4}" r="3" fill="{t["fraud"]}"/>')
        b.append(text(cx + 42, ry, r, 13.5, t["ink2"]))
    return svg(W, H, "".join(b), "fraudurl: fast, offline phishing-URL checker")


# ----------------------------------------------------------------------------------------------- demo
def demo(t, rows, summary):
    W = 1200
    top, lh = 44, 26
    H = top + 34 + lh * len(summary) + 36 + 12 + len(rows) * 40 + 26
    b = [f'<rect x="0.5" y="0.5" width="{W - 1}" height="{H - 1}" rx="12" fill="{t["term"]}" stroke="{t["border"]}"/>']
    for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        b.append(f'<circle cx="{22 + i * 20}" cy="22" r="6" fill="{c}"/>')
    b.append(text(W / 2, 27, "urls.csv  →  urls.fraudurl.csv", 13, t["muted"], 500, "middle", MONO))
    b.append(f'<line x1="0" y1="{top}" x2="{W}" y2="{top}" stroke="{t["border"]}"/>')
    y = top + 34
    b.append(text(28, y, "$", 16, t["legit"], 700, family=MONO))
    b.append(text(46, y, "python fraudurl_standalone.py urls.csv", 16, t["ink"], 500, family=MONO))
    for s in summary:
        y += lh
        b.append(text(46, y, s, 15, t["ink2"], family=MONO))
    y += 36
    cols = [(28, "url"), (548, "fraud_verdict"), (700, "fraud_probability"), (860, "top reason")]
    for x, h in cols:
        b.append(text(x, y, h, 13, t["muted"], 700, family=MONO))
    y += 12
    b.append(f'<line x1="24" y1="{y}" x2="{W - 24}" y2="{y}" stroke="{t["border"]}"/>')
    for r in rows:
        y += 40
        u = r["url"] if len(r["url"]) <= 57 else r["url"][:56] + "…"
        b.append(text(28, y, u, 14, t["ink"], family=MONO))
        p, _ = pill(548, y - 18, r["fraud_verdict"], t, h=24, size=12, pad=11)
        b.append(p)
        b.append(text(700, y, r["fraud_probability"] or "—", 14, t["ink"], 600, family=MONO))
        reason = (r["top_reasons"].split("; ")[0] if r["top_reasons"] else r["error"])
        reason = reason.replace(" (raises risk)", "").replace(" (lowers risk)", "")
        reason = reason if len(reason) <= 46 else reason[:45] + "…"
        b.append(text(860, y, reason, 14, t["ink2"]))
    return svg(W, H, "".join(b), "Example run: urls.csv in, urls.fraudurl.csv out")


# ----------------------------------------------------------------------------------------------- stats
def stats(t, s):
    W, H = 1200, 148
    tiles = [(s["time_1m"], "to check 1,000,000 URLs", "on a 4-core desktop"),
             (s["size"], "the whole tool in one file,", "models included"),
             ("0", "dependencies: Python 3.9+", "standard library only"),
             (s["auc"], "ROC-AUC on domains never", "seen in training (2021–2026)")]
    tw, gap = (W - 3 * 16) / 4, 16
    b = []
    for i, (big, l1, l2) in enumerate(tiles):
        x = i * (tw + gap)
        b.append(f'<rect x="{x + 0.5:.1f}" y="0.5" width="{tw - 1:.1f}" height="{H - 1}" rx="14" fill="{t["card"]}" '
                 f'stroke="{t["border"]}"/>')
        b.append(text(x + 24, 62, big, 40, t["ink"], 800, extra=' letter-spacing="-1"'))
        b.append(text(x + 24, 96, l1, 15, t["ink2"]))
        b.append(text(x + 24, 118, l2, 15, t["ink2"]))
    return svg(W, H, "".join(b), "fraudurl in numbers")


# ----------------------------------------------------------------------------------------------- verdicts chart
def verdicts(t, groups):
    W = 1200
    x0, x1 = 214, 1000
    bw = x1 - x0
    head, per = 132, 108
    H = head + per * len(groups) + 8
    b = [f'<rect x="0.5" y="0.5" width="{W - 1}" height="{H - 1}" rx="14" fill="{t["card"]}" stroke="{t["border"]}"/>',
         text(28, 46, "Where URLs end up", 24, t["ink"], 700),
         text(28, 74, "Share of each true class by verdict, on test URLs from domains never seen in training", 15,
              t["ink2"])]
    lx = 28
    for label, key in (("LEGITIMATE", "legit"), ("REVIEW", "review"), ("FRAUD", "fraud")):
        b.append(f'<rect x="{lx}" y="92" width="14" height="14" rx="3" fill="{t[key]}"/>')
        b.append(text(lx + 20, 104, label, 13, t["ink2"], 600))
        lx += 20 + len(label) * 9 + 26
    y = head
    for name, rates in groups:
        b.append(text(28, y + 4, name, 15, t["ink"], 700))
        for j, cls in enumerate(("legitimate", "phishing")):
            by = y + 16 + j * 34
            shares = rates[cls]
            b.append(text(28, by + 17, "legitimate URLs" if cls == "legitimate" else "phishing URLs", 13, t["ink2"]))
            xs = x0
            order = ("LEGITIMATE", "REVIEW", "FRAUD")
            segs = [(v, shares[v]) for v in order if shares[v] > 0]
            for k, (v, sh) in enumerate(segs):
                w = bw * sh
                gap = 2 if k < len(segs) - 1 else 0
                key = VERDICT_COLOR[v]
                first, last = k == 0, k == len(segs) - 1
                if first or last:  # rounded outer ends only
                    rx = 4
                    b.append(f'<rect x="{xs:.2f}" y="{by}" width="{max(w - gap, 0.8):.2f}" height="24" rx="{rx}" '
                             f'fill="{t[key]}"/>')
                    inner = xs + (w - gap) / 2 if first else xs
                    cover_w = max(min((w - gap) / 2, w - gap), 0)
                    if not (first and last) and cover_w > 0:
                        b.append(f'<rect x="{inner:.2f}" y="{by}" width="{cover_w:.2f}" height="24" fill="{t[key]}"/>')
                else:
                    b.append(f'<rect x="{xs:.2f}" y="{by}" width="{max(w - gap, 0.8):.2f}" height="24" fill="{t[key]}"/>')
                if w >= 58:
                    b.append(text(xs + (w - gap) / 2, by + 17, f"{sh * 100:.0f}%", 13, t["on_" + key], 700, "middle"))
                xs += w
            wrong = shares["FRAUD"] if cls == "legitimate" else shares["LEGITIMATE"]
            what = "FRAUD" if cls == "legitimate" else "LEGITIMATE"
            b.append(text(x1 + 14, by + 17, f"{wrong * 100:.1f}% wrongly {what}", 13, t["ink2"], 600))
        y += per
    return svg(W, H, "".join(b), "Where URLs end up: verdict shares by true class on unseen test domains")


def main():
    os.makedirs(OUT, exist_ok=True)
    rows, summary = real_run()
    pc = J("benchmark", "projection_1m.json")["per_class_rates"]

    def shares(key):
        d = pc[key]
        return {cls: {v: d[cls]["default"][v]["share"] for v in ("LEGITIMATE", "REVIEW", "FRAUD")}
                for cls in ("legitimate", "phishing")}
    groups = [("PhreshPhish 2024–25", shares("phreshphish_test")), ("2026 collection", shares("fresh26_test")),
              ("Ariyadasa 2021 (fully external)", shares("ariyadasa_unseen")), ("Hannousse 2020", shares("hannousse_test"))]
    scale = J("benchmark", "scale_1000000.json")
    secs = scale["seconds"]
    fs = J("final", "final_safe.json")
    aucs = [fs["test"]["phreshphish"]["metrics_at_0.5"]["roc_auc"], fs["test"]["fresh26"]["metrics_at_0.5"]["roc_auc"],
            fs["external"]["ariyadasa"]["metrics_at_0.5"]["roc_auc"]]
    size_kb = os.path.getsize(os.path.join(ROOT, "fraudurl_standalone.py")) / 1000
    s = {"time_1m": f"{int(secs // 60)} min {int(round(secs % 60))} s", "size": f"{round(size_kb, -1):.0f} KB",
         "auc": f"{min(aucs):.2f}–{max(aucs):.2f}"}
    fraud_row = next(r for r in rows if r["fraud_verdict"] == "FRAUD")
    for mode, t in THEMES.items():
        for name, content in (("hero", hero(t, fraud_row)), ("demo", demo(t, rows, summary)),
                              ("stats", stats(t, s)), ("verdicts", verdicts(t, groups))):
            with open(os.path.join(OUT, f"{name}-{mode}.svg"), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(content)
    print("wrote", sorted(os.listdir(OUT)))
    print("stats:", s, "| groups:", [(g, {c: {k: round(v, 3) for k, v in r.items()} for c, r in d.items()})
                                    for g, d in groups][:1])


if __name__ == "__main__":
    main()
