"""Audit the 1,000,000-row CLI output against its input: what exactly does a user get back?

Input : .cache/tmp/scale_1000000.csv          (written by experiments/scale_1m.py; columns id,url,note)
Output: .cache/tmp/scale_1000000.csv.out.csv  (python -m fraudurl <input> -o <output>, safe mode, defaults)

Checks (all numbers below are computed here; nothing is copied from elsewhere):
 1. format: row count, row order, original columns byte-identical, added columns, encoding/BOM, delimiter,
    line endings, quoting
 2. determinism: every duplicated URL must carry identical result columns (duplicates were scored in
    different 1000-row parts / 20,000-row chunks dispatched to a 4-process pool); plus an in-process
    re-score of a random sample against the file
 3. the ERROR rows
 4. verdict mix, probability deciles per verdict, number of reasons, most common reason phrases, cell length
 5. spreadsheet practicality (Excel 1,048,576 rows / 32,767 chars per cell) and formula-injection protection
    (_safe_cell), including a small controlled run of the CLI on URLs starting with = + - @
 6. bytes per row and per column (exact accounting, checked against the file size)
 7. verdicts vs probability and the shipped thresholds, handling the 3-decimal rounding exactly

Safe mode only: no network. Usage: python experiments/audit_output_1m.py
"""
from __future__ import annotations

import codecs
import csv
import json
import os
import sys
import time
from collections import Counter

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from fraudurl import cli  # noqa: E402  (read-only use: _safe_cell, _chunk_job, run in safe mode)

TMP = os.path.join(ROOT, ".cache", "tmp")
INP = os.path.join(TMP, "scale_1000000.csv")
OUTP = INP + ".out.csv"
MODEL = os.path.join(ROOT, "fraudurl", "data", "model_safe.json")
RES = os.path.join(ROOT, "results", "benchmark", "output_audit_1m.json")
EXCEL_MAX_ROWS, EXCEL_MAX_CELL = 1_048_576, 32_767
PART, CHUNK = 1000, 20000   # cli.run: flush every 20,000 rows, each flush split into 1,000-row parts for the pool
RESULT_COLS = list(cli.OUT_COLS)
T0 = time.time()


def log(*a):
    print(f"[{time.time() - T0:6.1f}s]", *a, flush=True)


def qdict(s: pd.Series, qs=(0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100)):
    if len(s) == 0:
        return {}
    v = np.percentile(s.to_numpy(dtype=float), qs)  # numpy default: linear interpolation
    return {f"p{q}": round(float(x), 4) for q, x in zip(qs, v)}


def written_bytes(s: pd.Series) -> tuple[int, int]:
    """Bytes a column occupies in a csv.writer (QUOTE_MINIMAL) UTF-8 file: payload + quoting overhead."""
    payload = int(s.str.encode("utf-8").str.len().sum())
    needs_q = s.str.contains(r'[,"\r\n]', regex=True)
    overhead = int(2 * needs_q.sum() + s[needs_q].str.count('"').sum())
    return payload + overhead, int(needs_q.sum())


def main():
    res = {"script": "experiments/audit_output_1m.py", "input": os.path.relpath(INP, ROOT).replace("\\", "/"),
           "output": os.path.relpath(OUTP, ROOT).replace("\\", "/")}
    model = json.load(open(MODEL, encoding="utf-8"))
    th_f, th_l = float(model["thresholds"]["fraud"]), float(model["thresholds"]["legit"])

    # ------------------------------------------------------------------ 1. raw bytes: encoding, EOL, byte-identity
    log("reading raw bytes")
    rin, rout = open(INP, "rb").read(), open(OUTP, "rb").read()
    fmt = {"input_bytes": len(rin), "output_bytes": len(rout)}
    for tag, b in (("input", rin), ("output", rout)):
        crlf, lf, cr = b.count(b"\r\n"), b.count(b"\n"), b.count(b"\r")
        bom = b.startswith(codecs.BOM_UTF8)
        dec, utf8_ok = codecs.getincrementaldecoder("utf-8")(), True
        try:
            for i in range(3 if bom else 0, len(b), 1 << 24):
                dec.decode(b[i:i + (1 << 24)])
            dec.decode(b"", final=True)
        except UnicodeDecodeError:
            utf8_ok = False
        fmt[tag] = {"utf8_bom": bom, "strict_utf8_decodes": utf8_ok, "crlf": crlf, "bare_lf": lf - crlf,
                    "bare_cr": cr - crlf, "ends_with_crlf": b.endswith(b"\r\n"),
                    "bytes_ge_0x80_excluding_bom": int((np.frombuffer(b, np.uint8) >= 0x80).sum()) - (3 if bom else 0)}
    head_line = rout[3:rout.index(b"\r\n")].decode("utf-8")
    fmt["output_header_line"] = head_line
    sniff = csv.Sniffer().sniff(rout[3:200_000].decode("utf-8", "ignore"), delimiters=",;\t|")
    fmt["sniffed_delimiter_output"] = sniff.delimiter
    # physical lines == records only if no field has an embedded CR/LF: verified by bare_lf == bare_cr == 0 above
    lin = rin.split(b"\r\n")
    lout = rout[3:].split(b"\r\n") if rout.startswith(codecs.BOM_UTF8) else rout.split(b"\r\n")
    if lin and lin[-1] == b"":
        lin.pop()
    if lout and lout[-1] == b"":
        lout.pop()
    fmt["physical_lines_input_incl_header"] = len(lin)
    fmt["physical_lines_output_incl_header"] = len(lout)
    n_pref = sum(1 for a, b in zip(lin, lout) if b.startswith(a + b","))
    fmt["output_lines_starting_with_the_exact_input_line_bytes_plus_comma"] = n_pref
    fmt["byte_prefix_mismatches"] = len(lin) - n_pref if len(lin) == len(lout) else None
    fmt["input_lines_with_a_quote_char"] = sum(1 for a in lin if b'"' in a)
    fmt["output_lines_with_a_quote_char"] = sum(1 for a in lout if b'"' in a)
    # every output record must have 11 fields (csv module parse)
    with open(OUTP, encoding="utf-8-sig", newline="") as fh:
        fc = Counter(len(r) for r in csv.reader(fh))
    fmt["output_fields_per_record_distribution"] = {str(k): v for k, v in sorted(fc.items())}
    del rin, rout, lin, lout

    # ------------------------------------------------------------------ 1b. pandas: rows, order, columns, values
    log("reading CSVs with pandas (dtype=str, keep_default_na=False)")
    di = pd.read_csv(INP, dtype=str, keep_default_na=False)
    do = pd.read_csv(OUTP, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    N = len(di)
    orig = list(di.columns)
    fmt.update({
        "input_rows": N, "output_rows": len(do), "row_count_equal": N == len(do),
        "input_columns": orig, "output_columns": list(do.columns),
        "original_columns_first_and_in_order": list(do.columns[:len(orig)]) == orig,
        "added_columns_in_order": list(do.columns[len(orig):]),
        "added_columns_equal_cli_OUT_COLS": list(do.columns[len(orig):]) == RESULT_COLS,
        "id_identical_same_order": bool((do["id"] == di["id"]).all()),
        "id_is_0_to_N_minus_1_in_order": bool((di["id"] == pd.Series(range(N)).astype(str)).all()),
        "cells_differing_per_original_column": {c: int((do[c] != di[c]).sum()) for c in orig},
    })
    log("format:", {k: fmt[k] for k in ("row_count_equal", "id_identical_same_order", "cells_differing_per_original_column",
                                         "byte_prefix_mismatches")})
    res["1_format"] = fmt

    # ------------------------------------------------------------------ 2. determinism across duplicates
    log("determinism across duplicated URLs")
    do["_row"] = np.arange(N)
    do["_part"] = do["_row"] // PART
    do["_chunk"] = do["_row"] // CHUNK
    mult = do.groupby("url", sort=False)["_row"].transform("size")
    dup = do[mult > 1]
    n_unique = int(do["url"].nunique())
    parts_per_url = dup.drop_duplicates(["url", "_part"]).groupby("url", sort=False).size()
    chunks_per_url = dup.drop_duplicates(["url", "_chunk"]).groupby("url", sort=False).size()
    det = {
        "unique_urls": n_unique, "urls_appearing_more_than_once": int(dup["url"].nunique()),
        "rows_in_duplicated_groups": int(len(dup)), "max_copies_of_one_url": int(mult.max()),
        "copies_distribution": {str(k): int(v) for k, v in
                                do.drop_duplicates("url").assign(m=mult).m.value_counts().sort_index().items()},
        "duplicated_urls_spanning_2plus_1000_row_parts": int((parts_per_url >= 2).sum()),
        "duplicated_urls_spanning_2plus_20000_row_chunks": int((chunks_per_url >= 2).sum()),
        "note_on_processes": "cli.run sends each 20,000-row chunk to a 4-process pool as 20 parts of 1,000 rows; "
                             "which process scored which part is not recorded, so 'different processes' is likely "
                             "for copies in different parts but not proven per pair",
    }
    viol = {}
    for c in RESULT_COLS:
        k = int(len(dup[["url", c]].drop_duplicates()) - dup["url"].nunique())
        viol[c] = k
    all_combo = int(len(dup[["url"] + RESULT_COLS].drop_duplicates()) - dup["url"].nunique())
    det["violations_extra_distinct_values_per_column"] = viol
    det["urls_with_any_differing_result_column"] = int(
        (dup[["url"] + RESULT_COLS].drop_duplicates().groupby("url", sort=False).size() > 1).sum())
    det["extra_distinct_result_tuples_total"] = all_combo
    log("determinism:", det["violations_extra_distinct_values_per_column"])
    res["2_determinism"] = det

    # ------------------------------------------------------------------ 3. ERROR rows
    err = do[do["fraud_verdict"] == "ERROR"]
    res["3_error_rows"] = {
        "count": int(len(err)),
        "error_message_counts": err["error"].value_counts().to_dict(),
        "non_error_rows_with_nonempty_error_column": int(((do["fraud_verdict"] != "ERROR") & (do["error"] != "")).sum()),
        "error_rows_with_empty_probability_confidence_reasons": int(
            ((err["fraud_probability"] == "") & (err["verdict_confidence"] == "") & (err["top_reasons"] == "")).sum()),
        "rows": [{"id": r.id, "url": r.url, "url_repr": repr(r.url), "error": r.error,
                  "registrable_domain": r.registrable_domain, "copies_in_input": int(mult[r.Index])}
                 for r in err.itertuples()],
    }
    log("errors:", res["3_error_rows"]["error_message_counts"])

    # ------------------------------------------------------------------ 4. verdicts, probabilities, reasons
    log("verdict / probability / reasons statistics")
    ok = do[do["fraud_verdict"] != "ERROR"].copy()
    ok["p"] = ok["fraud_probability"].astype(float)
    ok["conf"] = ok["verdict_confidence"].astype(float)
    reasons = ok["top_reasons"].str.split("; ")
    ok["n_reasons"] = np.where(ok["top_reasons"] == "", 0, reasons.str.len())
    ok["reasons_len"] = ok["top_reasons"].str.len()
    vc = do["fraud_verdict"].value_counts()
    sec4 = {"verdict_counts": {k: int(v) for k, v in vc.items()},
            "verdict_share": {k: round(float(v) / N, 6) for k, v in vc.items()},
            "probability_format_ok_rows": int(ok["fraud_probability"].str.fullmatch(r"[01]\.\d{3}").sum()),
            "confidence_format_ok_rows": int(ok["verdict_confidence"].str.fullmatch(r"[01]\.\d{3}").sum()),
            "scored_rows": int(len(ok)),
            "probability_deciles_by_verdict": {v: qdict(g["p"]) for v, g in ok.groupby("fraud_verdict")},
            "probability_deciles_all_scored": qdict(ok["p"]),
            "probability_mean_by_verdict": {v: round(float(g["p"].mean()), 4) for v, g in ok.groupby("fraud_verdict")},
            "review_rows_with_p_below_0.5": int(((ok.fraud_verdict == "REVIEW") & (ok.p < 0.5)).sum()),
            "review_rows_with_p_at_or_above_0.5": int(((ok.fraud_verdict == "REVIEW") & (ok.p >= 0.5)).sum()),
            "n_reasons_counts_by_verdict": {}, "n_reasons_share_by_verdict": {},
            "top_reasons_cell_length_chars": {}, "top10_reason_phrases": {}, "top10_reason_templates": {},
            "reason_direction_counts_by_verdict": {}}
    for v, g in ok.groupby("fraud_verdict"):
        cnt = g["n_reasons"].value_counts().sort_index()
        sec4["n_reasons_counts_by_verdict"][v] = {str(k): int(x) for k, x in cnt.items()}
        sec4["n_reasons_share_by_verdict"][v] = {str(k): round(float(x) / len(g), 4) for k, x in cnt.items()}
        sec4["top_reasons_cell_length_chars"][v] = {"mean": round(float(g["reasons_len"].mean()), 1),
                                                    "max": int(g["reasons_len"].max())}
    sec4["top_reasons_cell_length_chars"]["all_scored"] = {"mean": round(float(ok["reasons_len"].mean()), 1),
                                                           "max": int(ok["reasons_len"].max())}
    sec4["top_reasons_cell_length_chars"]["all_rows_incl_error"] = {
        "mean": round(float(do["top_reasons"].str.len().mean()), 1), "max": int(do["top_reasons"].str.len().max())}
    longest = ok.loc[ok["reasons_len"].idxmax()]
    sec4["longest_top_reasons_cell"] = {"id": longest["id"], "verdict": longest["fraud_verdict"],
                                        "chars": int(longest["reasons_len"]), "text": longest["top_reasons"]}
    ex = ok[["fraud_verdict", "_row"]].assign(r=reasons).explode("r")
    ex = ex[ex["r"].notna() & (ex["r"] != "")]
    ex["phrase"] = ex["r"].str.split("(", n=1).str[0].str.strip()
    ex["template"] = ex["phrase"].str.replace(r"'\.[^']*'", "'.TLD'", regex=True).str.replace(r"\d+(\.\d+)?", "N", regex=True)
    ex["direction"] = np.where(ex["r"].str.endswith("(raises risk)"), "raises risk",
                               np.where(ex["r"].str.endswith("(lowers risk)"), "lowers risk", "other"))
    for v, g in ex.groupby("fraud_verdict"):
        nv = int((ok["fraud_verdict"] == v).sum())
        for key, col in (("top10_reason_phrases", "phrase"), ("top10_reason_templates", "template")):
            occ = g[col].value_counts().head(10)
            rows_with = g.drop_duplicates(["_row", col])[col].value_counts()
            sec4[key][v] = [{col: k, "occurrences": int(c), "rows_with_it": int(rows_with[k]),
                             "share_of_verdict_rows": round(float(rows_with[k]) / nv, 4)} for k, c in occ.items()]
        sec4["reason_direction_counts_by_verdict"][v] = {k: int(c) for k, c in g["direction"].value_counts().items()}
        sec4.setdefault("distinct_reason_phrases_by_verdict", {})[v] = int(g["phrase"].nunique())
    sec4["total_reasons_written"] = int(len(ex))
    rep_rows = ex.loc[ex.duplicated(["_row", "phrase"]), "_row"].unique()
    sec4["rows_with_a_repeated_phrase_in_same_cell"] = int(len(rep_rows))
    sec4["repeated_phrase_examples"] = [{"id": do.at[int(i), "id"], "verdict": do.at[int(i), "fraud_verdict"],
                                         "top_reasons": do.at[int(i), "top_reasons"]} for i in rep_rows[:5]]
    sec4["top_reasons_cells_containing_a_comma"] = int(ok["top_reasons"].str.contains(",", regex=False).sum())
    sec4["top_reasons_cells_with_redirect_parameter_phrase"] = int(
        ok["top_reasons"].str.contains("redirect parameter (url=, next=, ...)", regex=False).sum())
    res["4_content"] = sec4
    log("verdicts:", sec4["verdict_counts"])

    # ------------------------------------------------------------------ 5. spreadsheet practicality
    log("spreadsheet checks")
    visible = [c for c in do.columns if not c.startswith("_")]
    lens = {c: do[c].str.len() for c in visible}
    utf16 = {c: lens[c] + do[c].str.count(r"[\U00010000-\U0010FFFF]") for c in visible}
    col_max = {c: int(utf16[c].max()) for c in visible}
    top_col = max(col_max, key=col_max.get)
    i_top = int(utf16[top_col].idxmax())
    starts = {}
    for c in visible:
        s0 = do[c].str[:1]
        starts[c] = {ch: int((s0 == ch).sum()) for ch in ("=", "+", "-", "@", "\t", "\r", "'")}
    sp = {
        "rows_including_header": N + 1, "excel_max_rows": EXCEL_MAX_ROWS, "fits_row_limit": N + 1 <= EXCEL_MAX_ROWS,
        "row_headroom": EXCEL_MAX_ROWS - (N + 1),
        "max_cell_length_utf16_units_by_column": col_max,
        "longest_cell": {"column": top_col, "id": do.at[i_top, "id"], "utf16_units": col_max[top_col],
                         "chars": int(lens[top_col][i_top]), "first_120_chars": do.at[i_top, top_col][:120]},
        "cells_over_32767": int(sum(int((utf16[c] > EXCEL_MAX_CELL).sum()) for c in visible)),
        "cells_over_10000": int(sum(int((utf16[c] > 10_000).sum()) for c in visible)),
        "cells_starting_with_char_by_column": starts,
        "input_cells_starting_with_formula_char": {c: {ch: int((di[c].str[:1] == ch).sum()) for ch in "=+-@"} for c in orig},
    }
    q = do[RESULT_COLS].apply(lambda s: s.str.startswith("'"))
    gen_q = {c: do.loc[q[c].to_numpy(), c] for c in RESULT_COLS}
    sp["generated_cells_starting_with_quote"] = {
        c: {"total": int(len(v)), "added_by_safe_cell": int(v.str[1:2].isin(["=", "+", "-", "@"]).sum()),
            "native_text_starting_with_quote": int((~v.str[1:2].isin(["=", "+", "-", "@"])).sum()),
            "native_starts_with_redirect_trick_phrase": int(v.str.startswith("'//' inside the path").sum())}
        for c, v in gen_q.items() if len(v)}
    sp["generated_cells_starting_with_quote_examples"] = [
        {"id": do.at[i, "id"], "column": c, "value": do.at[i, c]} for c in RESULT_COLS for i in do.index[q[c].to_numpy()][:5]]
    # _safe_cell unit behaviour and a controlled end-to-end run (safe mode, no network)
    sp["safe_cell_unit"] = {v: cli._safe_cell(v) for v in ("=1+1", "+1", "-1", "@SUM(A1)", "a=b", "", "'x")}
    ftd = os.path.join(TMP, "audit_formula")
    os.makedirs(ftd, exist_ok=True)
    fin, fout = os.path.join(ftd, "formula_test.csv"), os.path.join(ftd, "formula_test.out.csv")
    test_urls = ['=HYPERLINK("http://evil.example/x","click")', "=1+1", "+evil.example/login", "-evil.example/login",
                 "@evil.example/login", "http://-evil.example/", "https://@evil.example/", "http://example.com/=1+1"]
    pd.DataFrame({"id": range(len(test_urls)), "url": test_urls, "note": ["=2+2"] * len(test_urls)}).to_csv(fin, index=False)
    cli.run(fin, fout, workers=1, quiet=True)
    raw_lines = open(fout, "rb").read().decode("utf-8-sig").split("\r\n")
    ft = pd.read_csv(fout, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    sp["controlled_formula_test"] = {
        "note": "a small CSV run through cli.run (safe mode, 1 worker) to show how such values are written",
        "rows": [{"input_url": u, "raw_output_line": raw_lines[k + 1],
                  "url_cell_written": ft.at[k, "url"], "note_cell_written": ft.at[k, "note"],
                  "verdict": ft.at[k, "fraud_verdict"], "registrable_domain_cell": ft.at[k, "registrable_domain"],
                  "error": ft.at[k, "error"]} for k, u in enumerate(test_urls)],
        "input_columns_passed_through_unprotected": int(sum(ft.at[k, "url"] == u for k, u in enumerate(test_urls))),
    }
    res["5_spreadsheet"] = sp
    log("longest cell:", sp["longest_cell"]["column"], sp["longest_cell"]["utf16_units"])

    # ------------------------------------------------------------------ 6. bytes per row and per column
    log("size accounting")
    col_bytes, col_quoted = {}, {}
    for c in visible:
        col_bytes[c], col_quoted[c] = written_bytes(do[c])
    header_bytes = len("".join(visible).encode("utf-8"))  # header names only; its commas/CRLF are in sep_bytes
    n_fields = len(visible)
    sep_bytes = (n_fields - 1) * (N + 1) + 2 * (N + 1)  # commas + CRLF on every record incl. header
    total = 3 + header_bytes + sep_bytes + sum(col_bytes.values())
    out_size = os.path.getsize(OUTP)
    tr = ex["r"]
    size = {
        "output_bytes": out_size, "bytes_per_row": round(out_size / N, 1), "input_bytes": os.path.getsize(INP),
        "input_bytes_per_row": round(os.path.getsize(INP) / N, 1),
        "output_to_input_ratio": round(out_size / os.path.getsize(INP), 3),
        "reconstructed_bytes": total, "reconstruction_matches_file_size": total == out_size,
        "bom_bytes": 3, "header_name_bytes": header_bytes, "comma_and_crlf_bytes": sep_bytes,
        "bytes_by_column": col_bytes,
        "bytes_per_row_by_column": {c: round(b / N, 1) for c, b in col_bytes.items()},
        "share_of_file_by_column": {c: round(b / out_size, 4) for c, b in col_bytes.items()},
        "quoted_cells_by_column": col_quoted,
        "original_columns_bytes": int(sum(col_bytes[c] for c in orig)),
        "added_columns_bytes": int(sum(col_bytes[c] for c in RESULT_COLS)),
        "inside_top_reasons": {
            "direction_suffix_bytes_(raises/lowers risk)": int(tr.str.extract(r"( \((?:raises|lowers) risk\))$")[0]
                                                               .fillna("").str.len().sum()),
            "separator_bytes_('; ')": int(2 * (ok["n_reasons"].clip(lower=1) - 1).sum()),
            "tld_training_rate_parenthetical_bytes": int(tr.str.extract(r"( \(\d+% of training URLs with it were phishing\))")[0]
                                                        .fillna("").str.len().sum()),
            "all_top_reasons_bytes": col_bytes["top_reasons"],
        },
        "analysis_mode_distinct_values": do["analysis_mode"].value_counts().to_dict(),
        "lookup_status_nonempty": int((do["lookup_status"] != "").sum()),
        "registrable_domain_empty": int((do["registrable_domain"] == "").sum()),
        "registrable_domain_empty_by_verdict": do.loc[do["registrable_domain"] == "", "fraud_verdict"].value_counts().to_dict(),
        "registrable_domain_empty_examples": do.loc[do["registrable_domain"] == "", "url"].head(5).tolist(),
        "registrable_domain_empty_where_host_is_itself_a_public_suffix": int(sum(
            1 for u in do.loc[do["registrable_domain"] == "", "url"]
            if (lambda p: bool(p.host) and p.host == p.suffix)(cli.ParsedURL(u)))),
    }
    res["6_size"] = size
    log("bytes/row:", size["bytes_per_row"], "reconstructed ok:", size["reconstruction_matches_file_size"])

    # ------------------------------------------------------------------ 7. verdict vs probability vs thresholds
    log("threshold consistency")
    # default run: --base-rate not given -> p_adj == p; the file holds f"{p:.3f}" so |r - p| <= 0.0005.
    r, v = ok["p"], ok["fraud_verdict"]
    f_lo = np.ceil((th_f - 0.0005) * 1000 - 1e-9) / 1000     # smallest rounded value a FRAUD row can show
    f_hi = np.floor((th_f + 0.0005) * 1000 + 1e-9) / 1000    # largest rounded value a non-FRAUD row can show
    l_hi = np.floor((th_l + 0.0005) * 1000 + 1e-9) / 1000    # largest rounded value a LEGITIMATE row can show
    l_lo = np.ceil((th_l - 0.0005) * 1000 - 1e-9) / 1000     # smallest rounded value a non-LEGITIMATE row can show
    eps = 1e-9
    cons = {
        "thresholds_from_model_safe_json": {"fraud": th_f, "legit": th_l},
        "base_rate_used_by_run": "none (CLI default) -> p_adj == p",
        "rounded_bounds": {"FRAUD_needs_rounded_p_at_least": f_lo, "nonFRAUD_needs_rounded_p_at_most": f_hi,
                           "LEGIT_needs_rounded_p_at_most": l_hi, "nonLEGIT_needs_rounded_p_at_least": l_lo},
        "FRAUD_with_rounded_p_below_bound": int(((v == "FRAUD") & (r < f_lo - eps)).sum()),
        "nonFRAUD_with_rounded_p_above_bound": int(((v != "FRAUD") & (r > f_hi + eps)).sum()),
        "LEGIT_with_rounded_p_above_bound": int(((v == "LEGITIMATE") & (r > l_hi + eps)).sum()),
        "nonLEGIT_with_rounded_p_below_bound": int(((v != "LEGITIMATE") & (r < l_lo - eps)).sum()),
        "ambiguous_rows_at_fraud_boundary_by_verdict": v[(r > f_lo - eps) & (r < f_hi + eps)].value_counts().to_dict(),
        "ambiguous_rows_at_legit_boundary_by_verdict": v[(r > l_lo - eps) & (r < l_hi + eps)].value_counts().to_dict(),
    }
    # confidence column: FRAUD conf = p, LEGITIMATE conf = 1 - p, REVIEW conf = max(p, 1 - p) (each rounded separately)
    exp_conf = np.where(v == "FRAUD", r, np.where(v == "LEGITIMATE", 1 - r, np.maximum(r, 1 - r)))
    d = np.abs(ok["conf"].to_numpy() - exp_conf)
    cons["confidence_exact_match"] = int((d < 5e-7).sum())
    cons["confidence_off_by_0.001_rounding"] = int(((d >= 5e-7) & (d < 0.0010005)).sum())
    cons["confidence_off_by_more"] = int((d >= 0.0010005).sum())
    cons["confidence_below_0.5"] = int((ok["conf"] < 0.5).sum())
    res["7_threshold_consistency"] = cons
    log("consistency:", {k: cons[k] for k in cons if k.endswith("bound")})

    # ------------------------------------------------------------------ 7b / 2b. exact re-score in this process
    log("re-scoring boundary rows + a random sample in-process (safe mode)")
    amb = ok[((r > f_lo - eps) & (r < f_hi + eps)) | ((r > l_lo - eps) & (r < l_hi + eps))]
    samp = do.drop(err.index).sample(n=20000, random_state=0)
    pick = pd.concat([amb, samp, err]).drop_duplicates("url")
    cli._init_worker(False, None)
    urls = pick["url"].tolist()
    t1 = time.time()
    out = []
    for i in range(0, len(urls), PART):
        out.extend(cli._chunk_job((urls[i:i + PART], None)))
    rescore_s = time.time() - t1
    mism = Counter()
    for (_, row), o in zip(pick.iterrows(), out):
        for c in RESULT_COLS:
            if cli._safe_cell(o.get(c, "")) != row[c] and c not in ("analysis_mode", "lookup_status"):
                mism[c] += 1
    # exact threshold check for boundary rows using the unrounded probability
    m = cli._MODEL
    amb_exact = Counter()
    for u, verdict in zip(amb.drop_duplicates("url")["url"], amb.drop_duplicates("url")["fraud_verdict"]):
        _, p, _, _ = m.predict(cli.extract(u), want_reasons=True)  # same code path as score_rows
        exp = "FRAUD" if p >= th_f else ("LEGITIMATE" if p <= th_l else "REVIEW")
        amb_exact["agree" if exp == verdict else "disagree"] += 1
    res["7_threshold_consistency"]["boundary_rows_rescored_unique_urls"] = int(amb["url"].nunique())
    res["7_threshold_consistency"]["boundary_rows_exact_threshold_check"] = dict(amb_exact)
    res["2_determinism"]["in_process_rescore"] = {
        "unique_urls_rescored": len(urls), "random_sample_rows": 20000, "boundary_rows_included": int(len(amb)),
        "error_rows_included": int(len(err)), "seconds_single_process": round(rescore_s, 1),
        "mismatching_cells_by_column_vs_file": {c: int(mism.get(c, 0)) for c in RESULT_COLS
                                                if c not in ("analysis_mode", "lookup_status")},
    }
    log("rescore mismatches:", dict(mism), "boundary exact:", dict(amb_exact))

    res["runtime_seconds"] = round(time.time() - T0, 1)
    with open(RES, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1, ensure_ascii=False, default=lambda o: o.item() if hasattr(o, "item") else str(o))
    log("wrote", RES)


if __name__ == "__main__":
    main()
