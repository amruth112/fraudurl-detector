"""Laya experiments (CPU): zero-shot log-odds under several prompts + frozen embeddings.

Usage:
  python experiments/laya_eval.py zeroshot --data <csv> --checkpoint multilingual --n-test 1500
  python experiments/laya_eval.py embed    --data <csv> --checkpoint multilingual --n-train 6000

The input CSV must have columns: url, label (1 = phishing), split (train/val/test), group.
Outputs go to results/laya/*.npz so the analysis step never needs to re-run the model.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("USE_TF", "0")

import numpy as np
import pandas as pd
import psutil
import torch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RESULTS  # noqa: E402

import laya  # noqa: E402
from laya.agent import Agent  # noqa: E402
from laya.common import collate_items  # noqa: E402

CKPT = {"multilingual": "convaiinnovations/laya-multilingual", "english": "convaiinnovations/laya"}

# Three wordings, as recommended by the runtime investigation (noul answers can follow
# the option labels rather than the input, so the wording itself is a variable).
PROMPTS = {
    "default": {"type": "noul", "instructions": "Is this URL a phishing, scam or fraudulent link?"},
    "criteria": {"type": "noul", "instructions": "Is `url` a phishing, scam or fraudulent link?",
                 "criteria": {"true": "phishing, scam or fraud", "false": "a legitimate website"}},
    "ab_labels": {"type": "noul", "instructions": "Does this URL point to a phishing or fraudulent website?",
                  "labels": {"true": "A", "false": "B"}},
}


def noul_margin(agent, states, question, bs=32):
    """Raw (pre-temperature) log-odds of 'true' for one noul question, unrounded."""
    qid = "q"
    Agent._check_question(qid, question)
    internal = {qid: Agent._to_internal(question)}
    out = []
    with torch.inference_mode():
        for s in range(0, len(states), bs):
            enc = [agent._encode_state(st, [qid], internal) for st in states[s:s + bs]]
            logits, _ = agent._forward(collate_items(enc, agent.tok.pad_token_id))
            out.append(logits[:, 1] - logits[:, 0])
    return np.concatenate(out)


def sample(df, split, n, seed=0):
    d = df[df.split == split]
    if n and len(d) > n:  # stratified sample keeps the class balance of the split
        frac = n / len(d)
        d = pd.concat([g.sample(int(round(len(g) * frac)), random_state=seed)
                       for _, g in d.groupby("label")])
    return d


def signals_text(url):
    """Render the engineered lexical signals as text, to test whether Laya can reason over them."""
    from fraudurl import lexical as lx
    f = lx.extract(url)
    bits = []
    if f.get("host_is_ip"): bits.append("host is a raw IP address")
    if f.get("brand_in_sub"): bits.append("a well-known brand name appears in the subdomain")
    if f.get("brand_in_path"): bits.append("a well-known brand name appears in the path")
    if f.get("brand_typo"): bits.append("the domain looks like a misspelling of a well-known brand")
    if f.get("brand_is_sld"): bits.append("the domain is exactly a well-known brand's domain")
    if f.get("sus_words_host"): bits.append(f"{int(f['sus_words_host'])} credential/payment words in the hostname")
    if f.get("sus_words_path"): bits.append(f"{int(f['sus_words_path'])} credential/payment words in the path")
    if f.get("private_suffix") or f.get("user_content_host"): bits.append("hosted on a free/user-content hosting platform")
    if f.get("shortener"): bits.append("uses a URL shortener")
    if f.get("host_punycode"): bits.append("the hostname uses punycode (possible look-alike characters)")
    bits.append(f"hostname has {int(f.get('host_n_labels', 0))} labels and {int(f.get('host_n_hyphens', 0))} hyphens")
    bits.append(f"URL length {int(f.get('url_len', 0))}")
    return {"url": url, "signals": "; ".join(bits)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["zeroshot", "embed", "signals"])
    ap.add_argument("--data", required=True)
    ap.add_argument("--checkpoint", default="multilingual", choices=list(CKPT))
    ap.add_argument("--n-test", type=int, default=1500)
    ap.add_argument("--n-train", type=int, default=6000)
    ap.add_argument("--n-val", type=int, default=2000)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--tag", default="")
    args = ap.parse_args()
    torch.set_num_threads(args.threads)
    df = pd.read_csv(args.data)
    name = os.path.splitext(os.path.basename(args.data))[0] + (("_" + args.tag) if args.tag else "")
    outdir = os.path.join(RESULTS, "laya"); os.makedirs(outdir, exist_ok=True)
    proc = psutil.Process()

    t0 = time.time()
    agent = laya.load(CKPT[args.checkpoint], device="cpu")
    load_s = time.time() - t0
    rss_loaded = proc.memory_info().rss / 1e6
    print(f"loaded {args.checkpoint} in {load_s:.1f}s rss={rss_loaded:.0f}MB", flush=True)

    if args.mode in ("zeroshot", "signals"):
        test = sample(df, "test", args.n_test)
        val = sample(df, "val", 500)                    # prompt-variant selection
        cal = sample(df, "cal", min(args.n_val, 1000))  # temperature / Platt fitting
        res = {"test_url": test.url.values, "test_y": test.label.values, "test_group": test.group.values,
               "val_url": val.url.values, "val_y": val.label.values,
               "cal_url": cal.url.values, "cal_y": cal.label.values}
        prompts = PROMPTS if args.mode == "zeroshot" else {"signals": PROMPTS["ab_labels"]}  # best wording on val
        for pname, q in prompts.items():
            for part, d in (("val", val), ("cal", cal), ("test", test)):
                states = ([{"url": u} for u in d.url] if args.mode == "zeroshot"
                          else [signals_text(u) for u in d.url])
                t = time.perf_counter()
                m = noul_margin(agent, states, q)
                dt = time.perf_counter() - t
                res[f"{part}_{pname}"] = m
                res[f"{part}_{pname}_ms_per_url"] = dt / len(d) * 1000
                print(f"{pname}/{part}: {len(d)} urls, {dt / len(d) * 1000:.1f} ms/url", flush=True)
        res["rss_peak_MB"] = proc.memory_info().peak_wset / 1e6 if hasattr(proc.memory_info(), "peak_wset") else proc.memory_info().rss / 1e6
        res["load_s"] = load_s
        fp = os.path.join(outdir, f"{args.mode}_{args.checkpoint}_{name}.npz")
        np.savez_compressed(fp, **res)
        print("saved", fp)
    else:
        parts = {"train": sample(df, "train", args.n_train), "val": sample(df, "val", args.n_val),
                 "cal": sample(df, "cal", min(args.n_val, 1000)), "test": sample(df, "test", args.n_test)}
        embed = laya.embed_fn_from_agent(agent, max_length=128, batch_size=64)
        res = {}
        for part, d in parts.items():
            t = time.perf_counter()
            X = embed(list(d.url))
            dt = time.perf_counter() - t
            res[f"{part}_X"] = X.astype(np.float32)
            res[f"{part}_y"] = d.label.values
            res[f"{part}_url"] = d.url.values
            res[f"{part}_group"] = d.group.values
            res[f"{part}_ms_per_url"] = dt / len(d) * 1000
            print(f"embed {part}: {len(d)} urls, {dt / len(d) * 1000:.1f} ms/url", flush=True)
        res["rss_peak_MB"] = proc.memory_info().peak_wset / 1e6 if hasattr(proc.memory_info(), "peak_wset") else proc.memory_info().rss / 1e6
        fp = os.path.join(outdir, f"embed_{args.checkpoint}_{name}.npz")
        np.savez_compressed(fp, **res)
        print("saved", fp)


if __name__ == "__main__":
    main()
