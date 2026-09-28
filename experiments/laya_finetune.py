"""Fine-tune Laya for URL phishing on CPU, following the official notebook's recipe.

Stage 'head': freeze the encoder, cache its hidden states once, train the decision head
              (2-layer transformer + scorer) with the notebook's RLCD loss.
Stage 'full': train encoder + head (token embeddings frozen to save memory/time).

Loss (notebook cell 8): L = L_RL + L_CE, where L_RL is REINFORCE over G=4 Gaussian logit
perturbations scored by laya.common.proper_reward (log + 0.75*spherical), sigma annealed
0.4 -> 0.1, and L_CE is soft cross-entropy. AdamW, lr head 1e-4 / encoder 2.5e-5, clip 1.0.
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
import torch.nn.functional as F

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RESULTS, metrics  # noqa: E402
from laya_eval import CKPT, PROMPTS, sample  # noqa: E402

import laya  # noqa: E402
from laya.agent import Agent  # noqa: E402
from laya.common import QTYPES, build_sequence, collate_items, proper_reward  # noqa: E402

Q = PROMPTS["criteria"]


def make_items(agent, urls, labels):
    q = Agent._to_internal(Q)
    ml, hml = agent.cfg.get("max_len", 512), agent.cfg.get("head_max_len", 192)
    items = []
    for u, y in zip(urls, labels):
        ids, markers = build_sequence(agent.tok, {"url": u}, q, ml, hml)
        items.append({"ids": ids, "markers": markers, "qtype": QTYPES["noul"],
                      "target": [1.0 - float(y), float(y)], "label": int(y)})
    return items


def batches(items, bs, shuffle=False, seed=0):
    idx = np.arange(len(items))
    if shuffle:
        np.random.default_rng(seed).shuffle(idx)
    else:  # length-sorted for inference speed
        idx = np.argsort([len(it["ids"]) for it in items], kind="stable")
    for s in range(0, len(idx), bs):
        yield idx[s:s + bs]


def head_forward(model, h, att, mpos, mmask, qtype):
    h = h.float() + model.type_emb(qtype)[:, None, :]
    pad = ~att.bool()
    for layer in model.head.layers:
        h = layer(h, src_key_padding_mask=pad)
    gi = mpos.clamp(min=0)[:, :, None].expand(-1, -1, h.size(-1))
    m = torch.gather(h, 1, gi)
    return model.scorer(m).squeeze(-1).float().masked_fill(~mmask, -1e4)


def rlcd_loss(z, target, mask, qtype, sigma, G=4, w_sph=0.75):
    eps = torch.randn((G,) + tuple(z.shape)) * sigma
    eps = eps * mask
    eps = eps - (eps.sum(-1, keepdim=True) / mask.sum(-1, keepdim=True).clamp(min=1)) * mask
    zt = z.detach()[None] + eps
    qd = torch.softmax(zt.masked_fill(~mask, -1e4), -1)
    with torch.no_grad():
        r = proper_reward(qd, target, qtype, mask, w_sph=w_sph)
        A = (r - r.mean(0, keepdim=True)) / (r.std() + 1e-6)
    logpi = -(((zt - z[None]) ** 2) * mask).sum(-1) / (2 * sigma ** 2)
    l_rl = -(A * logpi).mean()
    l_ce = -(target * F.log_softmax(z.masked_fill(~mask, -1e4), -1)).sum(-1).mean()
    return l_rl + l_ce


@torch.no_grad()
def margins(model, items, bs=64, cache=None):
    model.eval()
    out = np.zeros(len(items), dtype=np.float32)
    for bi in batches(items, bs):
        b = collate_items([[items[i]] for i in bi], PAD[0])
        h = model.encoder(input_ids=b["input_ids"], attention_mask=b["attention_mask"]).last_hidden_state
        z = head_forward(model, h, b["attention_mask"], b["marker_pos"], b["marker_mask"], b["qtype"])
        out[bi] = (z[:, 1] - z[:, 0]).numpy()
    return out


PAD = [0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--checkpoint", default="multilingual", choices=list(CKPT))
    ap.add_argument("--stage", default="head", choices=["head", "full"])
    ap.add_argument("--n-train", type=int, default=6000)
    ap.add_argument("--n-val", type=int, default=1000)
    ap.add_argument("--n-test", type=int, default=1500)
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--bs", type=int, default=32)
    ap.add_argument("--threads", type=int, default=4)
    args = ap.parse_args()
    torch.set_num_threads(args.threads)
    torch.manual_seed(0)
    proc = psutil.Process()
    df = pd.read_csv(args.data)
    name = os.path.splitext(os.path.basename(args.data))[0]
    agent = laya.load(CKPT[args.checkpoint], device="cpu")
    model, PAD[0] = agent.model, agent.tok.pad_token_id
    tr, va, te = sample(df, "train", args.n_train), sample(df, "val", args.n_val), sample(df, "test", args.n_test)
    cal = sample(df, "cal", args.n_val)
    I = {k: make_items(agent, d.url.values, d.label.values) for k, d in
         (("train", tr), ("val", va), ("cal", cal), ("test", te))}
    print({k: len(v) for k, v in I.items()}, "mean tokens", np.mean([len(i["ids"]) for i in I["train"]]), flush=True)

    head_params = [p for n, p in model.named_parameters() if not n.startswith("encoder.")]
    if args.stage == "head":
        for p in model.encoder.parameters():
            p.requires_grad_(False)
        opt = torch.optim.AdamW(head_params, lr=1e-4, weight_decay=0.01)
        # cache encoder states once
        t = time.time()
        cache = []
        model.eval()
        # no_grad, not inference_mode: inference tensors (incl. targets / marker indices built
        # here) cannot be saved for backward when the head is trained on them later.
        with torch.no_grad():
            for bi in batches(I["train"], args.bs, shuffle=True):
                b = collate_items([[I["train"][i]] for i in bi], PAD[0])
                h = model.encoder(input_ids=b["input_ids"], attention_mask=b["attention_mask"]).last_hidden_state
                cache.append((h.to(torch.float16).clone(), b["attention_mask"], b["marker_pos"], b["marker_mask"],
                              b["qtype"], b["target"]))
        print(f"cached encoder states in {time.time() - t:.0f}s rss={proc.memory_info().rss / 1e6:.0f}MB", flush=True)
    else:
        for n, p in model.named_parameters():
            p.requires_grad_(not ("embeddings" in n and n.startswith("encoder.")))
        enc_params = [p for n, p in model.named_parameters() if n.startswith("encoder.") and p.requires_grad]
        opt = torch.optim.AdamW([{"params": enc_params, "lr": 2.5e-5}, {"params": head_params, "lr": 1e-4}],
                                weight_decay=0.01)
    steps = args.epochs * (len(I["train"]) // args.bs + 1)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=steps, eta_min=1e-6)
    log = {"epochs": []}
    step, best = 0, None
    t_train = time.time()
    for ep in range(args.epochs):
        model.train()
        t = time.time()
        losses = []
        if args.stage == "head":
            order = np.random.default_rng(ep).permutation(len(cache))
            for ci in order:
                h, att, mpos, mmask, qt, tgt = cache[ci]
                sigma = 0.4 + (0.1 - 0.4) * step / max(1, steps)
                z = head_forward(model, h, att, mpos, mmask, qt)
                loss = rlcd_loss(z, tgt, mmask, qt, sigma)
                opt.zero_grad(); loss.backward()
                torch.nn.utils.clip_grad_norm_(head_params, 1.0)
                opt.step(); sched.step(); step += 1
                losses.append(float(loss))
        else:
            for bi in batches(I["train"], args.bs, shuffle=True, seed=ep):
                b = collate_items([[I["train"][i]] for i in bi], PAD[0])
                sigma = 0.4 + (0.1 - 0.4) * step / max(1, steps)
                z, _ = model(b["input_ids"], b["attention_mask"], b["marker_pos"], b["marker_mask"], b["qtype"])
                loss = rlcd_loss(z, b["target"], b["marker_mask"], b["qtype"], sigma)
                opt.zero_grad(); loss.backward()
                torch.nn.utils.clip_grad_norm_([p for p in model.parameters() if p.requires_grad], 1.0)
                opt.step(); sched.step(); step += 1
                losses.append(float(loss))
                if step % 20 == 0:
                    print(f"  step {step} loss {np.mean(losses[-20:]):.4f} {time.time() - t:.0f}s", flush=True)
        mv = margins(model, I["val"])
        vm = metrics(va.label.values, 1 / (1 + np.exp(-mv)))
        ep_log = {"epoch": ep + 1, "loss": float(np.mean(losses)), "val_auc": vm["roc_auc"],
                  "val_log_loss": vm["log_loss"], "secs": time.time() - t}
        log["epochs"].append(ep_log)
        print(ep_log, flush=True)
        if best is None or vm["log_loss"] < best[0]:
            best = (vm["log_loss"], ep + 1, {k: v.detach().clone() for k, v in model.state_dict().items()
                                             if not k.startswith("encoder.") or args.stage == "full"})
    log["train_secs"] = time.time() - t_train
    model.load_state_dict(best[2], strict=False)
    log["best_epoch"] = best[1]
    t = time.time()
    res = {"test_margin": margins(model, I["test"]), "test_y": te.label.values, "test_url": te.url.values,
           "cal_margin": margins(model, I["cal"]), "cal_y": cal.label.values, "cal_url": cal.url.values}
    log["infer_ms_per_url"] = (time.time() - t) / (len(te) + len(cal)) * 1000
    log["rss_MB"] = proc.memory_info().rss / 1e6
    log["test_metrics_raw"] = metrics(te.label.values, 1 / (1 + np.exp(-res["test_margin"])))
    print("TEST", {k: log["test_metrics_raw"][k] for k in ("roc_auc", "pr_auc", "recall_at_fpr_1pct", "log_loss")}, flush=True)
    outdir = os.path.join(RESULTS, "laya"); os.makedirs(outdir, exist_ok=True)
    np.savez_compressed(os.path.join(outdir, f"finetune_{args.stage}_{args.checkpoint}_{name}.npz"), **res)
    import json
    with open(os.path.join(outdir, f"finetune_{args.stage}_{args.checkpoint}_{name}.json"), "w") as fh:
        json.dump(log, fh, indent=2, default=float)


if __name__ == "__main__":
    main()
