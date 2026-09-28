# Generated results summary (from results/*.json)

## Baselines on phreshphish (domain-grouped test split, n=99,169)

| model | ROC-AUC | PR-AUC | recall@1%FPR | recall@0.1%FPR | FPR@0.5 | FNR@0.5 | ECE | size (bytes or weights) |
|---|---|---|---|---|---|---|---|---|
| logreg | 0.9806 | 0.9814 | 0.847 | 0.665 | 0.0372 | 0.0936 | 0.0032 |  |
| tree | 0.9774 | 0.9742 | 0.825 | 0.000 | 0.0317 | 0.1022 | 0.0116 |  |
| lgbm_small | 0.9881 | 0.9886 | 0.889 | 0.770 | 0.0286 | 0.0716 | 0.0053 | 3428203 |
| lgbm | 0.9881 | 0.9887 | 0.888 | 0.769 | 0.0276 | 0.0703 | 0.0067 | 4289241 |
| char_ngram_lr | 0.9943 | 0.9939 | 0.923 | 0.790 | 0.0206 | 0.0543 | 0.0076 | 998796 |


## Baselines on fresh26 (domain-grouped test split, n=4,718)

| model | ROC-AUC | PR-AUC | recall@1%FPR | recall@0.1%FPR | FPR@0.5 | FNR@0.5 | ECE | size (bytes or weights) |
|---|---|---|---|---|---|---|---|---|
| logreg | 0.9734 | 0.9751 | 0.691 | 0.384 | 0.0616 | 0.1083 | 0.0147 |  |
| tree | 0.9622 | 0.9580 | 0.000 | 0.000 | 0.0896 | 0.1066 | 0.0215 |  |
| lgbm_small | 0.9818 | 0.9829 | 0.763 | 0.510 | 0.0611 | 0.0800 | 0.0118 | 797011 |
| lgbm | 0.9826 | 0.9837 | 0.785 | 0.488 | 0.0603 | 0.0766 | 0.0104 | 1118771 |
| char_ngram_lr | 0.9817 | 0.9825 | 0.770 | 0.476 | 0.0684 | 0.0753 | 0.0198 | 375285 |


## Baselines on hannousse (domain-grouped test split, n=2,369)

| model | ROC-AUC | PR-AUC | recall@1%FPR | recall@0.1%FPR | FPR@0.5 | FNR@0.5 | ECE | size (bytes or weights) |
|---|---|---|---|---|---|---|---|---|
| logreg | 0.9164 | 0.9285 | 0.464 | 0.194 | 0.1129 | 0.2275 | 0.0375 |  |
| tree | 0.8820 | 0.8604 | 0.000 | 0.000 | 0.2478 | 0.1401 | 0.0523 |  |
| lgbm_small | 0.9491 | 0.9594 | 0.632 | 0.500 | 0.1111 | 0.1287 | 0.0319 | 536984 |
| lgbm | 0.9503 | 0.9594 | 0.619 | 0.466 | 0.1085 | 0.1271 | 0.0282 | 769464 |
| char_ngram_lr | 0.9655 | 0.9701 | 0.698 | 0.279 | 0.1199 | 0.1012 | 0.0399 | 242292 |


## Laya on PhreshPhish (same 1,500 unseen-domain test URLs for every row)

| variant | ROC-AUC | PR-AUC | recall@1%FPR | ms/URL | ECE shipped | ECE after Platt |
|---|---|---|---|---|---|---|
| zero-shot english / prompt 'ab_labels' | 0.8891 | 0.8727 | 0.306 | 436 | 0.346 | 0.106 |
| zero-shot english / prompt 'criteria' | 0.8880 | 0.8726 | 0.299 | 576 | 0.370 | 0.072 |
| zero-shot english / prompt 'default' | 0.8951 | 0.8875 | 0.322 | 511 | 0.350 | 0.105 |
| zero-shot multilingual / prompt 'ab_labels' | 0.8315 | 0.7401 | 0.032 | 189 | 0.413 | 0.072 |
| zero-shot multilingual / prompt 'criteria' | 0.5321 | 0.4268 | 0.001 | 213 | 0.475 | 0.140 |
| zero-shot multilingual / prompt 'default' | 0.7568 | 0.6147 | 0.007 | 212 | 0.393 | 0.093 |
| zero-shot multilingual URL + engineered signals as text | 0.8662 | 0.8117 | 0.085 | 221 | 0.386 | 0.054 |
| multilingual frozen embeddings + logistic regression (6k train) | 0.9677 | 0.9648 | 0.621 | 116 |  |  |
| fine-tuned (head_multilingual, RLCD loss, 6k train, 70 min CPU) | 0.9331 | 0.9337 | 0.548 | 93 |  |  |
| **lgbm (295k train) on the same URLs** | 0.9904 | 0.9904 | 0.877 | 0.03 |  |  |
| **char_ngram_lr (295k train) on the same URLs** | 0.9954 | 0.9950 | 0.924 | 0.08 |  |  |

Paired bootstrap (1,000 resamples) of Laya minus LightGBM on identical URLs; stacking = LightGBM + Laya score (fit on one half, scored on the other); cascade = Laya only for LightGBM's uncertain 0.2-0.8 band.

| Laya variant | ΔROC-AUC 95% CI | Δrecall@1%FPR 95% CI | stack recall@1%: LGBM -> +Laya | cascade recall@1% |
|---|---|---|---|---|
| zeroshot_english | [-0.120, -0.086] | [-0.818, -0.435] | 0.900 -> 0.897 | 0.889 |
| zeroshot_multilingual | [-0.180, -0.138] | [-0.907, -0.777] | 0.900 -> 0.900 | 0.877 |
| signals_multilingual | [-0.143, -0.107] | [-0.856, -0.723] | 0.900 -> 0.897 | 0.881 |
| embed_multilingual | [-0.030, -0.016] | [-0.393, -0.156] | 0.900 -> 0.914 | 0.893 |
| finetune_head_multilingual | [-0.070, -0.046] | [-0.510, -0.260] | 0.900 -> 0.906 | 0.880 |


## Equal-data control (all trained on the same 6,000 URLs)

| method | ROC-AUC | PR-AUC | recall@1%FPR | recall@0.1%FPR |
|---|---|---|---|---|
| laya_embedding_LR | 0.9677 | 0.9648 | 0.621 | 0.439 |
| lightgbm_lexical_same_6k | 0.9876 | 0.9877 | 0.875 | 0.552 |
| char_ngram_LR_same_6k | 0.9812 | 0.9809 | 0.830 | 0.483 |
| laya_embedding+lexical_LR_same_6k | 0.9866 | 0.9874 | 0.868 | 0.799 |


## Feature study on phreshphish (82 candidate features)

| feature group | n | val ROC-AUC alone | val ROC-AUC when removed | Δ |
|---|---|---|---|---|
| scheme | 1 | 0.5802 | 0.9880 | -0.0015 |
| lengths_counts | 23 | 0.9399 | 0.9857 | -0.0039 |
| char_composition | 11 | 0.9295 | 0.9879 | -0.0016 |
| host_structure | 17 | 0.8949 | 0.9879 | -0.0016 |
| domain_shape | 11 | 0.9304 | 0.9852 | -0.0044 |
| hosting_platform | 3 | 0.7174 | 0.9896 | 0.0000 |
| path_semantics | 8 | 0.7359 | 0.9890 | -0.0005 |
| brand_keywords | 8 | 0.7273 | 0.9883 | -0.0013 |

| compact set | features | test ROC-AUC | test PR-AUC | recall@1%FPR | recall@0.1%FPR |
|---|---|---|---|---|---|
| forward_top1 | 1 | 0.8609 | 0.8460 | 0.553 | 0.266 |
| forward_top2 | 2 | 0.9334 | 0.9363 | 0.676 | 0.450 |
| forward_top3 | 3 | 0.9570 | 0.9571 | 0.695 | 0.521 |
| forward_top5 | 5 | 0.9777 | 0.9784 | 0.810 | 0.686 |
| forward_top8 | 8 | 0.9831 | 0.9840 | 0.861 | 0.719 |
| forward_top10 | 10 | 0.9854 | 0.9861 | 0.872 | 0.727 |
| forward_top12 | 12 | 0.9860 | 0.9867 | 0.879 | 0.743 |
| forward_top16 | 16 | 0.9872 | 0.9881 | 0.895 | 0.767 |
| forward_top20 | 20 | 0.9886 | 0.9894 | 0.903 | 0.785 |
| all | 82 | 0.9898 | 0.9904 | 0.911 | 0.803 |

Forward-selection order: tld_logit, path_len, sub_len, url_entropy, n_dot, scheme_http, sus_words_path, n_qmark, n_hyphen, path_depth, host_n_digits, host_max_label_len, path_digit_ratio, www_prefix, upper_ratio, sld_n_hyphens, n_equal, private_suffix, n_slash, wp_path

Without format-sensitive features ['scheme_http', 'www_prefix', 'is_homepage']: val ROC-AUC 0.9877 (all: 0.9896)


## Feature study on fresh26 (82 candidate features)

| feature group | n | val ROC-AUC alone | val ROC-AUC when removed | Δ |
|---|---|---|---|---|
| scheme | 1 | 0.6806 | 0.9795 | -0.0042 |
| lengths_counts | 23 | 0.9295 | 0.9813 | -0.0023 |
| char_composition | 11 | 0.9161 | 0.9809 | -0.0028 |
| host_structure | 17 | 0.9052 | 0.9834 | -0.0003 |
| domain_shape | 11 | 0.9345 | 0.9776 | -0.0061 |
| hosting_platform | 3 | 0.7428 | 0.9838 | 0.0001 |
| path_semantics | 8 | 0.7210 | 0.9829 | -0.0008 |
| brand_keywords | 8 | 0.7590 | 0.9810 | -0.0027 |

| compact set | features | test ROC-AUC | test PR-AUC | recall@1%FPR | recall@0.1%FPR |
|---|---|---|---|---|---|
| forward_top1 | 1 | 0.8028 | 0.7867 | 0.138 | 0.080 |
| forward_top2 | 2 | 0.8925 | 0.9086 | 0.439 | 0.278 |
| forward_top3 | 3 | 0.9405 | 0.9435 | 0.509 | 0.297 |
| forward_top5 | 5 | 0.9589 | 0.9616 | 0.640 | 0.282 |
| forward_top8 | 8 | 0.9715 | 0.9733 | 0.676 | 0.451 |
| forward_top10 | 10 | 0.9753 | 0.9769 | 0.711 | 0.515 |
| forward_top12 | 12 | 0.9761 | 0.9778 | 0.730 | 0.535 |
| forward_top16 | 16 | 0.9791 | 0.9807 | 0.768 | 0.554 |
| forward_top20 | 20 | 0.9794 | 0.9810 | 0.773 | 0.548 |
| all | 82 | 0.9835 | 0.9845 | 0.789 | 0.606 |

Forward-selection order: tld_logit, host_len, path_max_seg_len, sub_len, letter_ratio, scheme_http, url_entropy, n_hyphen, host_n_hyphens, n_slash, host_n_digits, private_suffix, brand_in_sld_not_equal, brand_in_path, ext_server, suffix_n_labels, host_max_label_len, path_digit_ratio, path_len, sld_n_hyphens

Without format-sensitive features ['scheme_http', 'www_prefix', 'is_homepage']: val ROC-AUC 0.9804 (all: 0.9837)


## Domain-popularity (Tranco) signal, non-circular evaluations only

| popularity list | PhreshPhish test (AUC / R@1%) | fresh26 HN-legit test | Ariyadasa unseen |
|---|---|---|---|
| no_popularity | 0.9899 / 0.913 | 0.9210 / 0.372 | 0.9308 / 0.254 |
| tranco_top10000 | 0.9897 / 0.907 | 0.9161 / 0.327 | 0.9300 / 0.229 |
| tranco_top100000 | 0.9913 / 0.918 | 0.9184 / 0.319 | 0.9386 / 0.266 |
| tranco_top1000000 | 0.9931 / 0.924 | 0.9131 / 0.237 | 0.9460 / 0.275 |


## Enrichment value on Hannousse 2020 (authors' features, captured while pages were live; grouped 5-fold CV)

| features | ROC-AUC | PR-AUC | recall@1%FPR | recall@0.1%FPR |
|---|---|---|---|---|
| lexical_only | 0.9645 | 0.9678 | 0.681 | 0.409 |
| lexical+domain(whois,dns) | 0.9785 | 0.9793 | 0.767 | 0.410 |
| lexical+page_content | 0.9813 | 0.9810 | 0.761 | 0.391 |
| lexical+domain+page | 0.9869 | 0.9865 | 0.840 | 0.369 |
| domain_only | 0.7577 | 0.7790 | 0.246 | 0.056 |
| page_only | 0.9208 | 0.9158 | 0.244 | 0.060 |
| lexical+domain+page+reputation(CIRCULAR) | 0.9917 | 0.9917 | 0.885 | 0.399 |


## Enrichment value on fresh26e (live DoH DNS + RDAP, 8,000 URLs, grouped 5-fold CV)

| features | ROC-AUC | PR-AUC | recall@1%FPR | recall@0.1%FPR |
|---|---|---|---|---|
| lexical_only | 0.9811 | 0.9824 | 0.784 | 0.606 |
| lexical+dns | 0.9898 | 0.9906 | 0.862 | 0.710 |
| lexical+rdap | 0.9846 | 0.9860 | 0.817 | 0.641 |
| lexical+dns+rdap | 0.9907 | 0.9916 | 0.879 | 0.736 |
| dns+rdap_only | 0.9632 | 0.9647 | 0.614 | 0.251 |
| lexical+dns+rdap__but_unavailable_at_test | 0.9644 | 0.9669 | 0.665 | 0.454 |
| live_only: lexical_only | 0.9813 | 0.9771 | 0.773 | 0.594 |
| live_only: lexical+dns+rdap_no_existence | 0.9868 | 0.9837 | 0.818 | 0.614 |
| recent_phish_7d: lexical_only | 0.9535 | 0.7735 | 0.605 | 0.388 |
| recent_phish_7d: lexical+dns+rdap | 0.9705 | 0.8511 | 0.701 | 0.466 |


## Stale-domain leakage demonstration (PhreshPhish Sep-Dec 2025 URLs resolved today)

Share by DNS status: {"0": {"nodata": 0.0, "nxdomain": 0.0, "ok": 1.0, "servfail": 0.0, "skip": 0.0, "timeout": 0.0}, "1": {"nodata": 0.006, "nxdomain": 0.444, "ok": 0.532, "servfail": 0.01, "skip": 0.004, "timeout": 0.004}}. ROC-AUC of the single feature 'does not resolve today': 0.729


## Cross-dataset generalisation (train on A, test on B's domains never seen in A)

| train | test | model | ROC-AUC | recall@1%FPR | recall (phishing-only sets) |
|---|---|---|---|---|---|
| fresh26 | phreshphish | all_lexical | 0.9552 | 0.646 | — |
| fresh26 | phreshphish | char_ngram_lr | 0.9456 | 0.515 | — |
| hannousse | phreshphish | all_lexical | 0.8854 | 0.253 | — |
| hannousse | phreshphish | char_ngram_lr | 0.8425 | 0.055 | — |
| phreshphish | fresh26 | all_lexical | 0.9429 | 0.413 | — |
| phreshphish | fresh26 | char_ngram_lr | 0.9286 | 0.365 | — |
| phreshphish | hannousse | all_lexical | 0.8453 | 0.253 | — |
| phreshphish | hannousse | char_ngram_lr | 0.8137 | 0.037 | — |
| phreshphish | openphish26 | all_lexical | — | — | 0.881 |
| phreshphish | openphish26 | char_ngram_lr | — | — | 0.870 |


## Shipped model: safe

```
{
 "meta": {
  "version": 1,
  "tag": "safe",
  "trained_on": {
   "phreshphish": 0.55,
   "fresh26": 0.35,
   "hannousse": 0.1
  },
  "n_train": 316682,
  "n_trees": 400,
  "leaves": 15,
  "calibration": "platt",
  "calibration_cv_logloss": {
   "platt": 0.15262007986878132,
   "isotonic": 0.15297367935681558
  },
  "calibration_base_rate": 0.4711891506613912,
  "calibration_and_thresholds": "CAL splits weighted by dataset share (same as training)",
  "threshold_targets": {
   "fpr": 0.01,
   "fnr": 0.02
  },
  "created": "2026-09-25"
 },
 "model_file": "fraudurl/data/model_safe.json",
 "model_bytes": 459430,
 "train_seconds": 64.44119048118591,
 "pure_python_max_abs_diff": [
  1.2434497875801753e-14,
  8.881784197001252e-15
 ],
 "end_to_end_max_abs_prob_diff": 5.551115123125783e-16,
 "thresholds": {
  "fraud": 0.8727196507443908,
  "legit": 0.10087719304430696
 }
}
```

| test set | n | ROC-AUC | PR-AUC | recall@1%FPR | ECE | FRAUD | REVIEW | LEGIT | legit→FRAUD | phish→LEGIT |
|---|---|---|---|---|---|---|---|---|---|---|
| phreshphish | 99169 | 0.9840 | 0.9846 | 0.853 | 0.0207 | 0.353 | 0.182 | 0.465 | 0.0029 | 0.0264 |
| fresh26 | 4718 | 0.9748 | 0.9767 | 0.729 | 0.0161 | 0.406 | 0.240 | 0.354 | 0.0178 | 0.0161 |
| hannousse | 2369 | 0.9071 | 0.9272 | 0.513 | 0.0379 | 0.297 | 0.446 | 0.257 | 0.0132 | 0.0494 |

| external set (unseen domains) | n | ROC-AUC | recall@1%FPR | FRAUD | REVIEW | LEGIT | legit→FRAUD | phish→LEGIT |
|---|---|---|---|---|---|---|---|---|
| ariyadasa | 54613 | 0.9581 | 0.581 | 0.327 | 0.334 | 0.339 | 0.0185 | 0.0211 |
| jpcert_recent | 13291 | — | — | 0.574 | 0.407 | 0.020 | — | — |
| openphish26 | 201 | — | — | 0.701 | 0.264 | 0.035 | — | — |
| tranco_home | 6276 | — | — | 0.026 | 0.765 | 0.209 | — | — |


## Shipped model: enrich

```
{
 "n_live_non_platform": 4523,
 "phish_share": 0.16559805438868008,
 "row_counts": {
  "live": 6829,
  "platform_excluded": 2306,
  "kept": 4523
 },
 "live_only": {
  "safe_only_uncalibrated": {
   "roc_auc": 0.9479567527945759,
   "pr_auc": 0.8137134828749277,
   "recall_at_fpr_1pct": 0.43391188251001334,
   "recall_at_fpr_0_1pct": 0.1548731642189586
  },
  "safe+enrichment_uncalibrated": {
   "roc_auc": 0.9624130531222339,
   "pr_auc": 0.8689335947491788,
   "recall_at_fpr_1pct": 0.5794392523364486,
   "recall_at_fpr_0_1pct": 0.22162883845126835
  }
 },
 "model_file": "fraudurl/data/model_enrich.json",
 "model_bytes": 72031,
 "calibration": "platt",
 "thresholds": {
  "fraud": 0.9228930475488746,
  "legit": 0.12471439983607555
 },
 "n_trees": 150,
 "calibration_prior_shift": {
  "from_base_rate": 0.16559805438868008,
  "to_base_rate": 0.4711891506613912,
  "logit_shift": 1.501780544340838,
  "why": "report enriched probabilities at the same reference prevalence as the safe model; monotone, error rates unchanged"
 }
}
```


## CLI benchmark

| run | seconds | URLs/s | peak RAM (MB, all processes) |
|---|---|---|---|
| cold start, 10 URLs, 1 process | 0.3 | 34 | 24 |
| 200000 URLs, 1 process | 197.6 | 1012 | 69 |
| 200000 URLs, 4 processes | 62.9 | 3179 | 223 |

Package size: {"data_files": {"model_enrich.json": 72280, "model_safe.json": 459240, "public_suffix_list.dat": 334786}, "python_code": 96676, "total": 962982}
