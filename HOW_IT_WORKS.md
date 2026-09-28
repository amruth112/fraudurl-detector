# fraudurl: what it does and how it works

> **In one sentence:** a single 450 KB Python file that reads a spreadsheet of links and flags
> phishing offline, at about 1,000 URLs a second per CPU core, with a plain-English reason for every
> call.

## The short version

* **One file, nothing to install.** `fraudurl_standalone.py` is 450 KB and runs on any computer with
  Python 3.9 or newer. It needs no internet, no GPU, no API key and no paid service.
* **Spreadsheet in, spreadsheet out.** Give it a CSV of links and it returns the same CSV with
  `FRAUD`, `LEGITIMATE` or `REVIEW` on every row, a probability, and the top three reasons in plain
  English.
* **It never visits the websites.** It judges the address itself, using 83 clues, such as a brand name in the wrong place, login or payment words, free hosting,
  a risky domain ending, plain `http://` or a random-looking name.
* **It is fast.** It checked 1,000,000 URLs in 6 minutes 20 seconds on an ordinary 4-core desktop,
  using about 230 MB of memory.
* **It was tested on websites it had never seen.** It was trained on 316,682 real URLs and tested on
  new ones:
  * It wrongly flagged only 0.3–1.8% of legitimate URLs.
  * It let only 1.6–2.6% of phishing through (4.9% on older, 2020-era data).
  * The 18–45% of URLs it was unsure about (depending on the data) went to `REVIEW` for a person,
    instead of being guessed.
* **Compared with Laya,** an open general-purpose text-classification model (644–843 MB, not designed for
  URLs): on the same test URLs this tool was more accurate and 94–583 times faster per URL (details in
  REPORT.md §2).

---

## Running it

1. Put your file in the same folder as `fraudurl_standalone.py`.
2. Open a Command Prompt (Windows) or Terminal (Mac/Linux) in that folder.
3. Type the first line below. On Windows, if `python` is not recognised, type `py` instead.

```
python fraudurl_standalone.py my_urls.csv                    # the normal way
python fraudurl_standalone.py my_urls.csv -o results.csv     # choose the output file name
python fraudurl_standalone.py my_urls.csv --url-column Website   # if it picks the wrong column
python fraudurl_standalone.py my_urls.csv --enrich-review    # look up DNS + domain age for the unsure ones (uses the internet)
python fraudurl_standalone.py my_urls.csv --enrich           # look up DNS + domain age for every URL (slowest)
python fraudurl_standalone.py my_urls.csv --block-list block.txt --allow-list allow.txt   # your team's decisions win
python fraudurl_standalone.py my_urls.csv --base-rate 0.01   # "I expect about 1 in 100 to be fraud"
python fraudurl_standalone.py --url https://example.com/login --enrich-review   # one URL, answer on screen (JSON)
```

* **Input:** any CSV, or a plain text file with one URL per line. Excel workbooks (`.xlsx`) must
  first be saved as "CSV UTF-8".
* **Output:** a new file next to the input, named with `.fraudurl` added (`my_urls.csv` becomes
  `my_urls.fraudurl.csv`). Running it again replaces that file without asking.
* **On screen:** a live counter while it runs, then a summary like this:
  ```
  Done: 5 URLs in 0.1s -> my_urls.fraudurl.csv
  Verdicts: ERROR=1, FRAUD=2, LEGITIMATE=2
  ```
* **How long it takes:** about 1,000 URLs a second per CPU core, and about 2,600–3,200 a second on
  4 cores. A few thousand URLs take seconds, and a million take about 6 minutes. The lookups are much
  slower; see "Under the hood".
* **If it complains:** "input file not found" means the file name or folder is wrong.

The default mode is called **offline mode**: it uses only the text of each URL and never touches the
network.

---

## What you get back

### An example

This file went in:

| id | Website | notes |
|---|---|---|
| 1 | `http://paypal-login-verify.example-secure.xyz/signin` | made-up example |
| 2 | `https://www.wikipedia.org/` | |
| 3 | `github.com/python/cpython` | no scheme |
| 4 | `https://my-shop.pages.dev/checkout` | free hosting |
| 5 | `not a url` | |

URLs 1 and 4 are invented for this guide; the names are not meant to point at any real site.

This came out (the original columns, plus eight new ones; three of them shown here):

| id | fraud_verdict | fraud_probability | top_reasons |
|---|---|---|---|
| 1 | **FRAUD** | 0.999 | domain ending '.xyz' (96% of training URLs with it were phishing) (raises risk); well-known brand name in the subdomain (impersonation pattern) (raises risk); uses unencrypted http:// (raises risk) |
| 2 | **LEGITIMATE** | 0.036 | domain ending '.org' (8% of training URLs with it were phishing) (lowers risk); has a 'www.' prefix (lowers risk); subdomain is 3 characters long (lowers risk) |
| 3 | **LEGITIMATE** | 0.079 | domain ending '.com' (23% of training URLs with it were phishing) (lowers risk); uses https:// (or no scheme given) (lowers risk); 4 slashes (lowers risk) |
| 4 | **FRAUD** | 0.967 | domain ending '.pages.dev' (100% of training URLs with it were phishing) (raises risk); domain name is 17% vowels (raises risk); 3 slashes (raises risk) |
| 5 | **ERROR** | | (error column: "not a URL (contains spaces or has no domain name)") |

### The eight added columns

| Column | What it holds |
|---|---|
| `fraud_verdict` | `FRAUD`, `LEGITIMATE`, `REVIEW` (a person should look) or `ERROR` (not a URL) |
| `fraud_probability` | from 0.000 to 1.000: how likely the URL is phishing |
| `verdict_confidence` | For FRAUD rows it equals the fraud probability. For LEGITIMATE rows it is 1 minus it. For REVIEW rows it only shows which way the URL leans: 0.745 on a row with probability 0.255 means "leans legitimate, but not enough to decide". |
| `top_reasons` | up to three plain-English reasons |
| `registrable_domain` | whose site it really is, e.g. `example-secure.xyz` for URL 1 |
| `analysis_mode` | *How* the row was checked, not whether it is safe. `offline (URL text only)` is the default. `enriched (URL + DNS + RDAP)` means lookups were made and worked. `offline (enrichment unavailable for this URL)` means lookups were on but this row was judged from its text only. `offline (URL text only; clear without lookups)` means `--enrich-review` skipped the lookups because the text alone was conclusive. `your block list` / `your allow list` means your own list decided. |
| `lookup_status` | with lookups on: what the DNS and registry lookups returned, or why they were skipped |
| `error` | why a row could not be checked |

**How to read a domain-ending reason.** A reason such as "domain ending '.com' (23% of training URLs
with it were phishing) (lowers risk)" is about the tool's **training data**, which was deliberately
about half phishing. It does not mean 23% of all `.com` websites are phishing. Think of 50% as
"average": an ending well below 50% counts in a URL's favour, and one well above counts against it.
Percentages are rounded, so 99.8% shows as 100%.

---

## What to do with the results

* **FRAUD**: very likely phishing, so block or escalate it. If your list is mostly ordinary traffic,
  some FRAUD rows will be false alarms, because legitimate URLs vastly outnumber phishing. Glance at
  `registrable_domain` first, or use `--base-rate`.
* **REVIEW**: the address alone does not settle it, and a person should decide. Look at
  `registrable_domain` (whose site it really is) and `top_reasons`. **Do not open the link in your
  normal browser to check it.**
* **LEGITIMATE**: very likely fine, but not a guarantee. In testing, 1.6–2.6% of phishing was still
  called LEGITIMATE (4.9% on 2020-era data).
* **ERROR**: the cell was empty or not a URL (see the `error` column). Fix the cell or ignore the
  row.
* **Working through a big file:** in Excel, sort or filter by `fraud_verdict`, then by
  `fraud_probability`, and work from the riskiest rows down.

## Is it safe to use on confidential data?

**In the default mode, yes: nothing leaves your computer.** The tool reads your file and writes a new
file next to it, and that is all.

With `--enrich` or `--enrich-review`, some information does leave your computer (with `--enrich-review`, only
for the unsure URLs):
* The **host name** of each URL (for example `login.example.com`) is sent to Cloudflare's public DNS
  service.
* The **domain** (`example.com`) is sent to the registry in charge of its ending.
* The public list of which registry handles which ending is downloaded from IANA (data.iana.org)
  once a month.
* The rest of the URL, meaning the path and anything after `?` (which can contain e-mail addresses
  or tokens), is **never** sent.
* The host names are also kept on your computer in a `.fraudurl_cache` folder.

Do not use the lookup options on lists you are not allowed to share outside your organisation. Your own
allow/block lists never leave your computer.

It never opens, downloads or submits anything at the URLs being checked, in either mode.

---

## How good it is

All figures were measured on websites (domains) the model had never seen during training.

| Test data | Ranking score (ROC-AUC) | Legitimate wrongly called FRAUD | Phishing wrongly called LEGITIMATE | Sent to REVIEW |
|---|---|---|---|---|
| 2024–25 browsing data (the public PhreshPhish collection) | 0.984 | 0.3% | 2.6% | 18% |
| 2026 data collected for this project | 0.975 | 1.8% | 1.6% | 24% |
| Independent 2021 dataset (Ariyadasa), never used for training | 0.958 | 1.8% | 2.1% | 33% |
| 2020 data (Hannousse), an older style of phishing | 0.907 | 1.3% | 4.9% | 45% |

* **What ROC-AUC means:** pick one phishing URL and one legitimate URL at random; how often does the
  tool give the phishing one the higher score? 1.0 is perfect and 0.5 is a coin toss. 0.98 means
  98 times out of 100.
* **Other checks:**
  * On bare homepages of 1,000 popular sites, 3% were called FRAUD and 76% went to REVIEW.
  * On a small OpenPhish snapshot taken on 2026-09-25 (201 URLs on unseen domains), 3.5% of phishing was
    called LEGITIMATE.
* **These numbers are slightly optimistic.** The final set-up was chosen partly by looking at these
  same test results.
* **Speed:** about 1,000 URLs a second on one core, and about 2,600–3,200 a second on 4 cores
  (1,000,000 URLs in 6 minutes 20 seconds), with memory flat at about 230 MB.

## Limits

* **The biggest risk is that your URLs differ from the training data.** When a model trained on one
  collection was tested on another, ROC-AUC fell to 0.85–0.96. On 2020-era data, 4.9% of phishing
  is called LEGITIMATE. If your URLs come from a very different source, expect worse results than the
  table above.
* **Bare homepages of popular sites** (`https://example.com/`) mostly land in REVIEW, because a bare
  address gives very little to go on.
* **Hosting platforms cut both ways.** Phishing on big legitimate platforms (Google Docs, Forms or Sites,
  Weebly) usually lands in REVIEW and can even be called LEGITIMATE (the Google Forms row in `examples/` is). Sites on heavily abused free-hosting platforms (`pages.dev`,
  `webflow.io`) are usually called FRAUD, including honest ones.
* **Hacked legitimate websites** hosting a phishing page, and carefully disguised URLs, can slip
  through.
* **If your list is mostly normal traffic, most FRAUD rows can be false alarms**, simply because
  legitimate URLs far outnumber phishing. Use `--base-rate` and treat FRAUD as "check first".
* **Scam patterns change**, so the model should be retrained on fresh data from time to time.

---

## Under the hood, step by step

Here is what happens to URL 1, `http://paypal-login-verify.example-secure.xyz/signin`, on its way
from the input file to the output file.

### Step 1: Reading the file

The tool copes with any common spreadsheet export:

* **Text encoding.** It detects UTF-8, UTF-16 (with a byte-order mark) and Windows-1252, the usual
  encoding of Excel on Windows. A file saved in another legacy encoding, such as Chinese GBK or
  Japanese Shift-JIS, is misread, so save such files as UTF-8 first.
* **Separator.** It detects comma, semicolon, tab or pipe; if none fits, it reads one URL per line.
* **Header row and URL column.** It works out which row holds the column names and which column
  holds the URLs. It looks for names like `url`, `link` or `website`, or failing that for the column
  whose values look most like web addresses. In the example it found `Website` by itself. If it ever
  picks the wrong column, name it: `--url-column "Column name"`.
  * One catch: in a file with **no** header whose first line is a bare domain such as `example.com`,
    followed by full links, that first line is taken as a header and gets no verdict. Adding a header
    row such as `url` avoids this.
* **Big files.** It reads the file 20,000 rows at a time and scores them in batches of 1,000 on up to
  4 CPU cores. The file is never loaded whole, so memory stays flat however big it is.

### Step 2: Rejecting things that are not URLs

These values get the verdict `ERROR`, with the reason in the `error` column:
* empty cells,
* values in which no host name can be found (such as `http://`),
* values with a space or other whitespace inside (such as `not a url`),
* host names with no dot (such as `localhost` or `intranet`), unless they are an IP address.

An e-mail address such as `john@example.com` is not rejected: it is scored as a URL with a hidden
`user@` part. Every data row still appears in the output.

### Step 3: Reading the URL the way a browser does

Phishing relies on addresses that look like one thing but lead somewhere else, so the tool first
works out where the URL really points, following the same rules a browser uses.

* **It tidies the text.** It removes surrounding quotes, turns backslashes into forward slashes and
  repairs sloppy forms such as `http:/x`. A missing `https://` is fine; URL 3 had none.
* **It separates the parts:**
  * the scheme (the `http://` or `https://` at the start),
  * any hidden `user@` part,
  * the host name and port,
  * the path (`/signin`) and the query (`?a=b`).

  The `#fragment` at the end is ignored, because browsers never send it to the website.
* **It normalises the host name.** It lower-cases it and decodes %-escapes (codes such as `%2E` that
  stand for a character). International names such as `bücher.de` are converted to their internet
  spelling (`xn--bcher-kva.de`, called punycode), which exposes look-alike letters from other
  alphabets.
* **It recognises disguised IP addresses**, such as `http://0x7f000001/` (written in hexadecimal)
  or `http://2130706433/` (written as a single large number).
* **It finds the registrable domain: the part someone actually bought and controls.** It uses the
  Public Suffix List (publicsuffix.org), a community-maintained list of the endings under which
  people and organisations register their own names. Examples are `.com`, `.co.uk`, the
  government-only `.gov.br`, and hosting platforms like `github.io` or `pages.dev`. The list has
  10,334 rules and is built into the file.
  * For URL 1, the host `paypal-login-verify.example-secure.xyz` splits into the subdomain
    `paypal-login-verify` and the registrable domain `example-secure.xyz`. The site belongs to
    whoever bought `example-secure.xyz`, not to PayPal. That is the classic phishing trick, and splitting the
    host this way exposes it.
  * For URL 4, `pages.dev` is a free hosting platform, so the domain is the user's own subdomain,
    `my-shop.pages.dev`. 3,384 of the list's rules are endings run by companies such as hosting,
    cloud and dynamic-DNS services.

### Step 4: Measuring 83 clues

The URL is turned into 83 numbers, none of which needs the internet. The trained model uses 71 of
them. The other 12 never came out as useful, mostly because they repeat a clue that is used: a
`user@` part is still counted through the number of `@` signs, and a raw IP address through the
domain-ending reputation.

| Group | What is measured | Why it matters |
|---|---|---|
| **Security and structure** | `http` or `https`; a hidden `user@` part; `@` signs; an explicit or unusual port; total length; counts of 16 symbols (dots, hyphens, slashes, `?`, `=`, `&`, `%`, `~`, `!`…) | Phishing links are often unencrypted, long and full of symbols |
| **Character make-up** | share of digits, letters, capitals and symbols; "randomness" of the URL; %-escapes; non-English characters | Machine-generated phishing addresses look random |
| **Tricks** | `//` inside the path; another URL embedded in the link; a redirect setting such as `?url=` or `?next=`; number of settings after `?` | Ways to bounce a victim somewhere else |
| **Host name** | length; number of parts and subdomain levels; `www.`; hyphens and digits; raw IP address; punycode; invalid characters; randomness | e.g. `secure-login.account-verify.x.y.xyz` |
| **Domain name** | length; randomness; digits; hyphens; share of vowels; longest run of consonants or digits; how often it switches between letters and digits | Throw-away names like `xk7qz9-2.top` are hard to pronounce |
| **Domain ending** | the ending's phishing rate (see below); whether it is a free hosting platform, a user-content site (Google Docs or Sites, Dropbox, Weebly…) or a link shortener; whether it is a government or education ending; its length | The single strongest clue |
| **Path** | length; depth; longest segment; digits; randomness; query length; file type (`.php`/`.asp` script, `.html` page, or a risky download such as `.exe`, `.zip`, `.apk`); bare homepage or not | Phishing kits live at paths like `/wp-content/secure/login.php` |
| **Words and brands** | 69 login/payment words (`login`, `verify`, `account`, `wallet`, `invoice`…) in the host or path; WordPress folders; 123 of the most-impersonated brands (PayPal, Microsoft, DHL, banks, crypto exchanges…) | This is the impersonation pattern itself |

For brands, it asks several questions:
* Is the name before the ending exactly a brand (`paypal.com`, but also `paypal.xyz`)?
* Is a brand embedded in someone else's domain, subdomain or path?
* Is the domain name a look-alike spelling of a brand? That covers one typo for brands of five or
  more letters, `paypa1`, `rnicrosoft` and Cyrillic look-alike letters.

**The domain-ending reputation.** From the training data, the tool learned how often each of 1,598
domain endings appeared on phishing URLs. That covers full endings such as `co.uk` and bare ones
such as `uk`. There is one extra entry for URLs with no ending at all, meaning raw IP addresses,
which were 99.9% phishing. Some examples:

| Ending | Share of training URLs that were phishing |
|---|---|
| `.gov` | 0.3% |
| `.co.uk` | 6% |
| `.org` | 8% |
| `.com` | 23% |
| `.xyz` | 96% |
| `.cn` | 98% |
| `.top` | 99.7% |
| `pages.dev` | 99.8% |

The rates are smoothed:
* Each ending's rate is blended with 20 imaginary URLs at its parent's rate, so `gov.br` is pulled
  towards `.br`.
* Endings never seen in training get the parent's rate, or the overall average of 47%.

This stops one unlucky example from giving an ending a bad name. It can also give a clean rare
ending a poor score: `gov.br` had no phishing among its 11 training URLs but is rated 58%, because
most `.br` URLs in training were phishing.

For URL 1 the tool measured, among other things:
* an explicit `http://`,
* 52 characters and 3 hyphens,
* the brand "paypal" in the subdomain but not in the registrable domain,
* 3 login/security words in the host (`login`, `verify`, `secure`) and 1 in the path (`signin`),
* the ending `.xyz` (96%).

### Step 5 (optional): Your own lists, then asking about the domain

**Your own lists come first** (`--block-list`, `--allow-list`). They are plain text files, one domain or URL
per line; anything after the first space is a note. `example.com` covers `example.com` and every subdomain
(`login.example.com`), but not look-alikes such as `notexample.com`. A URL with a path
(`https://example.com/secure/`) covers every URL that starts with it. A listed URL is decided straight away,
FRAUD for the block list and LEGITIMATE for the allow list, with no lookups; the probability is left empty
(it is your team's decision, not the model's) and the reasons still say what the model alone thought. The
block list always wins. Tricks such as `/secure/../other` are resolved first, IP addresses match however they
are written, and ordinary blocklist files in hosts format (`0.0.0.0 evil.test`) work as they are. This is how your team's confirmed decisions (and, later, any
blocklist you choose to use) plug in. Never allow-list a shared platform such as `google.com` or `github.io`:
that would also allow the phishing hosted there.

**Then, optionally, the lookups.** By default the tool never uses the network. With `--enrich-review` it asks two
public directories about the domain of every URL the text check left in REVIEW; with `--enrich` it asks for
every URL. It still never connects to the website itself.

**DNS** is the internet's address book. The tool asks it over an encrypted connection to Cloudflare's
public DNS service (1.1.1.1). It deliberately uses a service that answers truthfully for every
domain. Some DNS services pretend known-bad domains do not exist; relying on one of those would
mean relying on someone else's blocklist, and would make the tool look better in testing than it
really is. It collects:
* how many IPv4 addresses the host has, and whether it has IPv6 addresses,
* whether the name is a nickname (alias) for another name,
* how long other computers may remember the answer,
* whether it points to a private or internal address,
* how many nameservers (the computers that answer for the domain) it has,
* whether the domain can receive email.

**RDAP** is the official registration record, held by the registry (the organisation in charge of
that domain ending). It gives when the domain was registered, when it expires, and for how long it
was registered. Phishing domains are often only days or weeks old and registered for the minimum
one year.

The lookups are deliberately careful:
* **Limits.** At most 8 lookups run at once, and at most 2 requests a second go to each registry
  server.
* **Retries.**
  * A DNS question gives up after 3 seconds and is tried up to 3 times; 4 questions are asked per
    host name.
  * A registry request gives up after 8 seconds. A failed connection is retried once, and a "slow
    down" reply up to twice.
* **Caching.** Answers are cached in a `.fraudurl_cache` folder in the folder you run from, or
  wherever `--cache-dir` points. DNS answers are kept for 7 days and registry answers for 28 days,
  so each host or domain is normally looked up once, not once per URL. "Does not exist" answers and
  DNS server failures are cached too; timeouts, rate-limit replies and connection errors are not,
  and are retried later.
* **Skips.** Raw IP addresses and shared platforms are skipped. For `docs.google.com` or
  `x.pages.dev`, the registration date would describe Google or Cloudflare, not the page an attacker
  put there.
* **If DNS fails,** or shows the name does not exist, the row is scored from its text only and
  `analysis_mode` says so.
* **If only the registry lookup fails,** the extra model runs without registration data. That
  happens when an ending has no registry service (e.g. `.de`, `.io`, `.cn`, `.jp`), or because of a
  rate limit or an error. The row is still labelled `enriched`; only `lookup_status` shows the
  failure. Missing registration data makes the model more cautious. In an offline test on 1,000
  legitimate popular homepages, making every registry lookup fail cut LEGITIMATE verdicts from 338
  to 149, and most of those went to REVIEW.
* **Speed.** It is slow at scale. An estimate for 1,000,000 URLs (about 210,000 distinct domains) is
  16–19 hours with `--enrich`, because of the 2-a-second limit and because about half of all domains are
  `.com`, which a single registry serves. `--enrich-review` only looks up the unsure slice: about 7 hours for
  the same file. The small cost: enrichment can also soften some FRAUD or LEGITIMATE verdicts, which only
  `--enrich` gets to see.
* **Memory.** The lookup cache is held in memory, so the run peaks at about 0.9–1.2 GB for that size
  (about 230 MB without lookups).

### Step 6: The model makes a decision

The model was trained with LightGBM, a widely used free machine-learning toolkit. It was then
exported to a plain data table that about 60 lines of ordinary Python can evaluate, so no
machine-learning library is needed to run it.

* **It is 400 small flowcharts** ("decision trees").
  * Each one contains 14 yes/no questions about the clues and has 15 end points. The questions are
    things like: Is the domain ending's phishing rate high? Is the subdomain long? Is it plain
    `http`?
  * A URL follows one path through each flowchart, answering only the questions on that path. The
    end point it reaches holds a small plus or minus score.
* **The flowcharts were built one after another.** Each new one was trained to fix the mistakes the
  previous ones still made; that is what "gradient boosting" means.
* **The 400 small scores are added up** (plus one fixed starting value) into one raw score. Above
  about +0.1 leans phishing, and below it leans legitimate. For URL 1 the raw score is **+7.46**,
  which is very strongly phishing.
* **When lookups were made, a second, smaller model adds a correction** to the raw score. It has 150
  flowcharts with 6 questions each, based on the DNS and registration facts. For example, "registered
  3 days ago" pushes the score up, and "registered 20 years ago, receives email" pushes it down.
* **Training data:** 316,682 real URLs from three separately collected datasets (2020, 2024–25 and
  2026, weighted 10% / 55% / 35%; their phishing lists partly come from the same public feeds, such
  as PhishTank).

### Step 7: Turning the score into a calibrated probability

A raw score of +7.46 is not a probability, so it goes through an S-shaped curve fitted on a slice of
data the model never trained on. This step is called calibration. The result is roughly a
probability, not an exact one:
* On the independent 2021 test set, URLs given about 0.85 were phishing 84% of the time; on the
  other test sets that band was phishing 82–94% of the time.
* Mid-range scores (0.4–0.8) can be off by up to about 13 points either way.

URL 1 gets **0.999**.

**`--base-rate`.** The training data was about half phishing, so by default the probability assumes a
batch that is about half phishing. If you say you expect, for example, 1% fraud, the tool
re-weights every probability to match. At 1%, a score of 0.97 really means "about 27% chance".

### Step 8: Choosing the verdict

The probability is compared with two cut-offs. They were chosen on held-back data so that about 1% of
legitimate URLs get wrongly flagged and about 2% of phishing gets wrongly cleared.

| Probability | Verdict | Cut-off when lookups were made |
|---|---|---|
| at least **0.873** | **FRAUD** | 0.923 |
| at most **0.101** | **LEGITIMATE** | 0.125 |
| anything in between | **REVIEW** ("the URL alone is not conclusive") | |

**With `--base-rate`, the verdict and the probability can look inconsistent.** The
`fraud_probability` column shows the re-weighted number, but the cut-offs above are applied to the
original one, and a verdict that the re-weighted number contradicts is moved to REVIEW. So you can
see a REVIEW row with a probability as low as 0.004. Read it as: "the URL text alone is
inconclusive, but in a batch like yours it is probably fine". Some FRAUD rows becoming REVIEW is
intended. If you do not know your base rate, leave the option out and treat FRAUD as "check first".

### Step 9: Explaining the decision in plain English

The reasons are not a separate guess made afterwards; they come from the model's own arithmetic.
* As the URL walks through each flowchart, every question changes the running score a little, and
  that change is credited to the clue the question was about.
* Over all 400 flowcharts, these credits plus the fixed starting value (−0.07) add up exactly to the
  raw score. For URL 1: −0.07 + 7.53 = +7.46.

URL 1's largest credits:

| Clue | Credit |
|---|---|
| domain ending `.xyz` | +2.33 |
| brand in the subdomain | +1.70 |
| plain http | +1.10 |
| 3 login words in the host | +1.04 |
| long host name | +0.42 |
| login word in the path | +0.38 |

Up to three of the largest credits pointing towards the verdict are written out as sentences about
this URL. For FRAUD and REVIEW rows these are the biggest risk-raising clues; for LEGITIMATE rows,
the biggest risk-lowering ones. So the output says "uses unencrypted http://", not
"scheme_http = 1".

A single reason can look odd on its own, such as "no hyphens (raises risk)". It only means that, in
the training data, URLs like this one were slightly more often phishing. Read the three together,
and read them with the verdict.

### Step 10: Writing the results

* Every data row is written back in its original order with its original cell values, and the eight
  columns are added.
* The output is always comma-separated UTF-8, with a marker that makes Excel show international
  characters correctly, even if the input used tabs or semicolons. A file without a header gets one
  (`column_1`, `column_2`, …).
* If a row has extra fields they are joined into its last column; short rows are padded.
* **For pipelines**, `--url` (one or more URLs on the command line) or `--format json` writes one JSON
  record per URL instead of a CSV row. It has the same fields plus `stages`: what the text check said,
  whether your list decided, and the raw facts the lookups found (IP addresses, nameservers, mail servers,
  registration and expiry dates, domain age, registrar). With `--url` the answer is printed on screen.
* **Spreadsheet-formula protection covers only the eight added columns.** An added cell that starts
  with `=`, `+`, `-` or `@` gets a leading apostrophe, so a spreadsheet cannot run it as a formula.
  Your original cells are copied exactly as they were. If the URLs come from an untrusted feed, open
  the output with formulas disabled or import it as text.
* It refuses to overwrite the input file.
* If a cell contains a line break, it prints a note at the end, because that usually means a stray
  `"` in the input has merged rows.

---

## Glossary

| Term | Meaning |
|---|---|
| **Registrable domain** | the part of an address someone actually bought and controls, e.g. `example-secure.xyz` in `paypal-login-verify.example-secure.xyz` |
| **Domain ending** (public suffix) | the part after the registrable name: `.com`, `.co.uk`, or a hosting platform such as `pages.dev` |
| **Phishing** | a fake site that tricks people into giving passwords, card numbers or money |
| **REVIEW** | the URL text alone is not conclusive, so a person should decide |
| **Probability** | how likely the URL is phishing, from 0 to 1 |
| **Calibration** | adjusting the model's raw score so that "0.85" really means about 85% |
| **Base rate** | the share of fraud you expect in your own list, e.g. 1 in 100 |
| **ROC-AUC** | how often a random phishing URL scores higher than a random legitimate one (1.0 = perfect, 0.5 = coin toss) |
| **Decision tree / flowchart** | a chain of yes/no questions that ends in a small score |
| **Gradient boosting** | building many small trees, each one fixing the previous ones' mistakes |
| **Randomness (entropy)** | how jumbled the characters are; generated names such as `xk7qz9` score high |
| **Punycode** | the internet spelling of international names (`bücher.de` becomes `xn--bcher-kva.de`) |
| **DNS** | the internet's address book, which turns names into server addresses |
| **RDAP** | the official public record of when a domain was registered and when it expires |
| **Offline mode** | the default: only the URL text is used and nothing goes over the network |

## Where everything is

| File | What it is |
|---|---|
| `fraudurl_standalone.py` | The whole tool in one file: the easiest way to run it anywhere. |
| `fraudurl/` | The same tool as a normal Python package (`python -m fraudurl …`). The single file is generated from it by `experiments/build_single_file.py` and gives identical results. |
| `README.md` | usage reference |
| `REPORT.md` | the full engineering report: data, experiments, the Laya comparison and all measurements |
