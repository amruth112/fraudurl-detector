# Security policy

## Reporting a vulnerability

Please report security problems **privately**, using GitHub's **Security → Report a vulnerability** on this
repository. Do not open a public issue for them. You should get a reply within a week.

Examples of what counts:
- a crafted input that makes the tool crash, hang, use unbounded memory, or write outside the output file;
- spreadsheet-formula injection through one of the eight columns the tool adds (original cells are copied
  unchanged by design; see HOW_IT_WORKS.md, Step 10);
- `--enrich` contacting anything other than the DNS-over-HTTPS resolver, the RDAP registries and the IANA
  bootstrap file.

## Wrong verdicts are not vulnerabilities

A phishing URL marked LEGITIMATE, or a legitimate URL marked FRAUD, is a model limitation. Please report it
with the **Wrong verdict** issue form.

## Handling malicious URLs in issues and pull requests

- **Always defang URLs** before posting them: `hxxps://evil[.]example/login`.
- **Never post** a live phishing link, a link that contains a real person's e-mail address or token, or
  screenshots of real victims' data.
- **Test fixtures and examples** must use reserved names (`example.com`, `.example`, `.test`, `.invalid`) or
  documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

## What the tool does on the network

- **Default (offline) mode:** no network access at all.
- **`--enrich` / `--enrich-review`:**
  - It sends host names to Cloudflare's DNS-over-HTTPS resolver (1.1.1.1 / 1.0.0.1).
  - It sends registrable domains to the RDAP server of each domain's registry.
  - It downloads IANA's RDAP bootstrap list at most once every 30 days.
  - It never connects to the web server of a URL being checked.
