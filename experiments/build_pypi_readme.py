"""Turn README.md into the PyPI project page (release.yml runs this before building the wheel and the sdist).

PyPI renders a README differently from GitHub, so a few things are rewritten:
- relative images and links become absolute GitHub URLs pinned to the release tag, so the page never drifts;
- <picture> keeps only its light-mode <img> (PyPI strips <source>), and the Mermaid diagram, which PyPI would
  show as raw code, is dropped (the numbered steps under it say the same);
- the install line becomes `pip install fraudurl`.

    python experiments/build_pypi_readme.py -o README.md          # rewrite (release builds only)
    python experiments/build_pypi_readme.py --check README.md     # render it the PyPI way and verify (CI)
    python experiments/build_pypi_readme.py --check README.md --online   # also fetch every repo link/image
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPO = "amruth112/fraudurl-detector"
FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})(.*)$")
MERMAID = re.compile(r"\s*mermaid\b", re.I)
LOCAL = r"(?!https?:|mailto:|#|/)"          # a relative path inside the repository
GIT_INSTALL = re.compile(r'pip install ((?:-U |--upgrade )?)"?git\+https://github\.com/' + re.escape(REPO)
                         + r'(?:\.git)?(?:@[^\s"`]+)?"?')


def default_ref():
    src = (ROOT / "fraudurl" / "__init__.py").read_text(encoding="utf-8")
    return "v" + re.search(r'__version__ = "([^"]+)"', src).group(1)


def blocks(text):
    """Split markdown into (info, chunk) pieces: info is None for prose, else the code block's info string.
    A block closes only on a fence of the same character that is at least as long (CommonMark)."""
    out, buf, fence, info = [], [], None, None
    for line in text.replace("\r\n", "\n").splitlines(keepends=True):
        m = FENCE.match(line.rstrip("\n"))
        if fence is None and m:
            out.append((None, "".join(buf)))
            buf, fence, info = [line], m.group(1), m.group(2)
            continue
        buf.append(line)
        if fence is not None and m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) \
                and not m.group(2).strip():
            out.append((info, "".join(buf)))
            buf, fence, info = [], None, None
    out.append((info, "".join(buf)))
    return out


def rewrite(text, ref):
    raw = f"https://raw.githubusercontent.com/{REPO}/{ref}/"
    blob = f"https://github.com/{REPO}/blob/{ref}/"
    out = []
    for info, chunk in blocks(text):
        if info is not None:                       # code: only the install line changes; diagrams are dropped
            if not MERMAID.match(info):
                out.append(GIT_INSTALL.sub(r"pip install \1fraudurl", chunk))
            continue
        chunk = re.sub(r"<picture>\s*(?:<source[^>]*>\s*)*(<img[^>]*>)\s*</picture>", r"\1", chunk)
        chunk = re.sub(r'(<img[^>]*\ssrc=")' + LOCAL, lambda m: m.group(1) + raw, chunk)
        chunk = re.sub(r'(\shref=")' + LOCAL, lambda m: m.group(1) + blob, chunk)
        chunk = re.sub(r"(!\[[^\]]*\]\()" + LOCAL, lambda m: m.group(1) + raw, chunk)
        chunk = re.sub(r"(\]\()" + LOCAL, lambda m: m.group(1) + blob, chunk)  # links, badge links included
        chunk = GIT_INSTALL.sub(r"pip install \1fraudurl", chunk)
        out.append(re.sub(r"\n{3,}", "\n\n", chunk))
    return "".join(out)


def check(path, online=False):
    """Render like PyPI (readme_renderer, GitHub-flavoured markdown) and list anything that would break."""
    import readme_renderer.markdown
    html = readme_renderer.markdown.render(pathlib.Path(path).read_text(encoding="utf-8"), variant="GFM")
    if html is None:
        return ["readme_renderer could not render the file"]
    problems = []
    ids = set(re.findall(r'\sid="([^"]+)"', html))
    for attr, url in re.findall(r'\s(src|href)="([^"]*)"', html):
        if url.startswith("#"):
            if url[1:] not in ids:
                problems.append(f"in-page link {url} has no target")
        elif not re.match(r"https?:|mailto:", url):
            problems.append(f"relative {attr} would break on PyPI: {url}")
    if re.search(r'<pre lang="mermaid"', html, re.I) or "```" in html or "~~~" in html:
        problems.append("a diagram or unrendered code fence is left in the page")
    if "git+https://github.com/" + REPO in html:
        problems.append("a git+ install line is left on the page: PyPI users should see pip install fraudurl")
    if not re.search(r"<img[^>]+src=\"https://raw\.githubusercontent\.com/", html):
        problems.append("no repository images found: did the rewrite run?")
    if online:
        urls = sorted({u for u in re.findall(r'\s(?:src|href)="([^"#]+)', html) if REPO in u})
        for url in urls:
            for attempt in range(4):  # a tag pushed seconds ago can take a moment to reach raw.githubusercontent
                try:
                    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "fraudurl-release-check"})
                    with urllib.request.urlopen(req, timeout=20) as r:
                        status = r.status
                except Exception as e:  # noqa: BLE001 - report every kind of failure the same way
                    status = getattr(e, "code", type(e).__name__)
                if status == 200:
                    break
                time.sleep(5 * (attempt + 1))
            if status != 200:
                problems.append(f"{url} -> {status}")
        print(f"fetched {len(urls)} repository links and images")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--ref", default=None, help="git tag or commit the links point to (default: v<version>)")
    ap.add_argument("-o", "--output", help="write here (default: the screen)")
    ap.add_argument("--check", metavar="FILE", help="verify an already rewritten file instead")
    ap.add_argument("--online", action="store_true", help="with --check: also fetch every repository URL")
    a = ap.parse_args()
    if a.check:
        problems = check(a.check, a.online)
        for p in problems:
            print("PROBLEM:", p)
        if problems:
            sys.exit(f"{len(problems)} problem(s) on the PyPI page")
        print(a.check, "renders cleanly for PyPI")
        return
    text = rewrite((ROOT / "README.md").read_text(encoding="utf-8"), a.ref or default_ref())
    if a.output:
        pathlib.Path(a.output).write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
