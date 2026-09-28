## What this changes

## Checklist

- [ ] `python -m pytest -q` passes
- [ ] If `fraudurl/` changed: `python experiments/build_single_file.py` was run and the rebuilt
      `fraudurl_standalone.py` is committed (`python experiments/check_standalone.py` passes)
- [ ] No live malicious URLs, real e-mail addresses or tokens. Test URLs use reserved names
      (`example.com`, `.example`, `.test`, `.invalid`) or documentation IPs
- [ ] No third-party dataset files are added
- [ ] `CHANGELOG.md` updated if users will notice the change
