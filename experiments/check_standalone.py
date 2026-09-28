"""Check that fraudurl_standalone.py is in sync with the fraudurl/ package (CI runs this).

Rebuilds the single file into a temporary folder and compares the code and the *decompressed* embedded data
(the compressed bytes may differ between zlib versions, the content may not).

    python experiments/check_standalone.py
"""
import base64
import importlib.util
import os
import pathlib
import re
import sys
import tempfile
import zlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def split(path):
    s = pathlib.Path(path).read_text(encoding="utf-8").replace("\r\n", "\n")
    code, sep, data = s.partition("\n_EMBEDDED = {\n")
    assert sep, "no _EMBEDDED block in " + str(path)
    blobs = {k: zlib.decompress(base64.b64decode(v))
             for k, v in re.findall(r'    "([^"]+)": """\n(.*?)\n""",', data, re.S)}
    assert len(blobs) == 3, blobs.keys()
    return code, blobs


if __name__ == "__main__":
    spec = importlib.util.spec_from_file_location("bsf", ROOT / "experiments" / "build_single_file.py")
    bsf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bsf)
    with tempfile.TemporaryDirectory() as tmp:
        bsf.OUT = os.path.join(tmp, "rebuilt.py")
        bsf.main()
        if split(ROOT / "fraudurl_standalone.py") != split(bsf.OUT):
            sys.exit("fraudurl_standalone.py is out of date: run python experiments/build_single_file.py and commit it")
    print("fraudurl_standalone.py is in sync with fraudurl/")
