#!/usr/bin/env python3
"""Write a redacted copy of a decrypted ``romfile.cfg``.

Thin wrapper so the tool also works straight from a checkout; the installed
equivalent is ``romfile redact <cfg> -o <out>``. The rules live in
``src/dlink_romfile/redact.py`` and are shared with ``romfile report``.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dlink_romfile.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(["redact"] + sys.argv[1:]))
