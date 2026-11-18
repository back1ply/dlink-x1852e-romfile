#!/usr/bin/env python3
"""Unpack a DSL-X1852E firmware image.

Thin wrapper so the tool also works straight from a checkout; the installed
equivalent is ``romfile unpack <image> -o <dir>``. The container logic lives in
``src/dlink_romfile/unpack.py``.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dlink_romfile.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(["unpack"] + sys.argv[1:]))
