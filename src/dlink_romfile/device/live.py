"""Pull the configuration the DSL-X1852E web server serves at ``/romfile.cfg``.

On EG_1.00b15 that endpoint returns the *plaintext* running config with no
authentication; on b28 it returns the encrypted container instead. :func:`classify`
tells the two apart so callers can react.
"""
from __future__ import annotations

import urllib.request

MAGIC = bytes.fromhex("36e28bdc")  # encrypted-container header


def fetch(host: str, timeout: float = 20) -> bytes:
    """GET ``http://<host>/romfile.cfg`` and return the raw body."""
    url = f"http://{host}/romfile.cfg"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def classify(data: bytes) -> str:
    """Return 'plaintext', 'encrypted' or 'unknown' for a fetched body."""
    if data[:4] == MAGIC:
        return "encrypted"
    if data.lstrip()[:9] == b"<ROMFILE>":
        return "plaintext"
    return "unknown"
