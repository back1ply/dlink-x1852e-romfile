#!/usr/bin/env python3
"""Pull the live configuration off a D-Link DSL-X1852E and print a readable report.

    python fetch_live_config.py                 # 192.168.1.1
    python fetch_live_config.py 192.168.1.1 --show-secrets
    python fetch_live_config.py --keep-only     # just save, no report

Why this works: the EG firmware's web server (EHTTP) serves `/romfile.cfg` -- the
*plaintext* running config -- with no authentication at all. It is the same file the
GUI downloads, but it is never encrypted on the wire.

If a future firmware starts encrypting it, the response begins with the 8-byte
container header 36 e2 8b dc instead of `<ROMFILE>`; this script says so and stops.
"""

import argparse
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)                        # router_secrets (device tools)
sys.path.insert(0, os.path.join(PROJECT, "src"))  # dlink_romfile (report)
from router_secrets import get  # noqa: E402

MAGIC = bytes.fromhex("36e28bdc")
DEFAULT_HOST = "192.168.1.1"


def fetch(host, timeout=20):
    url = "http://%s/romfile.cfg" % host
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return url, resp.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host", nargs="?", default=None)
    ap.add_argument("-o", "--output", default=os.path.join(PROJECT, "input", "romfile_live.cfg"))
    ap.add_argument("--show-secrets", action="store_true")
    ap.add_argument("--keep-only", action="store_true")
    args = ap.parse_args()

    host = get("X1852E_HOST", args.host, DEFAULT_HOST)

    try:
        url, data = fetch(host)
    except (urllib.error.URLError, OSError) as exc:
        print("could not reach %s/romfile.cfg: %s" % (host, exc), file=sys.stderr)
        print("are you on the router's LAN? try: Test-NetConnection %s -Port 80" % host,
              file=sys.stderr)
        return 1

    if data[:4] == MAGIC:
        print("router returned the *encrypted* container (%d bytes, magic 36e28bdc)."
              % len(data), file=sys.stderr)
        print("this firmware no longer serves the plaintext config; need the AES key.",
              file=sys.stderr)
        return 2
    if not data.lstrip()[:9] == b"<ROMFILE>":
        print("unexpected payload (%d bytes): %r" % (len(data), data[:32]), file=sys.stderr)
        return 3

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "wb") as fh:
        fh.write(data)
    print("saved %d bytes of plaintext config to %s" % (len(data), args.output))

    if args.keep_only:
        return 0

    # Report via the installed package (replaces the old tools/romfile_report.py,
    # now `romfile report`); falls back silently if the package isn't importable.
    try:
        from dlink_romfile.cli import main as romfile_main
    except ImportError:
        print("(install the package or run `romfile report %s` for a summary)" % args.output,
              file=sys.stderr)
        return 0
    report_args = ["report", args.output]
    if args.show_secrets:
        report_args.append("--show-secrets")
    romfile_main(report_args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
