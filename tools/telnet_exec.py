#!/usr/bin/env python3
"""Minimal telnet client: log in to a BusyBox device and run one command.

Python 3.13+ removed telnetlib, so this speaks just enough of the protocol
(refuse every IAC option negotiation) over a raw socket.

    python telnet_exec.py "id; uname -a"
    python telnet_exec.py --host 192.168.1.1 --user admin --passwd '<yours>' "cat /proc/mtd"

Credentials are device-specific: read them from your own router's config
(the DSL-X1852E serves its plaintext config at http://<router>/romfile.cfg --
look at <Account>/<TelnetEntry> for telnet_username / telnet_passwd). Nothing
is hardcoded here.

Prints everything the device sends after login. Read-only by default -- it only
runs the command you pass.
"""
import argparse
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from router_secrets import get  # noqa: E402

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240


def negotiate(sock, data, out):
    """Strip/answer telnet IAC sequences, append plain bytes to out."""
    i = 0
    reply = bytearray()
    while i < len(data):
        b = data[i]
        if b == IAC:
            if i + 1 >= len(data):
                break
            cmd = data[i + 1]
            if cmd in (DO, DONT, WILL, WONT):
                opt = data[i + 2] if i + 2 < len(data) else 0
                # Refuse everything: answer DO->WONT, WILL->DONT
                ans = WONT if cmd == DO else (DONT if cmd == WILL else None)
                if ans is not None:
                    reply += bytes([IAC, ans, opt])
                i += 3
                continue
            if cmd == SB:  # subnegotiation: skip to IAC SE
                j = data.find(bytes([IAC, SE]), i)
                i = (j + 2) if j != -1 else len(data)
                continue
            i += 2
            continue
        out.append(b)
        i += 1
    if reply:
        sock.sendall(bytes(reply))


def recv_until(sock, patterns, timeout=8.0):
    """Read until any pattern (bytes, lowercased match) appears or timeout."""
    sock.settimeout(0.5)
    out = bytearray()
    end = time.time() + timeout
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            chunk = b""
        if chunk:
            negotiate(sock, chunk, out)
            low = bytes(out).lower()
            if any(p in low for p in patterns):
                return bytes(out), True
        elif patterns == []:
            break
    return bytes(out), False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("command")
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=23)
    ap.add_argument("--user", default=None)
    ap.add_argument("--passwd", default=None, help="telnet password (read it from your own config)")
    ap.add_argument("--marker", default="___DONE___")
    args = ap.parse_args()

    host = get("X1852E_HOST", args.host, "192.168.1.1")
    user = get("X1852E_TELNET_USER", args.user, "admin")
    passwd = get("X1852E_TELNET_PASS", args.passwd, "")

    s = socket.create_connection((host, args.port), timeout=10)

    recv_until(s, [b"login:", b"username:"], timeout=8)
    s.sendall(user.encode() + b"\n")
    recv_until(s, [b"password:"], timeout=6)
    s.sendall(passwd.encode() + b"\n")
    # wait for a shell prompt
    banner, _ = recv_until(s, [b"#", b"$", b"incorrect", b"wrong", b"fail"], timeout=8)
    sys.stderr.write("--- login banner ---\n")
    sys.stderr.write(banner.decode("latin-1", "replace") + "\n--------------------\n")

    # Run the command, then print a marker. The *typed* marker is quoted
    # (D''ONE) so the device's input-echo can't match it; only the shell's
    # dequoted output (DONE) does -- otherwise we'd stop on the echo.
    typed = args.marker[0] + "''" + args.marker[1:]
    s.sendall(args.command.encode() + b" ; echo " + typed.encode() + b"\n")
    out, _ = recv_until(s, [args.marker.lower().encode()], timeout=25)
    try:
        s.sendall(b"exit\n")
    except OSError:
        pass
    s.close()

    text = out.decode("latin-1", "replace")
    idx = text.rfind(args.marker)
    if idx != -1:
        text = text[:idx]
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
