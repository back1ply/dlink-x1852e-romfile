"""Minimal telnet client: log in to the BusyBox device and run one command.

Python 3.13+ removed ``telnetlib``, so this speaks just enough of the protocol
(refuse every IAC option negotiation) over a raw socket. Read-only by default: it
only runs the command it is given.
"""
from __future__ import annotations

import socket
import time

from . import DeviceError

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240


def negotiate(sock, data: bytes, out: bytearray) -> None:
    """Strip/answer telnet IAC sequences, append plain bytes to ``out``."""
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
                ans = WONT if cmd == DO else (DONT if cmd == WILL else None)
                if ans is not None:
                    reply += bytes([IAC, ans, opt])
                i += 3
                continue
            if cmd == SB:
                j = data.find(bytes([IAC, SE]), i)
                i = (j + 2) if j != -1 else len(data)
                continue
            i += 2
            continue
        out.append(b)
        i += 1
    if reply and sock is not None:
        sock.sendall(bytes(reply))


def recv_until(sock, patterns, timeout: float = 8.0):
    """Read until any pattern (lowercased bytes) appears or timeout."""
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


def run(host: str, user: str, passwd: str, command: str, port: int = 23,
        marker: str = "___DONE___") -> tuple[str, str]:
    """Log in and run one command. Returns (command_output, login_banner)."""
    try:
        s = socket.create_connection((host, port), timeout=10)
    except OSError as e:
        raise DeviceError(f"could not connect to {host}:{port}: {e}") from e
    try:
        recv_until(s, [b"login:", b"username:"], timeout=8)
        s.sendall(user.encode() + b"\n")
        recv_until(s, [b"password:"], timeout=6)
        s.sendall(passwd.encode() + b"\n")
        banner, _ = recv_until(s, [b"#", b"$", b"incorrect", b"wrong", b"fail"], timeout=8)

        # The typed marker is quoted (D''ONE) so the device's input echo can't match it;
        # only the shell's dequoted output (DONE) does.
        typed = marker[0] + "''" + marker[1:]
        s.sendall(command.encode() + b" ; echo " + typed.encode() + b"\n")
        out, _ = recv_until(s, [marker.lower().encode()], timeout=25)
        try:
            s.sendall(b"exit\n")
        except OSError:
            pass
    finally:
        s.close()

    text = out.decode("latin-1", "replace")
    idx = text.rfind(marker)
    if idx != -1:
        text = text[:idx]
    return text, banner.decode("latin-1", "replace")
