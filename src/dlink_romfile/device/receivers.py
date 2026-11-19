"""One-shot file receivers, so the router can push dumps back to this PC.

``http_receiver`` keeps a small HTTP server up (the router POSTs/PUTs with curl);
``tftp_receiver`` accepts a single BusyBox ``tftp -p`` upload and exits. Both write
into a chosen directory using the client-supplied basename. Standard library only.
"""
from __future__ import annotations

import http.server
import os
import socket
import struct

from . import DeviceError

RRQ, WRQ, DATA, ACK, ERROR = 1, 2, 3, 4, 5


def _unique_path(directory: str, filename: str) -> str:
    dest = os.path.join(directory, filename)
    base, ext = os.path.splitext(dest)
    n = 1
    while os.path.exists(dest):
        dest = f"{base}.{n}{ext}"
        n += 1
    return dest


def http_receiver(outdir: str, port: int = 8080, bind: str = "0.0.0.0", log=print) -> None:
    """Serve until Ctrl-C; each POST/PUT body is written under ``outdir``."""
    os.makedirs(outdir, exist_ok=True)

    class Receiver(http.server.SimpleHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _read_body(self):
            length = self.headers.get("Content-Length")
            if length:
                return self.rfile.read(int(length))
            chunks = []
            while True:
                line = self.rfile.readline().strip()
                if not line:
                    break
                size = int(line, 16)
                if size == 0:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.readline()
            return b"".join(chunks)

        def _store(self, method):
            body = self._read_body()
            name = os.path.basename(self.path.split("?")[0].rstrip("/"))
            name = name.replace("~", "") or "upload.bin"
            dest = _unique_path(outdir, name)
            with open(dest, "wb") as fh:
                fh.write(body)
            log(f"[+] {method} {self.path} -> {dest} ({len(body)} bytes)")
            self._reply(b"ok")

        def _reply(self, payload):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):
            self._store("POST")

        def do_PUT(self):
            self._store("PUT")

        def do_GET(self):
            self._reply(b"receiver ready\n")

        def log_message(self, format, *args):
            pass

    log(f"saving uploads to: {outdir}")
    log(f"HTTP receiver on {bind}:{port} -- allow it through the firewall; Ctrl-C to stop")
    with http.server.ThreadingHTTPServer((bind, port), Receiver) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            log("stopped")


def tftp_receiver(outdir: str, port: int = 6969, bind: str = "0.0.0.0",
                  timeout: float = 120.0, log=print) -> str:
    """Accept one WRQ upload, write it under ``outdir``, return the path. RFC 1350 subset."""
    os.makedirs(outdir, exist_ok=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.settimeout(timeout)
    log(f"TFTP receiver on {bind}:{port} -> {outdir} (waiting {timeout:.0f}s)")
    try:
        try:
            data, client = srv.recvfrom(1024)
        except socket.timeout:
            raise DeviceError("timed out: no client connected") from None

        if struct.unpack("!H", data[:2])[0] != WRQ:
            srv.sendto(struct.pack("!HH", ERROR, 4) + b"only uploads\0", client)
            raise DeviceError("expected a TFTP upload (WRQ)")

        fname = os.path.basename(data[2:].split(b"\0")[0].decode("latin-1")) or "upload.bin"
        dest = _unique_path(outdir, fname)
        log(f"receiving {fname!r} from {client[0]}:{client[1]}")

        srv.settimeout(10.0)
        srv.sendto(struct.pack("!HH", ACK, 0), client)
        received, expected = 0, 1
        with open(dest, "wb") as fh:
            while True:
                try:
                    pkt, addr = srv.recvfrom(2048)
                except socket.timeout:
                    raise DeviceError(f"timed out mid-transfer after {received} bytes") from None
                if addr != client:
                    continue
                op = struct.unpack("!H", pkt[:2])[0]
                if op == ERROR:
                    raise DeviceError(f"client error: {pkt[4:]!r}")
                if op != DATA:
                    continue
                block = struct.unpack("!H", pkt[2:4])[0]
                payload = pkt[4:]
                srv.sendto(struct.pack("!HH", ACK, block), client)
                if block == expected:
                    fh.write(payload)
                    received += len(payload)
                    expected = (expected + 1) & 0xFFFF
                    if len(payload) < 512:
                        break
        log(f"OK: wrote {received} bytes to {dest}")
        return dest
    finally:
        srv.close()
