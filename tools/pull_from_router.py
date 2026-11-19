#!/usr/bin/env python3
"""Tiny HTTP receiver so a router can push files to this PC.

Run on the PC:
    python pull_from_router.py            # listens on 0.0.0.0:8080
    python pull_from_router.py 9000       # custom port

Run on the router (busybox/curl shell):
    curl -s --data-binary @/var/romfile.cfg  http://<PC-IP>:8080/romfile.cfg
    curl -s --data-binary @/lib/libcfg_clisvc.so http://<PC-IP>:8080/libcfg_clisvc.so

Every upload is written to ../incoming/ with the name taken from the URL path.
A plain GET returns "receiver ready", so you can smoke-test from a browser.
"""

import http.server
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUTDIR = os.path.normpath(os.path.join(HERE, "..", "incoming"))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080


def unique_path(directory, filename):
    dest = os.path.join(directory, filename)
    base, ext = os.path.splitext(dest)
    n = 1
    while os.path.exists(dest):
        dest = "%s.%d%s" % (base, n, ext)
        n += 1
    return dest


class Receiver(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _read_body(self):
        length = self.headers.get("Content-Length")
        if length:
            return self.rfile.read(int(length))
        # chunked transfer-encoding (busybox curl usually sends Content-Length)
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
        dest = unique_path(OUTDIR, name)
        with open(dest, "wb") as fh:
            fh.write(body)
        print("[+] %s %-40s -> %s (%d bytes)" % (method, self.path, dest, len(body)), flush=True)
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

    def log_message(self, *args):
        pass


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    print("saving uploads to: %s" % OUTDIR)
    print("listening on port %d -- allow it through Windows Firewall when prompted" % PORT)
    with http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Receiver) as srv:
        print("ready. on the router, POST to http://<this-PC-IP>:%d/<filename>" % PORT)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")


if __name__ == "__main__":
    main()
