#!/usr/bin/env python3
"""Tiny single-shot TFTP server that only accepts uploads (WRQ).

Enough of RFC 1350 to let the router push one file to us:

    python tftp_recv.py --port 6969 --outdir incoming

On the router (BusyBox):
    tftp -p -l /lib/libcfg_clisvc.so -r libcfg_clisvc.so <PC-IP> 6969

Receives one file, writes it under --outdir with the client-supplied name
(basename only), prints a one-line summary, and exits. No pip deps.
"""
import argparse
import os
import socket
import struct
import sys

RRQ, WRQ, DATA, ACK, ERROR = 1, 2, 3, 4, 5


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=6969)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--outdir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "incoming"))
    ap.add_argument("--timeout", type=float, default=120.0, help="give up if no client connects")
    args = ap.parse_args()

    outdir = os.path.abspath(args.outdir)
    os.makedirs(outdir, exist_ok=True)

    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.settimeout(args.timeout)
    print("TFTP receiver on %s:%d -> %s (waiting %.0fs)" % (args.bind, args.port, outdir, args.timeout))

    try:
        data, client = srv.recvfrom(1024)
    except socket.timeout:
        print("timed out: no client connected", file=sys.stderr)
        return 2

    op = struct.unpack("!H", data[:2])[0]
    if op != WRQ:
        srv.sendto(struct.pack("!HH", ERROR, 4) + b"only uploads\0", client)
        print("expected WRQ, got opcode %d" % op, file=sys.stderr)
        return 3

    parts = data[2:].split(b"\0")
    fname = os.path.basename(parts[0].decode("latin-1")) or "upload.bin"
    dest = os.path.join(outdir, fname)
    print("receiving %r from %s:%d" % (fname, client[0], client[1]))

    srv.settimeout(10.0)
    srv.sendto(struct.pack("!HH", ACK, 0), client)  # ACK block 0

    received = 0
    expected = 1
    with open(dest, "wb") as fh:
        while True:
            try:
                pkt, addr = srv.recvfrom(2048)
            except socket.timeout:
                print("timed out mid-transfer after %d bytes" % received, file=sys.stderr)
                return 4
            if addr != client:
                continue
            op = struct.unpack("!H", pkt[:2])[0]
            if op == ERROR:
                print("client error: %r" % pkt[4:], file=sys.stderr)
                return 5
            if op != DATA:
                continue
            block = struct.unpack("!H", pkt[2:4])[0]
            payload = pkt[4:]
            if block == expected:
                fh.write(payload)
                received += len(payload)
                srv.sendto(struct.pack("!HH", ACK, block), client)
                expected = (expected + 1) & 0xFFFF
                if len(payload) < 512:
                    break
            else:
                # duplicate/old block: re-ACK it
                srv.sendto(struct.pack("!HH", ACK, block), client)

    print("OK: wrote %d bytes to %s" % (received, dest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
