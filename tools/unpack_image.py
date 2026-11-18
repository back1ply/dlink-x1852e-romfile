#!/usr/bin/env python3
"""Unpack a TC/EcoNet "New_GUI" firmware image (DSL-X1852E and relatives).

Both layouts use the same framing, only the magic differs:

    0x00  optional 256-byte RSA-2048 signature (the ".sig.bin" download name)
    0x100 "2RDH" (EG) or "4RDH" (AU) container header, padded to 0x100 bytes
          +0x04 u32be header size (0x100)
          +0x08 u32be image size
          +0x0C u32be check value
          +0x10 ascii version, "EG_1.00b28", zero padded
    +0x100 LZMA-alone stream -> MIPS kernel + boot ramdisk (fixed-size image)
    ...    "hsqs" SquashFS 4.0 rootfs (LZMA blocks), runs to EOF

EG images are not encrypted: the signature is verified by libcfg_clisvc.so and the
bootloader only LZMA-decompresses. Notes calling them "encrypted end to end" were
wrong - the 2RDH header sits at 0x100, so AES trials at offset 0/256/512 mangled it
before anything could match, and compressed data reads as ~8 bits/byte entropy.

    python tools/unpack_image.py tclinux_EG_1.00b28.sig.bin -o out/
    python tools/unpack_image.py <file> --list          # report only, write nothing

Writes <outdir>/image.bin (decompressed kernel+ramdisk), <outdir>/rootfs.squashfs and,
when 7z is on PATH, extracts it to <outdir>/rootfs/.
"""
import argparse
import lzma
import os
import shutil
import subprocess
import sys

MAGICS = (b"2RDH", b"4RDH")
SQUASHFS_MAGIC = b"hsqs"

AU_IMAGE_KEY = "11223344556677889900aabbccddeeff"
AU_IMAGE_IV = "a5" * 16


def find_container(data):
    for magic in MAGICS:
        off = data.find(magic)
        if off != -1 and off % 4 == 0:
            return off
    raise SystemExit("no 2RDH/4RDH container found")


def parse_header(data, off):
    hdr = data[off:off + 0x100]
    version = hdr[0x10:0x30].split(b"\x00")[0].decode("latin-1").strip()
    return {
        "offset": off,
        "magic": hdr[:4].decode("latin-1"),
        "signed": off > 0,
        "sig_len": off,
        "header_size": int.from_bytes(hdr[4:8], "big"),
        "image_size": int.from_bytes(hdr[8:12], "big"),
        "check": int.from_bytes(hdr[12:16], "big"),
        "version": version,
    }


def unpack(path, outdir, do_extract=True):
    data = open(path, "rb").read()
    off = find_container(data)
    h = parse_header(data, off)

    print("file      : %s (%d bytes)" % (os.path.basename(path), len(data)))
    print("container : %s at 0x%x%s" % (h["magic"], off,
          "  [preceded by a %d-byte signature block]" % off if off else ""))
    print("version   : %s" % h["version"])
    # image_size counts from the magic to the end of the meaningful image, i.e. it
    # includes this 0x100 header but not trailing flash padding.
    container = len(data) - off
    print("hdr size  : %d, declared image size %d (container in file: %d, slack %d)"
          % (h["header_size"], h["image_size"], container, container - h["image_size"]))

    body = data[off + h["header_size"]:]
    lz_off = body.find(b"\x5d\x00\x00")
    if lz_off == -1:
        print("payload   : no LZMA stream - this is the older encrypted layout.")
        print("            Decrypt the body with AES-128-CBC first:")
        print("              key %s" % AU_IMAGE_KEY)
        print("              iv  %s" % AU_IMAGE_IV)
        print("              openssl enc -d -aes-128-cbc -nopad -K %s -iv %s \\"
              % (AU_IMAGE_KEY, AU_IMAGE_IV))
        print("                -in <body.bin> -out <body.dec.bin>")
        print("            then re-run this tool on a file whose 0x0 is the header,")
        print("            or on the decrypted body if the header was already stripped.")
        return 2
    if lz_off:
        print("  ! %d bytes of padding before the LZMA stream" % lz_off)

    dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    image = dec.decompress(body[lz_off:])
    if not dec.eof:
        raise SystemExit("LZMA stream did not terminate cleanly")
    consumed = len(body) - lz_off - len(dec.unused_data)
    print("lzma      : %d -> %d bytes, %d bytes of stream used"
          % (len(body) - lz_off, len(image), consumed))

    sq_at = body.find(SQUASHFS_MAGIC, lz_off + consumed)
    squash = body[sq_at:] if sq_at != -1 else b""
    if squash:
        print("rootfs    : SquashFS at 0x%x, %d bytes"
              % (off + h["header_size"] + sq_at, len(squash)))
    else:
        print("rootfs    : no SquashFS found")

    if outdir is None:
        return 0

    os.makedirs(outdir, exist_ok=True)
    img_path = os.path.join(outdir, "image.bin")
    open(img_path, "wb").write(image)
    print("wrote     : %s" % img_path)

    if squash:
        sq_path = os.path.join(outdir, "rootfs.squashfs")
        open(sq_path, "wb").write(squash)
        print("wrote     : %s" % sq_path)
        if do_extract:
            seven = shutil.which("7z") or shutil.which("7zz")
            if not seven:
                print("  (7z not on PATH - skipping extraction)")
            else:
                dest = os.path.join(outdir, "rootfs")
                r = subprocess.run([seven, "x", sq_path, "-o" + dest, "-y"],
                                   capture_output=True, text=True)
                if r.returncode in (0, 1, 2):
                    print("extracted : %s" % dest)
                else:
                    print("  7z failed (rc=%d): %s" % (r.returncode, r.stderr.strip()[:200]))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Unpack a DSL-X1852E firmware image")
    ap.add_argument("image")
    ap.add_argument("-o", "--outdir", help="write artifacts here (default: report only)")
    ap.add_argument("--list", action="store_true", help="report only, write nothing")
    ap.add_argument("--no-extract", action="store_true",
                    help="carve the SquashFS but do not run 7z")
    args = ap.parse_args(argv)
    outdir = None if args.list else args.outdir
    return unpack(args.image, outdir, do_extract=not args.no_extract)


if __name__ == "__main__":
    sys.exit(main())
