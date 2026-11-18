"""Unpack a TC/EcoNet "New_GUI" firmware image (DSL-X1852E and relatives).

Both layouts use the same framing, only the magic differs:

    0x00  optional 256-byte RSA-2048 signature (the ".sig.bin" download name)
    0x100 "2RDH" (EG) or "4RDH" (AU) container header, padded to 0x100 bytes
          +0x04 u32be header size (0x100)
          +0x08 u32be image size
          +0x0C u32be check value
          +0x10 ascii version, "EG_1.00b28", zero padded
    +0x100 LZMA-alone stream -> kernel + boot ramdisk (fixed-size image)
    ...    "hsqs" SquashFS 4.0 rootfs (LZMA blocks), runs to EOF

EG images are not encrypted: the signature is verified by libcfg_clisvc.so and the
bootloader only LZMA-decompresses. Notes calling them "encrypted end to end" were
wrong - the 2RDH header sits at 0x100, so AES trials at offset 0/256/512 mangled it
before anything could match, and compressed data reads as ~8 bits/byte entropy.

The older AU layout is `4RDH` + AES-128-CBC with a known key; this module reports it
rather than decompressing noise.
"""
from __future__ import annotations

import lzma
import os
import shutil
import subprocess

MAGICS = (b"2RDH", b"4RDH")
SQUASHFS_MAGIC = b"hsqs"

AU_IMAGE_KEY = "11223344556677889900aabbccddeeff"
AU_IMAGE_IV = "a5" * 16


def find_container(data: bytes) -> int:
    """Offset of the 2RDH/4RDH header (`0x100` when a signature precedes it)."""
    for magic in MAGICS:
        off = data.find(magic)
        if off != -1 and off % 4 == 0:
            return off
    raise ValueError("no 2RDH/4RDH container found")


def parse_header(data: bytes, off: int) -> dict:
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


def unpack(path, outdir=None, do_extract=True, log=print) -> int:
    """Carve image.bin + rootfs.squashfs into ``outdir``; return an exit code."""
    data = open(path, "rb").read()
    off = find_container(data)
    h = parse_header(data, off)

    log("file      : %s (%d bytes)" % (os.path.basename(path), len(data)))
    log("container : %s at 0x%x%s" % (h["magic"], off,
        "  [preceded by a %d-byte signature block]" % off if off else ""))
    log("version   : %s" % h["version"])
    # image_size counts from the magic to the end of the meaningful image, i.e. it
    # includes this 0x100 header but not trailing flash padding.
    container = len(data) - off
    log("hdr size  : %d, declared image size %d (container in file: %d, slack %d)"
        % (h["header_size"], h["image_size"], container, container - h["image_size"]))

    body = data[off + h["header_size"]:]
    lz_off = body.find(b"\x5d\x00\x00")
    if lz_off == -1:
        log("payload   : no LZMA stream - this is the older encrypted layout.")
        log("            Decrypt the body with AES-128-CBC first:")
        log("              key %s" % AU_IMAGE_KEY)
        log("              iv  %s" % AU_IMAGE_IV)
        log("              openssl enc -d -aes-128-cbc -nopad -K %s -iv %s \\"
            % (AU_IMAGE_KEY, AU_IMAGE_IV))
        log("                -in <body.bin> -out <body.dec.bin>")
        log("            then re-run on the decrypted image.")
        return 2
    if lz_off:
        log("  ! %d bytes of padding before the LZMA stream" % lz_off)

    dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    image = dec.decompress(body[lz_off:])
    if not dec.eof:
        raise ValueError("LZMA stream did not terminate cleanly")
    consumed = len(body) - lz_off - len(dec.unused_data)
    log("lzma      : %d -> %d bytes, %d bytes of stream used"
        % (len(body) - lz_off, len(image), consumed))

    sq_at = body.find(SQUASHFS_MAGIC, lz_off + consumed)
    squash = body[sq_at:] if sq_at != -1 else b""
    if squash:
        log("rootfs    : SquashFS at 0x%x, %d bytes"
            % (off + h["header_size"] + sq_at, len(squash)))
    else:
        log("rootfs    : no SquashFS found")

    if outdir is None:
        return 0

    os.makedirs(outdir, exist_ok=True)
    img_path = os.path.join(outdir, "image.bin")
    open(img_path, "wb").write(image)
    log("wrote     : %s" % img_path)

    if squash:
        sq_path = os.path.join(outdir, "rootfs.squashfs")
        open(sq_path, "wb").write(squash)
        log("wrote     : %s" % sq_path)
        if do_extract:
            seven = shutil.which("7z") or shutil.which("7zz")
            if not seven:
                log("  (7z not on PATH - skipping extraction)")
            else:
                dest = os.path.join(outdir, "rootfs")
                r = subprocess.run([seven, "x", sq_path, "-o" + dest, "-y"],
                                   capture_output=True, text=True)
                if r.returncode in (0, 1, 2):
                    log("extracted : %s" % dest)
                else:
                    log("  7z failed (rc=%d): %s" % (r.returncode, r.stderr.strip()[:200]))
    return 0
