#!/usr/bin/env python3
"""
romfile_tool.py - Decrypt / analyze D-Link DSL-X1852E (TrendChip/Econet "New_GUI")
romfile.cfg configuration backups.

Reverse-engineered format of the encrypted romfile.cfg (DSL-X1852E, EG_1.00bxx):

    offset  size   field
    0       4      magic / CRC32 of plaintext   (observed: 36 e2 8b dc)
    4       4      plaintext length, big-endian (observed: 0x00012E45 = 77381)
    8       ...    AES-ECB ciphertext, length = multiple of 16
                   -> decrypts to <plaintext length> bytes of config text
                      plus a few bytes of block padding.

Evidence it is AES-ECB (not CBC/stream/compression):
  * Shannon entropy ~7.99 bits/byte (random-looking) -> encrypted, not plain text
  * Hundreds of *identical* 16-byte ciphertext blocks (ECB fingerprint over the
    large constant/zero runs in NVRAM config); CBC/CTR/stream never repeat blocks.
  * body length (filesize-8) is an exact multiple of 16; the 4-byte length field
    equals filesize-8 minus block padding.

The ONLY missing input is the AES key, which is hard-coded inside a firmware binary
(e.g. libCmd / cm / tcapi / httpd). Get it with:  romfile_tool.py findkey <rootfs_dir>
or supply it directly:                            romfile_tool.py decrypt ... --key <hex|ascii>

Usage:
  romfile_tool.py info    <romfile.cfg> [--json]
  romfile_tool.py decrypt <romfile.cfg> -o out.xml --key <KEY> [--keyfmt hex|ascii|password]
                          [--bits 128|256|auto] [--mode ecb]
  romfile_tool.py try     <romfile.cfg> --keys keys.txt [-o out.xml]   # brute a candidate list
  romfile_tool.py findkey <firmware_rootfs_dir_or_binary> [--cfg romfile.cfg] [-o out.xml]

Needs: openssl on PATH (used for the AES primitive). No third-party Python deps.
Exit codes: 0 ok, 1 usage/IO error, 2 decryption did not yield valid config.
"""
from __future__ import annotations
import argparse, hashlib, json, re, subprocess, sys, tempfile
from pathlib import Path

MAGIC_LEN = 4
LEN_OFF, LEN_SZ = 4, 4
HEADER = 8

# Recovered from /userfs/bin/azencrypt (EG_1.00b15, MIPS): main() passes this
# ASCII string to aes_expand_key, and a static 16-byte IV (.data @0x414034) to
# aes_cbc_decrypt_blocks. Mode is AES-128-CBC, NOT ECB. The 4-byte header magic
# is crc32() of the ciphertext (integrity check), then a 4-byte big-endian
# plaintext length, then the ciphertext.
EG_KEY = b"0123456789abcdef"               # AES-128 key (ascii)
EG_IV = bytes.fromhex("aa55aa55aa55aa55aa55aa55aa55aa55")


def read_header(data: bytes) -> dict:
    if len(data) < HEADER:
        raise ValueError("file shorter than 8-byte header")
    magic = data[:MAGIC_LEN]
    pt_len = int.from_bytes(data[LEN_OFF:LEN_OFF + LEN_SZ], "big")
    body = data[HEADER:]
    return {
        "file_size": len(data),
        "magic_hex": magic.hex(),
        "plaintext_len": pt_len,
        "body_len": len(body),
        "body_mult_of_16": len(body) % 16 == 0,
        "pad_bytes": len(body) - pt_len,
        "looks_consistent": len(body) % 16 == 0 and 0 <= (len(body) - pt_len) < 16,
    }


def looks_like_config(b: bytes) -> float:
    """Return fraction of printable bytes; TrendChip config is ASCII name=value / <tags>."""
    if not b:
        return 0.0
    printable = sum(1 for c in b if 9 <= c <= 13 or 32 <= c <= 126)
    return printable / len(b)


def derive_openssl_key(password: str, bits: int) -> bytes:
    """EVP_BytesToKey(MD5, no salt) as used by `openssl enc -k PASS -nosalt -md md5`."""
    need = bits // 8
    out = b""
    prev = b""
    while len(out) < need:
        prev = hashlib.md5(prev + password.encode()).digest()
        out += prev
    return out[:need]


def aes_ecb_decrypt(body: bytes, key: bytes) -> bytes:
    bits = len(key) * 8
    if bits not in (128, 192, 256):
        raise ValueError(f"key must be 16/24/32 bytes, got {len(key)}")
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / "in.bin"
        outp = Path(td) / "out.bin"
        inp.write_bytes(body)
        cmd = ["openssl", "enc", f"-aes-{bits}-ecb", "-d", "-nopad",
               "-K", key.hex(), "-in", str(inp), "-out", str(outp)]
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            raise RuntimeError("openssl: " + r.stderr.decode(errors="ignore").strip())
        return outp.read_bytes()


def aes_cbc_decrypt(body: bytes, key: bytes, iv: bytes) -> bytes:
    bits = len(key) * 8
    if bits not in (128, 192, 256):
        raise ValueError(f"key must be 16/24/32 bytes, got {len(key)}")
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / "in.bin"
        outp = Path(td) / "out.bin"
        inp.write_bytes(body)
        cmd = ["openssl", "enc", f"-aes-{bits}-cbc", "-d", "-nopad",
               "-K", key.hex(), "-iv", iv.hex(), "-in", str(inp), "-out", str(outp)]
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            raise RuntimeError("openssl: " + r.stderr.decode(errors="ignore").strip())
        return outp.read_bytes()


def aes_cbc_encrypt(body: bytes, key: bytes, iv: bytes) -> bytes:
    bits = len(key) * 8
    with tempfile.TemporaryDirectory() as td:
        inp, outp = Path(td) / "in.bin", Path(td) / "out.bin"
        inp.write_bytes(body)
        cmd = ["openssl", "enc", f"-aes-{bits}-cbc", "-nopad",
               "-K", key.hex(), "-iv", iv.hex(), "-in", str(inp), "-out", str(outp)]
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            raise RuntimeError("openssl: " + r.stderr.decode(errors="ignore").strip())
        return outp.read_bytes()


def pack_romfile(plaintext: bytes, logical_len: int, pad: bytes = b"\x00") -> bytes:
    """Build an EG romfile.cfg: crc32(ct)[4 BE] + logical_len[4 BE] + AES-128-CBC ct.

    `plaintext` is the exact buffer to encrypt. If it is not a multiple of 16 it is
    padded with `pad`. `logical_len` is the value written to the length field (the
    device reads only that many bytes back); default caller passes len(config_text).
    """
    import binascii
    buf = plaintext
    if len(buf) % 16:
        buf += pad * (16 - len(buf) % 16)
    ct = aes_cbc_encrypt(buf, EG_KEY, EG_IV)
    crc = (binascii.crc32(ct) & 0xFFFFFFFF).to_bytes(4, "big")
    return crc + int(logical_len).to_bytes(4, "big") + ct


def cmd_encrypt(a) -> int:
    """Re-encrypt plaintext config into a restorable romfile.cfg.

    Byte-exact round-trip (proof): feed the full block-aligned plaintext and pass
    --length with the original config length. Practical edit: feed your edited XML
    and omit --length (it defaults to the file size; the tail is zero-padded).
    """
    pt = Path(a.file).read_bytes()
    logical = a.length if a.length is not None else len(pt)
    out = a.output or (a.file + ".romfile.cfg")
    packed = pack_romfile(pt, logical)
    Path(out).write_bytes(packed)
    print(f"[encrypt] plaintext={len(pt)}B logical_len={logical} -> {out} ({len(packed)}B)")
    if a.verify_against:
        orig = Path(a.verify_against).read_bytes()
        identical = orig == packed
        print(f"[verify] byte-identical to {a.verify_against}: {identical}")
        return 0 if identical else 2
    return 0


def cmd_solve(a) -> int:
    """Decrypt a DSL-X1852E EG romfile.cfg with the recovered AES-128-CBC key/IV."""
    import binascii
    data = Path(a.file).read_bytes()
    h = read_header(data)
    body, pt_len = data[HEADER:], h["plaintext_len"]
    ct_crc = format(binascii.crc32(body) & 0xFFFFFFFF, "08x")
    crc_ok = ct_crc == h["magic_hex"]
    clear = aes_cbc_decrypt(body, EG_KEY, EG_IV)[:pt_len]
    score = looks_like_config(clear)
    out = a.output or (a.file + ".decrypted.xml")
    Path(out).write_bytes(clear)
    print(f"[header] magic={h['magic_hex']}  crc32(ciphertext)={ct_crc}  match={crc_ok}")
    print(f"[decrypt] AES-128-CBC key={EG_KEY.decode()} iv={EG_IV.hex()}")
    print(f"[OK] {len(clear)} bytes -> {out}  printable={score:.3f}  "
          f"starts_with_ROMFILE={clear[:16].lstrip().startswith(b'<ROMFILE>')}")
    return 0 if score > 0.95 else 2


def make_key(raw: str, keyfmt: str, bits: int) -> list[bytes]:
    """Return candidate key byte-strings for the given spec."""
    if keyfmt == "hex":
        return [bytes.fromhex(raw.strip())]
    if keyfmt == "ascii":
        return [raw.encode()]
    if keyfmt == "password":
        want = [128, 256] if bits == 0 else [bits]
        return [derive_openssl_key(raw, b) for b in want]
    raise ValueError("keyfmt must be hex|ascii|password")


def attempt(body: bytes, pt_len: int, key: bytes) -> tuple[bool, bytes, float]:
    dec = aes_ecb_decrypt(body, key)
    clear = dec[:pt_len] if pt_len and pt_len <= len(dec) else dec
    score = looks_like_config(clear)
    ok = score > 0.95 and (b"=" in clear[:4096] or b"<" in clear[:4096])
    return ok, clear, score


def cmd_info(a) -> int:
    data = Path(a.file).read_bytes()
    h = read_header(data)
    h["printable_fraction_raw"] = round(looks_like_config(data), 4)
    if a.json:
        print(json.dumps(h, indent=2))
    else:
        print(f"file            : {a.file}")
        print(f"size            : {h['file_size']} bytes")
        print(f"header magic    : {h['magic_hex']}")
        print(f"plaintext_len   : {h['plaintext_len']} (0x{h['plaintext_len']:08X})")
        print(f"body (enc) len  : {h['body_len']}  multiple_of_16={h['body_mult_of_16']}")
        print(f"padding bytes   : {h['pad_bytes']}")
        print(f"format consistent with AES-ECB+8B header: {h['looks_consistent']}")
        print("NOTE: supply the firmware AES key to actually decrypt (see --help).")
    return 0


def _decrypt_with_keys(a, keys: list[bytes]) -> int:
    data = Path(a.file).read_bytes()
    h = read_header(data)
    body, pt_len = data[HEADER:], h["plaintext_len"]
    for key in keys:
        try:
            ok, clear, score = attempt(body, pt_len, key)
        except Exception as e:
            print(f"[skip] key {key.hex()[:16]}..: {e}", file=sys.stderr)
            continue
        print(f"[try] key={key.hex()}  printable={score:.3f}  valid={ok}", file=sys.stderr)
        if ok:
            out = a.output or (a.file + ".decrypted.xml")
            Path(out).write_bytes(clear)
            print(f"[OK] decrypted -> {out} ({len(clear)} bytes)")
            return 0
    print("[FAIL] no candidate key produced valid config text", file=sys.stderr)
    return 2


def cmd_decrypt(a) -> int:
    keys = make_key(a.key, a.keyfmt, 0 if a.bits == "auto" else int(a.bits))
    return _decrypt_with_keys(a, keys)


def cmd_try(a) -> int:
    raw = Path(a.keys).read_text(errors="ignore").splitlines()
    keys: list[bytes] = []
    for line in raw:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        # accept hex (even length, hex chars) else treat as ascii & as openssl password
        if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s) and len(s) in (32, 48, 64):
            keys.append(bytes.fromhex(s))
        else:
            if len(s) in (16, 24, 32):
                keys.append(s.encode())
            keys += [derive_openssl_key(s, 128), derive_openssl_key(s, 256)]
    # de-dup preserving order
    seen, uniq = set(), []
    for k in keys:
        if k not in seen:
            seen.add(k); uniq.append(k)
    print(f"[info] {len(uniq)} candidate keys", file=sys.stderr)
    return _decrypt_with_keys(a, uniq)


KEY_HINT_RE = re.compile(rb"[A-Za-z0-9+/=._-]{16,64}")


def cmd_findkey(a) -> int:
    """Pull printable strings from firmware binaries and try each as a key/password."""
    root = Path(a.target)
    files: list[Path] = []
    if root.is_dir():
        for p in root.rglob("*"):
            if p.is_file() and p.stat().st_size < 8_000_000:
                files.append(p)
    else:
        files = [root]
    cands: list[bytes] = []
    for p in files:
        try:
            blob = p.read_bytes()
        except Exception:
            continue
        for m in set(KEY_HINT_RE.findall(blob)):
            s = m.decode("latin1")
            # raw-bytes key if exactly 16/32 bytes
            if len(m) in (16, 24, 32):
                cands.append(m)
            # hex-string -> raw key
            if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s) and len(s) in (32, 48, 64):
                cands.append(bytes.fromhex(s))
            # as openssl password
            cands += [derive_openssl_key(s, 128), derive_openssl_key(s, 256)]
    seen, uniq = set(), []
    for k in cands:
        if 16 <= len(k) <= 32 and k not in seen:
            seen.add(k); uniq.append(k)
    print(f"[info] harvested {len(uniq)} candidate keys from {len(files)} files", file=sys.stderr)
    cfg = a.cfg or str(Path(__file__).parent / "input" / "romfile.cfg")
    ns = argparse.Namespace(file=cfg, output=a.output)
    return _decrypt_with_keys(ns, uniq)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="D-Link DSL-X1852E romfile.cfg tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info"); p.add_argument("file"); p.add_argument("--json", action="store_true"); p.set_defaults(fn=cmd_info)

    p = sub.add_parser("decrypt"); p.add_argument("file"); p.add_argument("-o", "--output")
    p.add_argument("--key", required=True); p.add_argument("--keyfmt", default="hex", choices=["hex", "ascii", "password"])
    p.add_argument("--bits", default="auto", choices=["128", "256", "auto"]); p.add_argument("--mode", default="ecb")
    p.set_defaults(fn=cmd_decrypt)

    p = sub.add_parser("try"); p.add_argument("file"); p.add_argument("--keys", required=True); p.add_argument("-o", "--output"); p.set_defaults(fn=cmd_try)

    p = sub.add_parser("findkey"); p.add_argument("target"); p.add_argument("--cfg"); p.add_argument("-o", "--output"); p.set_defaults(fn=cmd_findkey)

    p = sub.add_parser("solve", help="decrypt an EG romfile.cfg with the recovered AES-128-CBC key/IV")
    p.add_argument("file"); p.add_argument("-o", "--output"); p.set_defaults(fn=cmd_solve)

    p = sub.add_parser("encrypt", help="re-pack plaintext config into a restorable romfile.cfg")
    p.add_argument("file"); p.add_argument("-o", "--output")
    p.add_argument("--length", type=int, help="logical config length for the header (default: file size)")
    p.add_argument("--verify-against", help="assert the output is byte-identical to this file")
    p.set_defaults(fn=cmd_encrypt)

    a = ap.parse_args(argv)
    try:
        return a.fn(a)
    except (ValueError, OSError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
