"""Core format + crypto logic for D-Link DSL-X1852E (EG) ``romfile.cfg``.

No argparse, no process exit -- everything here is importable and returns values
or raises. The CLI layer in :mod:`dlink_romfile.cli` wraps these.

Container layout (EG_1.00bxx):

    offset  size  field
    0       4     crc32(ciphertext), big-endian
    4       4     plaintext (logical config) length, big-endian
    8       ...   AES-128-CBC ciphertext

Key/IV recovered from ``/userfs/bin/azencrypt``:
    key = ascii "0123456789abcdef", iv = aa55aa55aa55aa55aa55aa55aa55aa55, CBC.
"""
from __future__ import annotations

import binascii
import hashlib
import subprocess
import tempfile
from pathlib import Path

MAGIC_LEN = 4
LEN_OFF, LEN_SZ = 4, 4
HEADER = 8

EG_KEY = b"0123456789abcdef"
EG_IV = bytes.fromhex("aa55aa55aa55aa55aa55aa55aa55aa55")


class OpensslError(RuntimeError):
    """openssl not on PATH, or it rejected the input."""


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
        "crc32_ciphertext": format(binascii.crc32(body) & 0xFFFFFFFF, "08x"),
    }


def looks_like_config(b: bytes) -> float:
    """Fraction of printable bytes; TrendChip config is ASCII name=value / <tags>."""
    if not b:
        return 0.0
    printable = sum(1 for c in b if 9 <= c <= 13 or 32 <= c <= 126)
    return printable / len(b)


def derive_openssl_key(password: str, bits: int) -> bytes:
    """EVP_BytesToKey(MD5, no salt), as ``openssl enc -k PASS -nosalt -md md5``."""
    need = bits // 8
    out = b""
    prev = b""
    while len(out) < need:
        prev = hashlib.md5(prev + password.encode()).digest()
        out += prev
    return out[:need]


def _openssl(args: list[str], data: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        inp, outp = Path(td) / "in.bin", Path(td) / "out.bin"
        inp.write_bytes(data)
        cmd = ["openssl", *args, "-in", str(inp), "-out", str(outp)]
        try:
            r = subprocess.run(cmd, capture_output=True)
        except FileNotFoundError as exc:
            raise OpensslError("openssl not found on PATH") from exc
        if r.returncode != 0:
            raise OpensslError(r.stderr.decode(errors="ignore").strip() or "openssl failed")
        return outp.read_bytes()


def aes_cbc_decrypt(body: bytes, key: bytes, iv: bytes) -> bytes:
    bits = len(key) * 8
    if bits not in (128, 192, 256):
        raise ValueError(f"key must be 16/24/32 bytes, got {len(key)}")
    return _openssl([f"enc", f"-aes-{bits}-cbc", "-d", "-nopad", "-K", key.hex(), "-iv", iv.hex()], body)


def aes_cbc_encrypt(body: bytes, key: bytes, iv: bytes) -> bytes:
    bits = len(key) * 8
    return _openssl([f"enc", f"-aes-{bits}-cbc", "-nopad", "-K", key.hex(), "-iv", iv.hex()], body)


def aes_ecb_decrypt(body: bytes, key: bytes) -> bytes:
    bits = len(key) * 8
    if bits not in (128, 192, 256):
        raise ValueError(f"key must be 16/24/32 bytes, got {len(key)}")
    return _openssl([f"enc", f"-aes-{bits}-ecb", "-d", "-nopad", "-K", key.hex()], body)


def decrypt_romfile(data: bytes, key: bytes = EG_KEY, iv: bytes = EG_IV) -> tuple[bytes, dict]:
    """Decrypt a romfile container; return (plaintext_config, header_info)."""
    h = read_header(data)
    clear = aes_cbc_decrypt(data[HEADER:], key, iv)[: h["plaintext_len"]]
    return clear, h


def pack_romfile(plaintext: bytes, logical_len: int | None = None,
                 key: bytes = EG_KEY, iv: bytes = EG_IV, pad: bytes = b"\x00") -> bytes:
    """Build a romfile container: crc32(ct)[4 BE] + logical_len[4 BE] + AES-128-CBC ct."""
    if logical_len is None:
        logical_len = len(plaintext)
    buf = plaintext
    if len(buf) % 16:
        buf += pad * (16 - len(buf) % 16)
    ct = aes_cbc_encrypt(buf, key, iv)
    crc = (binascii.crc32(ct) & 0xFFFFFFFF).to_bytes(4, "big")
    return crc + int(logical_len).to_bytes(4, "big") + ct
