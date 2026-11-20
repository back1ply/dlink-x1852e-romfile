"""Command-line interface for ``romfile`` -- decrypt/inspect/re-pack DSL-X1852E configs
and unpack its firmware images.

Data goes to stdout; notes, warnings and errors go to stderr. ``main(argv)`` returns
an exit code (0 ok, 1 failure, 2 usage). Subcommands dispatch through ``COMMANDS``.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from . import __version__, audit, config, core, redact, report, unpack


def _err(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)


# --- subcommands -----------------------------------------------------------

def cmd_info(a) -> int:
    data = Path(a.file).read_bytes()
    h = core.read_header(data)
    if a.json:
        print(json.dumps(h, indent=2))
    else:
        print(f"file            : {a.file}")
        print(f"size            : {h['file_size']} bytes")
        print(f"header magic    : {h['magic_hex']}")
        print(f"crc32(ciphertext): {h['crc32_ciphertext']}  "
              f"(matches magic: {h['crc32_ciphertext'] == h['magic_hex']})")
        print(f"plaintext_len   : {h['plaintext_len']} (0x{h['plaintext_len']:08X})")
        print(f"body (enc) len  : {h['body_len']}  multiple_of_16={h['body_mult_of_16']}")
        print(f"padding bytes   : {h['pad_bytes']}")
    return 0


def cmd_solve(a) -> int:
    data = Path(a.file).read_bytes()
    clear, h = core.decrypt_romfile(data)
    score = core.looks_like_config(clear)
    out = a.output or (a.file + ".decrypted.xml")
    Path(out).write_bytes(clear)
    crc_ok = h["crc32_ciphertext"] == h["magic_hex"]
    print(f"[header] magic={h['magic_hex']} crc32(ciphertext)={h['crc32_ciphertext']} match={crc_ok}",
          file=sys.stderr)
    print(f"[decrypt] AES-128-CBC key={core.EG_KEY.decode()} iv={core.EG_IV.hex()}", file=sys.stderr)
    print(out)
    if score <= 0.95:
        _err(f"output does not look like config (printable={score:.3f})")
        return 2
    return 0


def cmd_encrypt(a) -> int:
    pt = Path(a.file).read_bytes()
    score = core.looks_like_config(pt)
    if score <= 0.95 and not a.force:
        _err(f"{a.file} does not look like a config (printable={score:.3f}); "
             "a backup built from it will not restore. Use --force to override")
        return 2
    logical = a.length if a.length is not None else len(pt)
    out = a.output or (a.file + ".romfile.cfg")
    packed = core.pack_romfile(pt, logical)
    Path(out).write_bytes(packed)
    print(f"[encrypt] plaintext={len(pt)}B logical_len={logical} -> {len(packed)}B", file=sys.stderr)
    print(out)
    if a.verify_against:
        identical = Path(a.verify_against).read_bytes() == packed
        print(f"[verify] byte-identical to {a.verify_against}: {identical}", file=sys.stderr)
        return 0 if identical else 2
    return 0


def _make_keys(raw: str, keyfmt: str, bits: int) -> list[bytes]:
    if keyfmt == "hex":
        return [bytes.fromhex(raw.strip())]
    if keyfmt == "ascii":
        return [raw.encode()]
    if keyfmt == "password":
        want = [128, 256] if bits == 0 else [bits]
        return [core.derive_openssl_key(raw, b) for b in want]
    raise ValueError("keyfmt must be hex|ascii|password")


def _attempt(data: bytes, key: bytes, mode: str, iv: bytes):
    body = data[core.HEADER:]
    pt_len = core.read_header(data)["plaintext_len"]
    dec = core.aes_cbc_decrypt(body, key, iv) if mode == "cbc" else core.aes_ecb_decrypt(body, key)
    clear = dec[:pt_len] if pt_len and pt_len <= len(dec) else dec
    score = core.looks_like_config(clear)
    ok = score > 0.95 and (b"=" in clear[:4096] or b"<" in clear[:4096])
    return ok, clear, score


def cmd_decrypt(a) -> int:
    iv = bytes.fromhex(a.iv) if a.iv else core.EG_IV
    bits = 0 if a.bits == "auto" else int(a.bits)
    try:
        keys = _make_keys(a.key, a.keyfmt, bits)
    except ValueError as e:
        _err(str(e)); return 2
    for key in keys:
        try:
            ok, clear, score = _attempt(Path(a.file).read_bytes(), key, a.mode, iv)
        except (core.OpensslError, ValueError) as e:
            print(f"[skip] {key.hex()[:16]}..: {e}", file=sys.stderr)
            continue
        print(f"[try] key={key.hex()} printable={score:.3f} valid={ok}", file=sys.stderr)
        if ok:
            out = a.output or (a.file + ".decrypted.xml")
            Path(out).write_bytes(clear)
            print(out)
            return 0
    _err("no key produced valid config")
    return 2


def cmd_try(a) -> int:
    lines = Path(a.keys).read_text(errors="ignore").splitlines()
    keys: list[bytes] = []
    for s in (x.strip() for x in lines):
        if not s or s.startswith("#"):
            continue
        if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s) and len(s) in (32, 48, 64):
            keys.append(bytes.fromhex(s))
        elif len(s) in (16, 24, 32):
            keys.append(s.encode())
    data = Path(a.file).read_bytes()
    for key in keys:
        try:
            ok, clear, _ = _attempt(data, key, "cbc", core.EG_IV)
        except (core.OpensslError, ValueError):
            continue
        if ok:
            out = a.output or (a.file + ".decrypted.xml")
            Path(out).write_bytes(clear)
            print(out)
            return 0
    _err(f"none of {len(keys)} candidate keys worked")
    return 2


def cmd_findkey(a) -> int:
    hint = re.compile(rb"[A-Za-z0-9+/=._-]{16,64}")
    root = Path(a.target)
    files = [p for p in root.rglob("*") if p.is_file() and p.stat().st_size < 8_000_000] \
        if root.is_dir() else [root]
    cands: list[bytes] = []
    for p in files:
        try:
            blob = p.read_bytes()
        except OSError:
            continue
        for m in set(hint.findall(blob)):
            if len(m) in (16, 24, 32):
                cands.append(m)
            s = m.decode("latin1")
            if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s) and len(s) in (32, 48, 64):
                cands.append(bytes.fromhex(s))
    seen, uniq = set(), []
    for k in cands:
        if 16 <= len(k) <= 32 and k not in seen:
            seen.add(k); uniq.append(k)
    print(f"[info] {len(uniq)} candidate keys from {len(files)} files", file=sys.stderr)
    data = Path(a.cfg).read_bytes()
    for key in uniq:
        try:
            ok, clear, _ = _attempt(data, key, "cbc", core.EG_IV)
        except (core.OpensslError, ValueError):
            continue
        if ok:
            out = a.output or "config.xml"
            Path(out).write_bytes(clear)
            print(f"[FOUND] key={key.hex()}", file=sys.stderr)
            print(out)
            return 0
    _err("no harvested key worked")
    return 2


def cmd_report(a) -> int:
    raw = Path(a.file).read_bytes().decode("utf-8", "replace")
    text, warn = report.render(raw, sections=a.section, show_secrets=a.show_secrets,
                               effective=getattr(a, "effective", True))
    if warn:
        print(f"note: {warn}", file=sys.stderr)
    if a.json:
        data, _ = report.parse(raw)
        if not a.show_secrets:
            data = _mask_data(data)
        print(json.dumps(data, indent=2))
    else:
        print(text)
    return 0


def _audit_live(a):
    """Fetch the live config and probe its ports; return (results, reconcile_rows)."""
    from .device import live, secrets
    host = secrets.get("X1852E_HOST", a.host or a.file, "192.168.1.1") or "192.168.1.1"
    raw = live.fetch(host).decode("utf-8", "replace")
    results = audit.evaluate_text(raw)
    recon = audit.reconcile(results, audit.probe_ports(host))
    print(f"[audit] live config + port probe of {host}", file=sys.stderr)
    return results, recon


def _emit_audit(a, results, recon) -> None:
    if a.json:
        out = {"surfaces": audit.to_json(results)}
        if recon is not None:
            out["reconcile"] = recon
        print(json.dumps(out, indent=2))
        return
    print(audit.render_table(results, only_exposed=a.only_exposed))
    if recon is not None:
        print("\n== config verdict vs. observed open ports ==")
        print(audit.render_reconcile(recon))


def cmd_audit(a) -> int:
    from .device import DeviceError
    if not a.live and not a.file:
        _err("audit needs a config file, or --live to pull from the device")
        return 2
    try:
        if a.live:
            results, recon = _audit_live(a)
        else:
            raw = Path(a.file).read_bytes().decode("utf-8", "replace")
            results, recon = audit.evaluate_text(raw), None
    except (OSError, DeviceError) as e:
        _err(f"audit failed: {e}")
        return 1
    _emit_audit(a, results, recon)
    return 1 if a.exit_code and any(r.wan_exposed for r in results) else 0


def _mask_data(data: dict) -> dict:
    out = {}
    for sect, items in data.items():
        new_items = []
        for label, attrs in items:
            masked = {}
            for k, v in attrs.items():
                if redact.classify(k.lstrip("_"), v):
                    v = redact.mask(v)
                masked[k] = v
            new_items.append([label, masked])
        out[sect] = new_items
    return out


def cmd_redact(a) -> int:
    text = Path(a.file).read_bytes().decode("latin-1")
    if not text.lstrip().startswith("<ROMFILE>"):
        _err(f"{a.file} is not a plaintext config (expected <ROMFILE>); "
             "run `romfile solve` first")
        return 2
    out, counts = redact.redact_text(text, a.keep_ssid, a.keep_macs, a.keep_ips)
    dest = Path(a.output or (a.file + ".redacted.xml"))
    dest.write_bytes(out.encode("latin-1"))
    print(f"[redact] {sum(counts.values())} values across {len(counts)} attributes masked",
          file=sys.stderr)
    print(dest)
    return 0


def _require_plaintext(text: str, file: str) -> None:
    if not text.lstrip().startswith("<ROMFILE>"):
        raise config.PathError(f"{file} is not a plaintext config (expected <ROMFILE>); "
                               "run `romfile solve` first")


def _mask_get(obj):
    if not isinstance(obj, dict):
        return obj
    out = {}
    for k, v in obj.items():
        if isinstance(v, dict):
            out[k] = _mask_get(v)
        elif redact.classify(k.lstrip("_"), v):
            out[k] = redact.mask(v)
        else:
            out[k] = v
    return out


def cmd_get(a) -> int:
    text = Path(a.file).read_bytes().decode("latin-1")
    try:
        _require_plaintext(text, a.file)
        val = config.get(text, a.path)
    except config.PathError as e:
        _err(str(e)); return 2
    if isinstance(val, str):
        print(json.dumps(val) if a.json else val)
        return 0
    data = val if a.show_secrets else _mask_get(val)
    if a.json:
        print(json.dumps(data, indent=2))
    else:
        for k, v in data.items():
            if isinstance(v, dict):
                print(f"[{k}]")
                for ak, av in v.items():
                    print(f"  {ak.lstrip('_')}={av}")
            else:
                print(f"{k.lstrip('_')}={v}")
    return 0


def cmd_set(a) -> int:
    raw = Path(a.file).read_bytes()
    text = raw.decode("latin-1")
    try:
        _require_plaintext(text, a.file)
        new_text, old, label = config.set_value(text, a.path, a.value)
    except config.PathError as e:
        _err(str(e)); return 2
    if old == a.value:
        print(f"[set] {label} unchanged (already {a.value!r})", file=sys.stderr)
    new_bytes = new_text.encode("latin-1")
    dest = Path(a.output or a.file)
    dest.write_bytes(new_bytes)
    attr = a.path.split("/")[-1].lstrip("_")
    print(f"[set] {label} {attr}: {old} -> {a.value}  ({len(new_bytes) - len(raw):+d} bytes)",
          file=sys.stderr)
    print(dest)
    return 0


def _mask_diff(d: dict) -> dict:
    out: dict = {}
    for section, groups in d.items():
        g = {"changed": [], "added": [], "removed": []}
        for item in groups["changed"]:
            attrs = {}
            for attr, (old, new) in item["attrs"].items():
                if redact.classify(attr.lstrip("_"), old or new or ""):
                    old = None if old is None else redact.mask(old)
                    new = None if new is None else redact.mask(new)
                attrs[attr] = [old, new]
            g["changed"].append({"element": item["element"], "attrs": attrs})
        for bucket in ("added", "removed"):
            g[bucket] = [{"element": it["element"], "attrs": _mask_get(it["attrs"])}
                         for it in groups[bucket]]
        out[section] = g
    return out


def cmd_diff(a) -> int:
    ta = Path(a.a).read_bytes().decode("latin-1")
    tb = Path(a.b).read_bytes().decode("latin-1")
    d = config.diff(ta, tb)
    if a.json:
        print(json.dumps(d if a.show_secrets else _mask_diff(d), indent=2))
    else:
        print(config.render_diff(d, show_secrets=a.show_secrets))
    return 1 if (d and a.exit_code) else 0


def cmd_fetch(a) -> int:
    from .device import DeviceError, live, secrets
    host = secrets.get("X1852E_HOST", a.host, "192.168.1.1")
    try:
        data = live.fetch(host)
    except (OSError, DeviceError) as e:
        _err(f"could not reach {host}/romfile.cfg: {e}")
        print(f"are you on the router's LAN? try: ping {host}", file=sys.stderr)
        return 1
    kind = live.classify(data)
    if kind == "encrypted":
        _err(f"router returned the *encrypted* container ({len(data)} bytes); "
             "this firmware no longer serves the plaintext config. Run `romfile solve` on it")
        return 2
    if kind != "plaintext":
        _err(f"unexpected payload ({len(data)} bytes): {data[:32]!r}")
        return 3
    out = a.output or "romfile_live.cfg"
    Path(out).write_bytes(data)
    print(f"[fetch] {len(data)} bytes of plaintext config -> {out}", file=sys.stderr)
    print(out)
    if not a.no_report:
        text, warn = report.render(data.decode("utf-8", "replace"), show_secrets=a.show_secrets)
        if warn:
            print(f"note: {warn}", file=sys.stderr)
        print(text)
    return 0


def cmd_acl(a) -> int:
    from .device import DeviceError, acl, secrets
    try:
        r = acl.Router(secrets.get("X1852E_HOST", a.host, "192.168.1.1"),
                       secrets.get("X1852E_WEB_USER", a.user, "root"),
                       secrets.get("X1852E_WEB_PASS", a.passwd, required=True))
        r.login()
        if a.action in ("on", "off"):
            status = r.post_acl("Yes" if a.action == "on" else "No")
            print(f"posted ACL update (http {status}): Telnet/LAN -> "
                  f"{'Yes' if a.action == 'on' else 'No'}", file=sys.stderr)
        rules = acl.parse_rules(r.acl_page())
    except (OSError, DeviceError) as e:
        _err(str(e)); return 1
    if not rules:
        _err("could not parse the ACL rule table"); return 1
    for i, rule in enumerate(rules):
        mark = "  <-- telnet" if (rule["application"] == "Telnet"
                                  and rule["interface"] == "LAN") else ""
        print(f"  [{i}] active={rule['activate']:<3} {rule['application']:<6} "
              f"{rule['interface']:<3} {rule['src_begin']}-{rule['src_end']}{mark}")
    return 0


def cmd_telnet(a) -> int:
    from .device import DeviceError, secrets, telnet
    try:
        out, banner = telnet.run(
            secrets.get("X1852E_HOST", a.host, "192.168.1.1"),
            secrets.get("X1852E_TELNET_USER", a.user, required=True),
            secrets.get("X1852E_TELNET_PASS", a.passwd, required=True),
            a.command, port=a.port)
    except (OSError, DeviceError) as e:
        _err(str(e)); return 1
    print("--- login banner ---\n" + banner + "\n--------------------", file=sys.stderr)
    sys.stdout.write(out)
    return 0


def cmd_recv(a) -> int:
    from .device import receivers
    receivers.http_receiver(a.outdir, port=a.port, bind=a.bind,
                            log=lambda m: print(m, file=sys.stderr))
    return 0


def cmd_tftp(a) -> int:
    from .device import DeviceError, receivers
    try:
        dest = receivers.tftp_receiver(a.outdir, port=a.port, bind=a.bind, timeout=a.timeout,
                                       log=lambda m: print(m, file=sys.stderr))
    except DeviceError as e:
        _err(str(e)); return 1
    print(dest)
    return 0


def cmd_unpack(a) -> int:
    outdir = None if a.list else a.outdir
    rc = unpack.unpack(a.image, outdir, do_extract=not a.no_extract,
                       log=lambda m: print(m, file=sys.stderr))
    if rc == 0 and outdir:
        print(outdir)
    return rc


COMMANDS = {
    "info": cmd_info,
    "solve": cmd_solve,
    "encrypt": cmd_encrypt,
    "decrypt": cmd_decrypt,
    "try": cmd_try,
    "findkey": cmd_findkey,
    "report": cmd_report,
    "get": cmd_get,
    "set": cmd_set,
    "diff": cmd_diff,
    "redact": cmd_redact,
    "audit": cmd_audit,
    "unpack": cmd_unpack,
    "fetch": cmd_fetch,
    "acl": cmd_acl,
    "telnet": cmd_telnet,
    "recv": cmd_recv,
    "tftp": cmd_tftp,
}


def _add_report_parser(sub) -> None:
    p = sub.add_parser("report", help="readable summary of a plaintext config")
    p.add_argument("file"); p.add_argument("--show-secrets", action="store_true")
    p.add_argument("--section", action="append"); p.add_argument("--json", action="store_true")
    p.add_argument("--no-effective", dest="effective", action="store_false",
                   help="do not annotate gated flags with their resolved state")


def _add_audit_parser(sub) -> None:
    p = sub.add_parser("audit",
                       help="resolve each service to its effective (reachable) state")
    p.add_argument("file", nargs="?", help="plaintext config (omit with --live)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--only-exposed", action="store_true",
                   help="show only surfaces that are actually reachable")
    p.add_argument("--live", action="store_true",
                   help="re-evaluate the live config and probe the known ports")
    p.add_argument("--host", help="live host (default: X1852E_HOST or 192.168.1.1)")
    p.add_argument("--exit-code", action="store_true",
                   help="exit 1 if any WAN-reachable surface is found")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="romfile",
                                 description="Inspect, decrypt and re-pack D-Link "
                                             "DSL-X1852E configs, and unpack its firmware")
    ap.add_argument("--version", action="version", version=f"romfile {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="parse the container header")
    p.add_argument("file"); p.add_argument("--json", action="store_true")

    p = sub.add_parser("solve", help="decrypt with the recovered AES-128-CBC key/IV")
    p.add_argument("file"); p.add_argument("-o", "--output")

    p = sub.add_parser("encrypt", help="re-pack plaintext into a restorable romfile.cfg")
    p.add_argument("file"); p.add_argument("-o", "--output")
    p.add_argument("--length", type=int, help="logical length for the header (default: file size)")
    p.add_argument("--verify-against", help="assert output is byte-identical to this file")
    p.add_argument("--force", action="store_true", help="pack even if the input is not text")

    p = sub.add_parser("decrypt", help="decrypt with an explicit key")
    p.add_argument("file"); p.add_argument("-o", "--output")
    p.add_argument("--key", required=True)
    p.add_argument("--keyfmt", default="hex", choices=["hex", "ascii", "password"])
    p.add_argument("--bits", default="auto", choices=["128", "256", "auto"])
    p.add_argument("--mode", default="cbc", choices=["cbc", "ecb"])
    p.add_argument("--iv", help="hex IV for CBC (default: the EG IV)")

    p = sub.add_parser("try", help="brute a candidate key list")
    p.add_argument("file"); p.add_argument("--keys", required=True); p.add_argument("-o", "--output")

    p = sub.add_parser("findkey", help="harvest keys from a firmware rootfs/binary and try each")
    p.add_argument("target"); p.add_argument("--cfg", required=True); p.add_argument("-o", "--output")

    _add_report_parser(sub)
    _add_audit_parser(sub)

    p = sub.add_parser("get", help="read a config value by path (Section/Element/attr)")
    p.add_argument("file")
    p.add_argument("path", help="e.g. Account/Entry0/web_passwd, WLan, Lan/Entry0")
    p.add_argument("--show-secrets", action="store_true", help="do not mask secrets in bulk output")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("set", help="change one config value in place (targeted, byte-exact)")
    p.add_argument("file")
    p.add_argument("path", help="Section/Element/attr, or Section/attr for a section-tag attribute")
    p.add_argument("value", help="new attribute value (no double quotes)")
    p.add_argument("-o", "--output", help="write here instead of editing in place")

    p = sub.add_parser("diff", help="compare two decrypted configs")
    p.add_argument("a"); p.add_argument("b")
    p.add_argument("--show-secrets", action="store_true", help="reveal secret values in the diff")
    p.add_argument("--exit-code", action="store_true", help="exit 1 when there are differences")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("redact", help="write a shareable copy of a plaintext config")
    p.add_argument("file"); p.add_argument("-o", "--output")
    p.add_argument("--keep-ssid", action="store_true", help="leave SSID names alone")
    p.add_argument("--keep-macs", action="store_true", help="leave MAC addresses alone")
    p.add_argument("--keep-ips", action="store_true", help="leave IPv4 addresses alone")

    p = sub.add_parser("unpack", help="unpack a firmware image (RSA + 2RDH + LZMA + SquashFS)")
    p.add_argument("image"); p.add_argument("-o", "--outdir")
    p.add_argument("--list", action="store_true", help="report only, write nothing")
    p.add_argument("--no-extract", action="store_true",
                   help="carve the SquashFS but do not run 7z")

    # --- live-device subcommands (talk to a unit on your LAN) ---------------
    p = sub.add_parser("fetch", help="pull the config the web server serves at /romfile.cfg")
    p.add_argument("host", nargs="?", help="default: X1852E_HOST or 192.168.1.1")
    p.add_argument("-o", "--output", help="default: romfile_live.cfg")
    p.add_argument("--show-secrets", action="store_true")
    p.add_argument("--no-report", action="store_true", help="just save, do not print a report")

    p = sub.add_parser("acl", help="show/toggle the Telnet-on-LAN ACL rule via the web UI")
    p.add_argument("action", choices=["show", "on", "off"])
    p.add_argument("--host"); p.add_argument("--user"); p.add_argument("--passwd")

    p = sub.add_parser("telnet", help="run one command over telnet (raw-socket)")
    p.add_argument("command")
    p.add_argument("--host"); p.add_argument("--user"); p.add_argument("--passwd")
    p.add_argument("--port", type=int, default=23)

    p = sub.add_parser("recv", help="HTTP receiver so the router can POST files back")
    p.add_argument("-o", "--outdir", default="incoming")
    p.add_argument("--port", type=int, default=8080); p.add_argument("--bind", default="0.0.0.0")

    p = sub.add_parser("tftp", help="one-shot TFTP receiver for a single router upload")
    p.add_argument("-o", "--outdir", default="incoming")
    p.add_argument("--port", type=int, default=6969); p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--timeout", type=float, default=120.0)

    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.cmd](args)
    except core.OpensslError as e:
        _err(str(e)); return 1
    except FileNotFoundError as e:
        _err(f"no such file: {e.filename}"); return 1
    except (ValueError, OSError) as e:
        _err(str(e)); return 1


if __name__ == "__main__":
    raise SystemExit(main())
