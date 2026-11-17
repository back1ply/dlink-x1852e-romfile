#!/usr/bin/env python3
"""Summarise a D-Link / TrendChip `romfile.cfg` (plaintext XML) as a readable report.

    python romfile_report.py input/romfile_live.cfg
    python romfile_report.py input/romfile_live.cfg --show-secrets
    python romfile_report.py input/romfile_live.cfg --section Wan --section WLan

Secrets (passwords, PSKs, SNMP community, SIP auth) are masked unless
--show-secrets is given. Use `tools/fetch_live_config.py` to download the file itself.
"""

import argparse
import re
import sys
import xml.etree.ElementTree as ET

SECRET_HINT = re.compile(r"(pass|passwd|pwd|psk|key|secret|community|auth|token|pin)", re.I)

# Sections worth showing first, in a sensible reading order.
PRIORITY = [
    "SysInfo", "Sys", "Lan", "LanAlias", "Dhcp6s", "Wan", "Adsl", "WLan", "WLan11ac",
    "Firewall", "Nat", "VirServer", "portTriggering", "Accesslimit", "Account", "System",
    "Timezone", "Ddns", "Snmpd", "Upnpd", "Cwmp", "Mac", "QoS", "VlanBind", "ACL",
    "UrlFilter", "IGMPproxy", "SysLog", "Samba", "LANHost2",
]

ENTITY = re.compile(r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)")
# The vendor's own parser accepts attribute names that XML forbids, e.g. 11nMode="1"
DIGIT_NAME = re.compile(r'(\s)(\d[\w.\-]*)="')


def repair(raw):
    return DIGIT_NAME.sub(r'\1_\2="', ENTITY.sub("&amp;", raw))


def load(path):
    """Parse the romfile; it is near-XML, so repair entities and illegal attribute names."""
    raw = open(path, "rb").read().decode("utf-8", "replace")
    for candidate in (raw, repair(raw)):
        try:
            return ET.fromstring(candidate), None
        except ET.ParseError:
            continue
    try:
        ET.fromstring(repair(raw))
    except ET.ParseError as exc:
        return None, "XML parse failed (%s) - falling back to regex" % exc
    return None, None


def collect(root):
    """{section: [(label, attrs), ...]} walking descendants so nested blocks are kept.

    WAN lives under <Wan><WanPTM><Common .../><Entry .../></WanPTM></Wan>, so a direct
    child scan would silently drop it.
    """
    data = {}
    for section in root:
        items = []
        if section.attrib:
            items.append((section.tag, dict(section.attrib)))
        for el in section.iter():
            if el is section or not el.attrib:
                continue
            items.append((el.tag, dict(el.attrib)))
        if items:
            data[section.tag] = items
    return data


def collect_lenient(raw):
    """Regex fallback with the same output shape; peels the outer <ROMFILE> wrapper."""
    inner = raw
    m = re.match(r"\s*<ROMFILE>(.*)</ROMFILE>\s*$", raw, re.S)
    if m:
        inner = m.group(1)
    data = {}
    for m in re.finditer(r"<([A-Za-z][\w.-]*)>(.*?)</\1>", inner, re.S):
        section, body = m.group(1), m.group(2)
        items = []
        for em in re.finditer(r"<([A-Za-z][\w.\-]*)\b([^>]*?)/?>", body):
            attrs = dict(re.findall(r'([\w.\-]+)="([^"]*)"', em.group(2)))
            if attrs:
                items.append((em.group(1), attrs))
        if items:
            data.setdefault(section, []).extend(items)
    return data


def mask(value):
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def show(name, items, show_secrets):
    print("\n== %s (%d) ==" % (name, len(items)))
    for i, (label, attrs) in enumerate(items):
        parts = []
        for k, v in attrs.items():
            if v == "":
                continue
            if len(v) > 60:                      # TR-069 attribute blobs; not human-readable
                v = "<%d chars>" % len(v)
            elif not show_secrets and SECRET_HINT.search(k) and v not in ("0", "No", "None"):
                v = mask(v)
            parts.append("%s=%s" % (k.lstrip("_"), v))
        if not parts:
            continue
        prefix = "[%d]" % i if label.lower().startswith("entry") else "%s:" % label
        print("  %s %s" % (prefix, "  ".join(parts)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("romfile")
    ap.add_argument("--show-secrets", action="store_true")
    ap.add_argument("--section", action="append", default=None)
    args = ap.parse_args()

    raw = open(args.romfile, "rb").read().decode("utf-8", "replace")
    root, warn = load(args.romfile)
    if warn:
        print("note: %s" % warn, file=sys.stderr)
    data = collect(root) if root is not None else collect_lenient(raw)

    if args.section:
        wanted = args.section
    else:
        wanted = [s for s in PRIORITY if s in data]
        wanted += [s for s in data if s not in PRIORITY]

    for name in wanted:
        if name in data:
            show(name, data[name], args.show_secrets)
        else:
            print("\n== %s: not present ==" % name, file=sys.stderr)

    if not args.section:
        hidden = sorted(set(data) - set(wanted))
        if hidden:
            print("\n(%d further sections not shown: %s)" % (len(hidden), ", ".join(hidden)))


if __name__ == "__main__":
    main()
