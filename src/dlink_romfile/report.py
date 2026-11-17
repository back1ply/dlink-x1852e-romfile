"""Render a plaintext TrendChip/D-Link ``romfile.cfg`` as a readable report.

The config is near-XML (illegal entity refs and attribute names like ``11nMode``),
so parsing repairs it, with a regex fallback. Secrets are masked unless asked for.
Returns strings; the CLI prints them.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

SECRET_HINT = re.compile(r"(pass|passwd|pwd|psk|key|secret|community|auth|token|pin)", re.I)

PRIORITY = [
    "SysInfo", "Sys", "Lan", "LanAlias", "Dhcp6s", "Wan", "Adsl", "WLan", "WLan11ac",
    "Firewall", "Nat", "VirServer", "portTriggering", "Accesslimit", "Account", "System",
    "Timezone", "Ddns", "Snmpd", "Upnpd", "Cwmp", "Mac", "QoS", "VlanBind", "ACL",
    "UrlFilter", "IGMPproxy", "SysLog", "Samba", "LANHost2",
]

ENTITY = re.compile(r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)")
DIGIT_NAME = re.compile(r'(\s)(\d[\w.\-]*)="')


def repair(raw: str) -> str:
    return DIGIT_NAME.sub(r'\1_\2="', ENTITY.sub("&amp;", raw))


def parse(raw: str):
    """Return (data, warning). data is {section: [(label, attrs), ...]}."""
    root = None
    for candidate in (raw, repair(raw)):
        try:
            root = ET.fromstring(candidate)
            break
        except ET.ParseError:
            continue
    if root is not None:
        return _collect(root), None
    return _collect_lenient(raw), "XML parse failed; used regex fallback"


def _collect(root) -> dict:
    data: dict = {}
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


def _collect_lenient(raw: str) -> dict:
    inner = raw
    m = re.match(r"\s*<ROMFILE>(.*)</ROMFILE>\s*$", raw, re.S)
    if m:
        inner = m.group(1)
    data: dict = {}
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


def mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def _render_section(name: str, items, show_secrets: bool) -> list[str]:
    lines = ["", "== %s (%d) ==" % (name, len(items))]
    for i, (label, attrs) in enumerate(items):
        parts = []
        for k, v in attrs.items():
            if v == "":
                continue
            if len(v) > 60:
                v = "<%d chars>" % len(v)
            elif not show_secrets and SECRET_HINT.search(k) and v not in ("0", "No", "None"):
                v = mask(v)
            parts.append("%s=%s" % (k.lstrip("_"), v))
        if not parts:
            continue
        prefix = "[%d]" % i if label.lower().startswith("entry") else "%s:" % label
        lines.append("  %s %s" % (prefix, "  ".join(parts)))
    return lines


def render(raw: str, sections=None, show_secrets: bool = False) -> tuple[str, str]:
    """Return (report_text, warning_text)."""
    data, warn = parse(raw)
    if sections:
        wanted = list(sections)
    else:
        wanted = [s for s in PRIORITY if s in data]
        wanted += [s for s in data if s not in PRIORITY]
    out: list[str] = []
    for name in wanted:
        if name in data:
            out += _render_section(name, data[name], show_secrets)
    if not sections:
        hidden = sorted(set(data) - set(wanted))
        if hidden:
            out += ["", "(%d further sections not shown: %s)" % (len(hidden), ", ".join(hidden))]
    return "\n".join(out).lstrip("\n"), (warn or "")
