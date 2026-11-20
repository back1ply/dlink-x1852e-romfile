"""Render a plaintext TrendChip/D-Link ``romfile.cfg`` as a readable report.

The config is near-XML (illegal entity refs and attribute names like ``11nMode``),
so parsing repairs it, with a regex fallback. Sensitivity rules come from
:mod:`dlink_romfile.redact`, the same ones file redaction uses, so the two views
cannot disagree. Returns strings; the CLI prints them.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from . import redact

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


def _render_section(name: str, items, show_secrets: bool, notes=None) -> list[str]:
    lines = ["", "== %s (%d) ==" % (name, len(items))]
    for i, (label, attrs) in enumerate(items):
        parts = []
        for k, v in attrs.items():
            if v == "":
                continue
            if len(v) > 60:
                v = "<%d chars>" % len(v)
            elif not show_secrets and redact.classify(k.lstrip("_"), v):
                v = redact.mask(v)
            note = notes.get((name, label, k)) if notes else None
            cell = "%s=%s" % (k.lstrip("_"), v)
            parts.append("%s  [%s]" % (cell, note) if note else cell)
        if not parts:
            continue
        prefix = "[%d]" % i if label.lower().startswith("entry") else "%s:" % label
        lines.append("  %s %s" % (prefix, "  ".join(parts)))
    return lines


def render(raw: str, sections=None, show_secrets: bool = False,
           effective: bool = True) -> tuple[str, str]:
    """Return (report_text, warning_text).

    When ``effective`` is set, gated security flags carry an inline note from
    :mod:`dlink_romfile.audit` explaining their resolved (reachable/off) state.
    """
    data, warn = parse(raw)
    notes = None
    if effective:
        from . import audit
        notes = audit.annotate(data)
    if sections:
        wanted = list(sections)
    else:
        wanted = [s for s in PRIORITY if s in data]
        wanted += [s for s in data if s not in PRIORITY]
    out: list[str] = []
    for name in wanted:
        if name in data:
            out += _render_section(name, data[name], show_secrets, notes)
    if not sections:
        hidden = sorted(set(data) - set(wanted))
        if hidden:
            out += ["", "(%d further sections not shown: %s)" % (len(hidden), ", ".join(hidden))]
    return "\n".join(out).lstrip("\n"), (warn or "")
