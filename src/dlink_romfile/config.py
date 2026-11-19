"""Query, edit and compare a decrypted ``romfile.cfg`` (plaintext near-XML).

Two layers:

* :func:`get_value` / :func:`set_value` work on the raw text by **targeted
  substitution**. The text is handled as latin-1 (every byte maps to one char and
  back, losslessly), and ``set`` rewrites only the bytes of the one attribute value
  it targets -- every other byte is preserved. That keeps the project's round-trip
  guarantee intact: a ``set`` followed by ``encrypt`` differs from the original only
  where you asked it to.
* :func:`diff` compares two configs structurally, reusing :mod:`dlink_romfile.report`'s
  parser so the two views cannot disagree.

Path grammar (``/`` separated):

* ``Section``                     -- the whole section
* ``Section/Element``             -- one child element (``Element[n]`` for the n-th of
                                      repeated tags, 0-based)
* ``Section/Element/attr``        -- one attribute value
* ``Section/attr`` (set only)     -- an attribute on the section's own open tag

Elements are literal tags (``Entry0``, ``Common``, ``Entry`` ...); values live in
double-quoted attributes.
"""
from __future__ import annotations

import re

from . import redact, report


class PathError(ValueError):
    """Raised when a config path does not resolve to an element/attribute."""


def _split_element(token: str) -> tuple[str, int]:
    m = re.fullmatch(r"([A-Za-z_][\w.\-]*)(?:\[(\d+)\])?", token)
    if not m:
        raise PathError(f"bad path element: {token!r}")
    return m.group(1), int(m.group(2) or 0)


def _section_span(text: str, section: str) -> tuple[int, int, int, int]:
    """Return (open_start, open_end, body_start, body_end) for ``<section>..</section>``.

    For a self-closing section (``<section .../>``) body is empty and body_start ==
    body_end == open_end.
    """
    open_m = re.search(rf"<{re.escape(section)}\b[^>]*?(/?)>", text)
    if not open_m:
        raise PathError(f"section not found: {section!r}")
    if open_m.group(1) == "/":
        return open_m.start(), open_m.end(), open_m.end(), open_m.end()
    close_m = re.search(rf"</{re.escape(section)}\s*>", text[open_m.end():])
    body_start = open_m.end()
    body_end = body_start + close_m.start() if close_m else len(text)
    return open_m.start(), open_m.end(), body_start, body_end


def _element_span(text: str, body_start: int, body_end: int, name: str, idx: int):
    """Return (tag_start, tag_end) of the idx-th ``<name ...>`` in [body_start, body_end)."""
    body = text[body_start:body_end]
    hits = list(re.finditer(rf"<{re.escape(name)}\b[^>]*?/?>", body))
    if not hits:
        raise PathError(f"element not found: {name!r}")
    if idx >= len(hits):
        raise PathError(f"element {name}[{idx}] out of range (have {len(hits)})")
    m = hits[idx]
    return body_start + m.start(), body_start + m.end()


def _attr_in(text: str, tag_start: int, tag_end: int, attr: str):
    """Return (value_start, value_end, value) for attr within a tag region."""
    tag = text[tag_start:tag_end]
    m = re.search(rf'\b{re.escape(attr)}="([^"]*)"', tag)
    if not m:
        have = re.findall(r'\b([\w.\-]+)="', tag)
        raise PathError(f"attribute not found: {attr!r} (available: {', '.join(have) or 'none'})")
    return tag_start + m.start(1), tag_start + m.end(1), m.group(1)


def _resolve_attr(text: str, path: str):
    """Resolve a path to (value_start, value_end, value, label). 2 or 3 parts only."""
    parts = path.split("/")
    if len(parts) == 3:
        section, element, attr = parts
        name, idx = _split_element(element)
        _, _, bstart, bend = _section_span(text, section)
        tstart, tend = _element_span(text, bstart, bend, name, idx)
        vs, ve, val = _attr_in(text, tstart, tend, attr)
        return vs, ve, val, f"{section}/{element}"
    if len(parts) == 2:
        section, attr = parts
        ostart, oend, _, _ = _section_span(text, section)
        vs, ve, val = _attr_in(text, ostart, oend, attr)
        return vs, ve, val, section
    raise PathError("set/get of an attribute needs 'Section/attr' or 'Section/Element/attr'")


# --- public API ------------------------------------------------------------

def get(text: str, path: str):
    """Return a value (str) for a 3-part path, or a structured dict for shorter paths.

    ``Section`` -> {label: attrs}; ``Section/Element`` -> attrs; ``Section/Element/attr``
    or ``Section/attr`` -> the string value.
    """
    parts = path.split("/")
    if len(parts) >= 2:
        # Prefer an attribute resolution when the last part is not itself an element.
        try:
            _, _, val, _ = _resolve_attr(text, path)
            return val
        except PathError:
            if len(parts) != 2:
                raise
            # fall through: treat 'Section/Element' as an element dump
    data, _ = report.parse(text)
    if len(parts) == 1:
        if parts[0] not in data:
            raise PathError(f"section not found: {parts[0]!r}")
        return {label: attrs for label, attrs in data[parts[0]]}
    section, element = parts
    name, idx = _split_element(element)
    if section not in data:
        raise PathError(f"section not found: {section!r}")
    matches = [attrs for label, attrs in data[section] if label == name]
    if not matches:
        raise PathError(f"element not found: {section}/{name}")
    if idx >= len(matches):
        raise PathError(f"element {section}/{name}[{idx}] out of range (have {len(matches)})")
    return matches[idx]


def set_value(text: str, path: str, new_value: str) -> tuple[str, str, str]:
    """Return (new_text, old_value, label). Rewrites only the targeted attribute value."""
    if '"' in new_value:
        raise PathError('value may not contain a double quote')
    vs, ve, old, label = _resolve_attr(text, path)
    new_text = text[:vs] + new_value + text[ve:]
    return new_text, old, label


def diff(a: str, b: str):
    """Return a structured diff: {section: {"changed": [...], "added": [...], "removed": [...]}}.

    Each changed entry is {"element", "attrs": {attr: [old, new]}}; added/removed carry
    the element label and its attrs.
    """
    da, _ = report.parse(a)
    db, _ = report.parse(b)

    def keyed(items):
        counts: dict[str, int] = {}
        out = {}
        order = []
        for label, attrs in items:
            n = counts.get(label, 0)
            counts[label] = n + 1
            key = label if n == 0 else f"{label}[{n}]"
            out[key] = attrs
            order.append(key)
        return out, order

    result: dict = {}
    for section in list(da) + [s for s in db if s not in da]:
        ka, oa = keyed(da.get(section, []))
        kb, ob = keyed(db.get(section, []))
        changed, added, removed = [], [], []
        for key in oa:
            if key not in kb:
                removed.append({"element": key, "attrs": ka[key]})
                continue
            attr_changes = {}
            aattrs, battrs = ka[key], kb[key]
            for ak in list(aattrs) + [k for k in battrs if k not in aattrs]:
                av, bv = aattrs.get(ak), battrs.get(ak)
                if av != bv:
                    attr_changes[ak] = [av, bv]
            if attr_changes:
                changed.append({"element": key, "attrs": attr_changes})
        for key in ob:
            if key not in ka:
                added.append({"element": key, "attrs": kb[key]})
        if changed or added or removed:
            result[section] = {"changed": changed, "added": added, "removed": removed}
    return result


def _show(attr: str, value, show_secrets: bool) -> str:
    if value is None:
        return "(absent)"
    if not show_secrets and redact.classify(attr.lstrip("_"), value):
        return "(hidden)"
    return value


def render_diff(d: dict, show_secrets: bool = False) -> str:
    """Human-readable rendering of :func:`diff` output."""
    if not d:
        return "no differences"
    lines: list[str] = []
    for section, groups in d.items():
        lines.append(f"== {section} ==")
        for item in groups["removed"]:
            lines.append(f"  - {item['element']}  (removed)")
        for item in groups["added"]:
            lines.append(f"  + {item['element']}  (added)")
        for item in groups["changed"]:
            first = True
            for attr, (old, new) in item["attrs"].items():
                name = attr.lstrip("_")
                tag = f"  ~ {item['element']}" if first else "    " + " " * len(item["element"])
                first = False
                lines.append(f"{tag}  {name}: {_show(attr, old, show_secrets)} -> "
                             f"{_show(attr, new, show_secrets)}")
    return "\n".join(lines)
