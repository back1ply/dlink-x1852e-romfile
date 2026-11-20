"""Effective-state audit of a decrypted ``romfile.cfg``.

The config stores *every* flag, including dormant defaults and per-service flags the
firmware overrides via a master switch, an ACL rule, or an interface binding. Reading a
raw flag therefore tells you what the config *says*, not whether a service is actually
reachable. This module resolves each remote-access surface through its gating chain and
reports the **effective** verdict -- the same answer the device's UI and open ports give.

One declarative table (:data:`RULES`) is the single source of truth, shared by the
``audit`` command, the inline annotations in :mod:`dlink_romfile.report`, and
``docs/effective-state.md``.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field

from . import report

TRUTHY = {"yes", "1", "true", "enable", "enabled", "on"}

# surface -> TCP port used by the --live probe
PORTS = {
    "Web (WAN)": 80, "Web (LAN)": 80, "Telnet": 23,
    "Samba/SMB": 445, "TFTP": 69, "TR-069": 7547,
}


def _truthy(value) -> bool:
    return value is not None and value.strip().lower() in TRUTHY


@dataclass(frozen=True)
class Rule:
    """One remote-access surface and the config locations that gate it.

    ``flag`` is the raw (section, label, attr) the config exposes as the service's own
    switch; ``acl`` is an (application, interface) pair looked up in the ACL table;
    ``nonempty`` is a (section, label, attr) that must carry a value. ``kind`` selects
    how those pieces combine.
    """

    name: str
    kind: str                       # service | acl | plain | cwmp | advisory
    interface: str = "-"            # WAN | LAN | -
    flag: tuple | None = None
    acl: tuple | None = None
    nonempty: tuple | None = None
    advice: str = ""


RULES = [
    Rule("Web (WAN)", "acl", "WAN", acl=("Web", "WAN")),
    Rule("Web (LAN)", "acl", "LAN", acl=("Web", "LAN")),
    Rule("Telnet", "service", "LAN",
         flag=("Account", "TelnetEntry", "Active"), acl=("Telnet", "LAN")),
    Rule("Samba/SMB", "service", "LAN",
         flag=("Samba", "Entry0", "Active"), acl=("Samba", "LAN")),
    Rule("TFTP", "acl", "LAN", acl=("TFTP", "LAN")),
    Rule("Ping", "acl", "LAN", acl=("Ping", "LAN")),
    Rule("TR-069", "cwmp", "WAN",
         flag=("Cwmp", "Entry", "Tr069Enable"), nonempty=("Cwmp", "Entry", "acsUrl")),
    Rule("UPnP IGD", "plain", "LAN", flag=("Upnpd", "Entry", "Active")),
    Rule("SSH (console)", "advisory", "-",
         flag=("Account", "Common", "sshOption"),
         advice="console sshOption; not in the ACL set and not WAN-bound"),
]


@dataclass
class SurfaceResult:
    name: str
    interface: str
    configured: str                 # what the raw flag says, e.g. "Active=Yes" or "-"
    effective: bool | None          # True/False reachable; None for advisory-only
    reason: str
    flag_loc: tuple | None = None   # (section, label, attr) for report annotation
    advisory: bool = False
    _extra: dict = field(default_factory=dict)

    @property
    def wan_exposed(self) -> bool:
        return self.interface == "WAN" and self.effective is True


# --- config lookups ---------------------------------------------------------

def _element(data: dict, section: str, label: str) -> dict | None:
    for lbl, attrs in data.get(section, []):
        if lbl == label:
            return attrs
    return None


def _attr(data: dict, loc: tuple | None) -> str | None:
    if not loc:
        return None
    section, label, attr = loc
    attrs = _element(data, section, label)
    return None if attrs is None else attrs.get(attr)


def _acl(data: dict, app: str, iface: str) -> tuple[str | None, str | None]:
    """Return (label, Activate) of the ACL rule for (app, iface), or (None, None)."""
    for label, attrs in data.get("ACL", []):
        if attrs.get("Application") == app and attrs.get("Interface") == iface:
            return label, attrs.get("Activate")
    return None, None


# --- resolvers (one per kind) ----------------------------------------------

def _resolve_acl(rule: Rule, data: dict) -> SurfaceResult:
    assert rule.acl
    app, iface = rule.acl
    label, state = _acl(data, app, iface)
    loc = ("ACL", label, "Activate") if label else None
    if state is None:
        return SurfaceResult(rule.name, rule.interface, "-", False,
                             f"no ACL rule for {app}/{iface}", loc)
    on = _truthy(state)
    reason = f"ACL {app}/{iface}={state}"
    return SurfaceResult(rule.name, rule.interface, f"ACL={state}", on, reason, loc)


def _resolve_service(rule: Rule, data: dict) -> SurfaceResult:
    assert rule.flag and rule.acl
    flag = _attr(data, rule.flag)
    app, iface = rule.acl
    _, acl_state = _acl(data, app, iface)
    configured = f"{rule.flag[2]}={flag}" if flag is not None else "-"
    if not _truthy(flag):
        reason = f"service off ({rule.flag[2]}={flag})"
        return SurfaceResult(rule.name, rule.interface, configured, False, reason, rule.flag)
    if not _truthy(acl_state):
        reason = f"blocked by ACL {app}/{iface}={acl_state}"
        return SurfaceResult(rule.name, rule.interface, configured, False, reason, rule.flag)
    return SurfaceResult(rule.name, rule.interface, configured, True,
                         f"service on and ACL {app}/{iface}={acl_state}", rule.flag)


def _resolve_plain(rule: Rule, data: dict) -> SurfaceResult:
    assert rule.flag
    flag = _attr(data, rule.flag)
    configured = f"{rule.flag[2]}={flag}" if flag is not None else "-"
    on = _truthy(flag)
    return SurfaceResult(rule.name, rule.interface, configured, on,
                         f"{rule.flag[2]}={flag}", rule.flag)


def _resolve_cwmp(rule: Rule, data: dict) -> SurfaceResult:
    enable = _attr(data, rule.flag)
    active = _attr(data, ("Cwmp", "Entry", "Active"))
    acs = _attr(data, rule.nonempty)
    configured = f"Tr069Enable={enable}" if enable is not None else "-"
    if not _truthy(active):
        reason = f"CWMP deactivated (Active={active})"
        return SurfaceResult(rule.name, rule.interface, configured, False, reason, rule.flag)
    if not (acs or "").strip():
        return SurfaceResult(rule.name, rule.interface, configured, False,
                             "no ACS URL set", rule.flag)
    return SurfaceResult(rule.name, rule.interface, configured, True,
                         f"CWMP active, ACS={acs}", rule.flag)


def _resolve_advisory(rule: Rule, data: dict) -> SurfaceResult:
    loc = rule.flag
    assert loc
    flag = _attr(data, loc)
    configured = f"{loc[2]}={flag}" if flag is not None else "-"
    return SurfaceResult(rule.name, rule.interface, configured, None,
                         rule.advice, loc, advisory=True)


_RESOLVERS = {
    "acl": _resolve_acl, "service": _resolve_service, "plain": _resolve_plain,
    "cwmp": _resolve_cwmp, "advisory": _resolve_advisory,
}


def evaluate(data: dict) -> list[SurfaceResult]:
    """Resolve every rule against parsed config data (``report.parse`` output)."""
    return [_RESOLVERS[rule.kind](rule, data) for rule in RULES]


def evaluate_text(raw: str) -> list[SurfaceResult]:
    data, _ = report.parse(raw)
    return evaluate(data)


def annotate(data: dict) -> dict:
    """Map (section, label, attr) -> short effective-state note for report inlining."""
    notes: dict = {}
    for r in evaluate(data):
        if not r.flag_loc:
            continue
        if r.effective is None:
            notes[r.flag_loc] = f"effective: advisory — {r.reason}"
        elif r.effective:
            notes[r.flag_loc] = f"effective: REACHABLE ({r.interface}) — {r.reason}"
        else:
            notes[r.flag_loc] = f"effective: off — {r.reason}"
    return notes


# --- rendering --------------------------------------------------------------

def _verdict(r: SurfaceResult) -> str:
    if r.advisory:
        return "advisory"
    return "REACHABLE" if r.effective else "off"


def _format_table(header: tuple, rows: list[tuple]) -> str:
    """Render a fixed-width text table; tolerates an empty row set."""
    widths = [max(len(r[i]) for r in [header, *rows]) for i in range(len(header))]
    fmt = "  ".join("%%-%ds" % w for w in widths)
    sep = tuple("-" * w for w in widths)
    return "\n".join(fmt % row for row in (header, sep, *rows))


def _wanted(r: SurfaceResult, only_exposed: bool) -> bool:
    return not only_exposed or bool(r.effective) or r.wan_exposed


def render_table(results: list[SurfaceResult], only_exposed: bool = False) -> str:
    header = ("Surface", "Iface", "Configured", "Effective", "Why")
    rows = [(r.name, r.interface, r.configured, _verdict(r), r.reason)
            for r in results if _wanted(r, only_exposed)]
    out = _format_table(header, rows)
    exposed = [r.name for r in results if r.wan_exposed]
    if exposed:
        out += "\n\nWAN-EXPOSED: " + ", ".join(exposed)
    return out


def to_json(results: list[SurfaceResult]) -> list[dict]:
    return [{"surface": r.name, "interface": r.interface, "configured": r.configured,
             "effective": r.effective, "reason": r.reason,
             "advisory": r.advisory, "wan_exposed": r.wan_exposed} for r in results]


# --- live reconciliation ----------------------------------------------------

def probe_port(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_ports(host: str, timeout: float = 1.5) -> dict:
    """TCP-connect (no data sent) each known surface port; return {surface: open?}."""
    return {name: probe_port(host, port, timeout) for name, port in PORTS.items()}


def reconcile(results: list[SurfaceResult], observed: dict) -> list[dict]:
    """Compare each surface's config verdict with the observed open/closed port.

    The probe runs from the LAN, so it can only judge LAN-facing surfaces; WAN surfaces
    are skipped (a closed/open LAN port says nothing about WAN exposure).
    """
    rows = []
    for r in results:
        if not _reconcilable(r, observed):
            continue
        is_open = observed[r.name]
        rows.append({"surface": r.name, "effective": r.effective, "port_open": is_open,
                     "agree": r.effective == is_open})
    return rows


def _reconcilable(r: SurfaceResult, observed: dict) -> bool:
    """LAN-facing surfaces with a definite verdict and a probed port can be compared."""
    if r.interface == "WAN" or r.effective is None:
        return False
    return r.name in observed


def render_reconcile(rows: list[dict]) -> str:
    header = ("Surface", "Effective", "Port", "Agree")
    body = [(row["surface"], "reachable" if row["effective"] else "off",
             "open" if row["port_open"] else "closed",
             "yes" if row["agree"] else "** MISMATCH **") for row in rows]
    return _format_table(header, body)
