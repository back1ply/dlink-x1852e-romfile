# Effective state: why the config and the device disagree

A decrypted `romfile.cfg` is a **flat dump of every stored flag** — including vendor
defaults and per-service flags that the firmware never acts on directly. Reading a raw
flag tells you what the config *stores*, not whether a service is actually reachable.
The device's own behaviour (and its web UI) show the **resolved** state after the
firmware applies a chain of gates above each flag:

- a **master switch** for the whole feature (e.g. the Samba server enable),
- an **ACL rule** that permits/blocks the service per interface (LAN/WAN),
- a dependency such as a **non-empty ACS URL** for TR-069.

So a per-service flag that reads `Active=Yes` can still be *off* because an ACL blocks
it, the master switch is off, or a required value is empty. This is exactly why reading
the raw config is misleading, and why `romfile audit` exists: it resolves each
remote-access surface through its gate chain and reports the effective verdict, and
`romfile report` annotates the gated flags inline.

## Gating map

This table mirrors `RULES` in [`src/dlink_romfile/audit.py`](../src/dlink_romfile/audit.py)
— that table is the single source of truth; this doc is the human-readable copy.

| Surface | Raw "configured" flag | Gate(s) that decide reachability | Reachable iff |
|---|---|---|---|
| Web admin (WAN) | — | `ACL[Web/WAN].Activate` | ACL = Yes **(key WAN exposure)** |
| Web admin (LAN) | — | `ACL[Web/LAN].Activate` | ACL = Yes |
| Telnet | `Account/TelnetEntry.Active` | `ACL[Telnet/LAN].Activate` | flag = Yes **and** ACL = Yes |
| Samba / SMB | `Samba/Entry0.Active` | `ACL[Samba/LAN].Activate` | flag = Yes **and** ACL = Yes |
| TFTP | — | `ACL[TFTP/LAN].Activate` | ACL = Yes |
| FTP | `Account/FtpCommon.Active` | — (inetd; `bftpd` is IPv6-only) | Active = Yes |
| DLNA / DMS | `DMS/Entry.Enable` | — (media server, port 12345) | Enable = Yes |
| DNS | `Dproxy/Entry.Active` | `ACL[domain/LAN].Activate` | Active = Yes **and** ACL = Yes |
| SNMP | `Snmpd/Entry.Active` | — (UDP 161) | Active = Yes |
| Ping | — | `ACL[Ping/LAN].Activate` | ACL = Yes |
| TR-069 / CWMP | `Cwmp…Tr069Enable` | `Cwmp…Active` **and** non-empty `Cwmp…acsUrl` | Active = Yes and ACS set |
| UPnP IGD | `Upnpd/Entry.Active` | — | Active = Yes |
| SSH (console) | `Account/Common.sshOption` | not in the ACL set, not WAN-bound | advisory only |

`Active`/`Activate` values are `Yes`/`No`; `Tr069Enable` is `1`/`0`. The resolver treats
`{yes, 1, true, enable, enabled, on}` (case-insensitive) as truthy.

## Usage

```bash
# resolve every surface to its effective state (table)
romfile audit config.xml

# only what is actually reachable, as JSON
romfile audit config.xml --only-exposed --json

# fail (exit 1) if any WAN-facing surface is reachable — useful as a check
romfile audit config.xml --exit-code

# pull the live config and compare the verdict against observed open ports
romfile audit --live 192.168.1.1
```

The `--live` probe runs from your LAN. It is a **TCP connect** probe, so UDP-only services
(TFTP, SNMP) are listed in the effective-state table but left out of the reconcile rather
than reported misleadingly. A WAN surface that *shares* a port with a LAN one (Web uses 80
for both) is skipped too — an open LAN port can't distinguish WAN exposure from the LAN
sibling. A WAN surface with its **own** port (TR-069's 7547) is still reconciled, because an
answer there is the daemon itself. A `** MISMATCH **` row means the config says a service is
off but its port answered (or vice-versa) — e.g. an SMB or TR-069 listener that keeps
running despite the config flag being off.

## Worked example

On a unit whose config stored `TelnetEntry.Active=Yes`, `Samba/Entry0` populated, and
`Tr069Enable=1`, the raw `report` looked alarming. `audit` resolved all three to **off**:

```
Telnet     LAN  Active=Yes     off  blocked by ACL Telnet/LAN=No
Samba/SMB  LAN  Active=No      off  service off (Active=No)
TR-069     WAN  Tr069Enable=1  off  CWMP deactivated (Active=No)
```

…which matched the device's web UI exactly.
