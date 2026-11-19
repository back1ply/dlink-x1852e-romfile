# Security Policy

## Scope

This repository is a **defensive / educational reverse-engineering** tool for a
device you own: it decrypts, inspects and re-packs the `romfile.cfg` configuration
backup of the D-Link DSL-X1852E, and unpacks its firmware image. It is not a remote
exploit — recovering the key requires the firmware image or a shell on your own unit.

There are two kinds of security issue to keep separate:

1. **Vulnerabilities in this tool** (the Python code here) — report them to us (below).
2. **Vulnerabilities in the D-Link device/firmware** that this tool merely documents —
   those belong to **D-Link's PSIRT**, not to this project. We cannot fix firmware.

## Reporting a vulnerability in this tool

Use GitHub's **private vulnerability reporting** for this repository
(Security → *Report a vulnerability*), or open a normal issue if the problem is not
itself sensitive. Please include the version (`romfile --version`), your OS and
`openssl` version, and a minimal reproduction. We aim to acknowledge within a week.

Do **not** attach a real `romfile.cfg` or decrypted config: it contains live
credentials. Redact it first with `romfile redact config.xml -o config.redacted.xml`.

## Device / firmware findings documented here

These are properties of the shipped D-Link firmware, recorded so owners can assess
their own units. Report firmware issues to **D-Link's PSIRT**; a CVE may be
appropriate.

| Finding | Firmware | Notes |
|---------|----------|-------|
| Config backup encrypted with a **vendor-wide constant key** (AES-128-CBC, key `0123456789abcdef`, static IV) | EG_1.00bxx | The encryption is an obfuscation layer, not an access control — the key is baked into `azencrypt` and appears shared across models. |
| `GET /romfile.cfg` serves the **plaintext running config with no authentication** | EG_1.00b15 | Exposes every stored password to anyone on the LAN. Same class as CVE-2018-8898 (DSL-3782). |
| Telnet **open on the LAN by default** with factory `admin` / `1234` | EG_1.00b28 | `ACL/Entry2` ships `Activate=Yes`; the plaintext-config endpoint is closed in b28 but this default is introduced. |

### If your device may be affected
- Change every credential in your config that you did not set yourself — treat
  factory defaults as compromised.
- If your config was ever served over unauthenticated HTTP, treat all of its
  credentials as exposed and rotate them.
- Check the telnet ACL and account on your own unit (`romfile report <config>
  --section ACL --section Account`).

## Supported versions

This project is pre-1.0; only the latest release/`main` is supported. There is no
back-porting of fixes to older tags.
