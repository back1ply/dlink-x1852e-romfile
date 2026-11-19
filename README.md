# D-Link DSL-X1852E — `romfile.cfg` decryptor

First public tool and format writeup for the **D-Link DSL-X1852E** VDSL/ADSL
modem-router (EG region firmware, `EG_1.00bxx`). It decrypts the device's
`romfile.cfg` configuration backup, which this model encrypts.

It also documents the EG firmware container — an RSA-2048 signature in front of a
plain `2RDH` + LZMA + SquashFS image, not the encrypted blob it is usually described
as — and ships an unpacker for it.

This is defensive/educational reverse engineering of a device you own. It is not a
remote exploit — recovering the key requires either the firmware image or a shell on
your own unit. Use it only on hardware you are authorized to work on.

## Install

```bash
# not on PyPI yet - install from the repo
uv tool install "git+https://github.com/back1ply/dlink-x1852e-romfile"
# from a checkout:  uv tool install .    or    pip install .
```

Installs a `romfile` command. Requires **`openssl` on PATH** (used for the AES
primitive). No Python dependencies; 7z is optional, for extracting a firmware rootfs.

## TL;DR

```bash
# decrypt a backup you exported from your own router
romfile solve romfile.cfg -o config.xml

# edit config.xml, then re-pack it into a restorable backup
romfile encrypt config.xml -o new_romfile.cfg

# a copy that is safe to paste into an issue
romfile redact config.xml -o config.redacted.xml

# machine-readable header info
romfile info romfile.cfg --json
```

The config comes out as plain `<ROMFILE>…</ROMFILE>` XML/`name=value` text.
Subcommands: `info solve encrypt decrypt try findkey report redact unpack`. Data is
written to stdout; notes/keys go to stderr. Exit codes: `0` ok, `1` failure, `2` usage.

### Verified correct (not just "looks like XML")

The model is proven, not guessed: re-encrypting the full decrypted buffer reproduces
the original backup **byte-for-byte** (identical SHA-256), and an edited config survives
an `encrypt`→`solve` round-trip byte-for-byte. The static IV makes CBC deterministic, so
this is an exact oracle, not a heuristic.

```bash
# reproduce the proof on your own file
romfile encrypt full_plaintext.bin --length <cfg_len> \
    -o out.cfg --verify-against original_romfile.cfg   # -> byte-identical: True
```

## The format (EG_1.00bxx)

| offset | size | field |
|--------|------|-------|
| 0 | 4 | **CRC32 of the ciphertext** (integrity check — not of the plaintext) |
| 4 | 4 | plaintext length, big-endian |
| 8 | …  | **AES-128-CBC** ciphertext (length a multiple of 16) |

Decrypt the body from offset 8, then keep the first *plaintext-length* bytes (the
rest is block padding).

### Key / IV / mode

- **Mode:** AES-128-**CBC**
- **Key:** ASCII `0123456789abcdef` (hex `30313233343536373839616263646566`)
- **IV:** `aa55aa55aa55aa55aa55aa55aa55aa55`

One-liner with openssl:

```bash
tail -c +9 romfile.cfg | \
  openssl enc -d -aes-128-cbc -nopad \
    -K 30313233343536373839616263646566 \
    -iv aa55aa55aa55aa55aa55aa55aa55aa55 | head -c <plaintext_len>
```

## How the key was recovered

The key lives in `/userfs/bin/azencrypt` on the device (a small stripped MIPS CLI the
firmware calls as `azencrypt dec <in> <out>`). Disassembly of its `main()` shows the
ASCII key passed to `aes_expand_key` and the static `.data` IV passed to
`aes_cbc_decrypt_blocks`. The header magic was confirmed as `crc32(ciphertext)`.

`romfile_tool.py` also has a `findkey` mode that harvests candidate keys from a
firmware rootfs, for related models.

### Scope — the key is a vendor-wide constant (verified on a second model)

The same `0123456789abcdef` / `aa55…` key+IV is **reused across the DSL-X Airoha family**,
not per-model. Confirmed by unpacking a second model's firmware:

| model | firmware | `azencrypt` arch | key | IV |
|-------|----------|------------------|-----|----|
| DSL-X1852E | EG_1.00b15 | MIPS (32-bit BE) | `0123456789abcdef` | `aa55…` |
| DSL-X3052E | AU_1.05b01 | ARM (32-bit LE) | `0123456789abcdef` | `aa55…` |

These are **independently compiled binaries for different CPUs**, yet both load the same
ASCII string as the first argument to `aes_expand_key` (MIPS `a0` / ARM `r0`) and carry
the identical 16-byte IV constant — so the key is baked vendor-wide, not generated per
device or per build. (Note: the DSL-X1852E *AU* firmware ships no `azencrypt` and stores
the config in plaintext; encryption appears on the X-series EG builds and on the X3052E.)

The firmware image itself is a separate story, and the two axes do not line up: the EG
image is not encrypted at all, while the older AU image is `4RDH` + AES-128-CBC with key
`11223344556677889900aabbccddeeff` and IV `a5…` (from the GPL `buildImage.sh`). See
[The firmware image](#the-firmware-image) below.

## The firmware image

An EG upgrade file (`tclinux_EG_1.00b28.sig.bin`) is **not encrypted**. It is the flash
image with a signature block glued to the front:

| offset | size | field |
|--------|------|-------|
| `0x000` | 256 | RSA-2048 PKCS#1 v1.5 signature |
| `0x100` | 256 | `2RDH` container header — the same header the flash layout uses |
| `0x200` | … | LZMA-alone stream → kernel + boot ramdisk |
| … | … | `hsqs` SquashFS 4.0 rootfs (LZMA blocks), to EOF |

`2RDH` header, all fields big-endian:

| offset | size | field |
|--------|------|-------|
| `+0x00` | 4 | magic `2RDH` |
| `+0x04` | 4 | header size, `0x100` |
| `+0x08` | 4 | image size, counted from the magic to the end of the image |
| `+0x0C` | 4 | check value (not CRC32 or CRC32C of the payload) |
| `+0x10` | … | ASCII version, `EG_1.00b28\n`, zero padded to `0x100` |

Why the old "encrypted end to end" reading was wrong: the header sits at `0x100`, so
every AES trial at offset 0/256/512 destroyed the magic before anything could match, and
a fully compressed payload has ~8 bits/byte of entropy, which is indistinguishable from
ciphertext by eye. On the device side, the bootloader contains no AES S-box and no key
material — its only job is `lzma decompress boot.img` — and `libcfg_clisvc.so` does
`PEM_read_bio_RSA_PUBKEY` + `SHA256` + `RSA_verify`. The live unit's flash starts with
the same `2RDH` + LZMA layout (`EG_1.00b15`, image size 22,732,500), so the upgrade file
is the flash image plus a signature, nothing more.

```bash
romfile unpack tclinux_EG_1.00b28.sig.bin -o out/
# -> out/image.bin (kernel+ramdisk), out/rootfs.squashfs, out/rootfs/ (needs 7z)

romfile unpack tclinux_EG_1.00b28.sig.bin --list   # report only
```

On `EG_1.00b28` that yields a 15,005,504-byte MIPS kernel+initramfs (Linux 3.18.21) and
an 18,908,974-byte SquashFS with 1,888 files.

One loose end: the signature block is a well-formed PKCS#1 v1.5 SHA-256 block against
the RSA-2048 public key embedded in `libcfg_clisvc.so`, but its digest matches none of
the payload, the LZMA stream, the SquashFS or the decompressed image. Either the packer
rewrites what was signed or the release re-signs a canonicalised form. It does not
affect extraction — nothing here is signed *and* encrypted.

### The older AU layout is encrypted

AU builds still use the `buildImage.sh` scheme: `4RDH` at offset 0 with an AES-128-CBC
payload (key `11223344556677889900aabbccddeeff`, IV `a5…`). EG dropped it.
`romfile unpack` detects that case, prints the decrypt parameters and exits `2` instead
of decompressing noise.

Note that image encryption and config encryption are unrelated: the AU image is
encrypted while its config is stored in plaintext, and the EG image is plaintext while
its config is encrypted.

## What changed in EG_1.00b28

Comparing the factory config shipped inside the b28 rootfs against the live b15 unit:

| | `EG_1.00b15` (live) | `EG_1.00b28` (factory) |
|---|---|---|
| `userfs/bin/azencrypt` | – | **byte-identical** to b15, so the config key/IV are unchanged |
| `GET /romfile.cfg` | plaintext config, no auth | 0-byte placeholder; the backup is generated by `cgi-bin/get/New_GUI/romfile.cfg`, which runs `azencrypt enc` |
| backup link on `System.asp` | `/romfile.cfg` | `/cgi-bin/get/New_GUI/romfile.cfg` |
| telnet/LAN ACL (`ACL/Entry2`) | `Activate=No`, port 23 filtered | `Activate=Yes` — telnet open on the LAN |
| `Account/TelnetEntry` | site-set credentials | factory default `admin` / `1234` |

So the unauthenticated plaintext-config download is **fixed** in b28, but it buys
little: the container and the key are unchanged, so `romfile solve` still decrypts any
b28 backup. The regression that matters is the ACL default — after a factory reset or a
b28 upgrade, telnet answers on the LAN with the shipped `admin` / `1234` account until
someone changes it or sets `Activate=No` again.

## Scope of the evidence

What the claims above rest on, so they are not read wider than they go:

- **One DSL-X1852E unit**, EG region, running `EG_1.00b15`: its live config, the first
  512 KB of its firmware partition, and the `azencrypt` / `libcfg_clisvc.so` binaries
  from its rootfs.
- **`EG_1.00b28` as a download only.** The image was unpacked and compared statically.
  It was never flashed, so the telnet-ACL and backup-CGI changes are read from the
  factory config, web tree and CGI binaries inside the image — not observed on running
  hardware.
- **`DSL-X3052E` AU_1.05b01** firmware, for the key-reuse comparison: a second model on
  a different CPU architecture, with the same constants.

That supports a vendor-wide key and container for the DSL-X Airoha family; it does not
make either universal to every D-Link DSL device, and other regions, hardware revisions
and firmware branches were not examined. If yours differs, `romfile info` and `romfile
unpack` will show it quickly. Likewise the telnet default is what one b28 image ships,
not a survey of deployed units.

## Commands & tools

The installed `romfile` command (package `dlink_romfile`, source in `src/`):

| command | purpose |
|---------|---------|
| `romfile info` | parse the container header (`--json`) |
| `romfile solve` | decrypt with the recovered AES-128-CBC key/IV |
| `romfile encrypt` | re-pack plaintext into a restorable `romfile.cfg` (`--verify-against`) |
| `romfile decrypt` | decrypt with an explicit `--key`/`--iv`/`--mode` |
| `romfile try` | brute a candidate key list |
| `romfile findkey` | harvest keys from a firmware rootfs/binary and try each |
| `romfile report` | readable summary of a plaintext config (masks credentials, hostnames and addresses unless `--show-secrets`; `--json`) |
| `romfile redact` | write a shareable copy of a plaintext config, sensitive values replaced with `REDACTED` |
| `romfile unpack` | unpack a firmware image: RSA signature + `2RDH` + LZMA + SquashFS (`--list` to report only) |

Standalone helpers in `tools/` — device access, not part of the installed package:

| file | purpose |
|------|---------|
| `tools/fetch_live_config.py` | pull the plaintext running config the b15 web server serves |
| `tools/acl_toggle.py` | flip the Telnet/LAN ACL rule (`Entry2`) via the web UI — `show` / `on` / `off` |
| `tools/telnet_exec.py` | run one command over telnet (raw-socket; Py3.13+ has no telnetlib) |
| `tools/pull_from_router.py` | tiny HTTP receiver so the router can push files (dumps) back to this PC |
| `tools/tftp_recv.py` | one-shot TFTP receiver, to pull a file off the device |
| `tools/router_secrets.py` | shared credential loader (flag > env var > `secrets.local.env`) for the device tools |
| `tools/redact_config.py` | shim for `romfile redact`, for running from a checkout |
| `tools/unpack_image.py` | shim for `romfile unpack`, for running from a checkout |

The device tools (`fetch_live_config`, `acl_toggle`, `telnet_exec`, `pull_from_router`,
`tftp_recv`) need a live unit; the two shims are equivalent to the installed commands.
`fetch_live_config`, `acl_toggle` and `telnet_exec` resolve host and credentials through
`router_secrets.py` — precedence is CLI flag > environment variable > `secrets.local.env`.
Copy `secrets.example.env` to `secrets.local.env` (gitignored) and fill it in, or export
`X1852E_HOST` / `X1852E_WEB_USER` / `X1852E_WEB_PASS` / `X1852E_TELNET_USER` /
`X1852E_TELNET_PASS`. No credentials are stored in the repo.

Requires `openssl` on PATH. No third-party Python runtime dependencies.

### Migrating from the old script

The former `romfile_tool.py` and `tools/romfile_report.py` are now the `romfile`
command — same subcommands and flags:

| old | new |
|-----|-----|
| `python romfile_tool.py solve x.cfg -o y.xml` | `romfile solve x.cfg -o y.xml` |
| `python romfile_tool.py encrypt y.xml -o x.cfg` | `romfile encrypt y.xml -o x.cfg` |
| `python tools/romfile_report.py cfg.xml` | `romfile report cfg.xml` |

### For agents / CI

Non-interactive by design: no prompts, nothing read from stdin, deterministic exit
codes, and `--json` on `info`/`report` emits exactly one JSON document on stdout. Run
`romfile <sub> --help` for the full flag list.

## Development

```bash
uv sync          # install with the dev group (pytest)
uv run pytest -q # 20 tests: behaviour per subcommand, redaction, masking
uv build         # wheel + sdist in dist/
```

A `justfile` wraps these as `just setup|test|lint|check`.

## Related work / prior art

Router config decryption is a well-trodden category; this is the first tool targeting
*this* model and its specific parameters.

- [`pawitp/asus-romfile-tools`](https://github.com/pawitp/asus-romfile-tools) — ASUS DSL
  (also TrendChip) `romfile.cfg`, but a **different, non-AES** byte-obfuscation scheme.
- [`antnks/technicolor-config-decrypt`](https://github.com/antnks/technicolor-config-decrypt)
  — Technicolor `config.bin`, AES-128-CBC with a hardware key.
- [`coolrecep/huawei-ont-firmware-reverse-engineering-research`](https://github.com/coolrecep/huawei-ont-firmware-reverse-engineering-research)
  — Huawei ONT XML config, AES-256 + SHA-256 PBKDF.
- Background on the SDK: CVE-2018-8898 (DSL-3782, same New_GUI framework).

## Handling captured configs

A decrypted config is a full credential dump: PPPoE login, WiFi PSKs, web/telnet/FTP
accounts, DDNS and SNMP secrets, the serial number, MACs, the WAN address and the
hostnames of the machines on your network. Treat every `romfile.cfg` and every
`config.xml` derived from one as secret.

`romfile report` masks credentials, hostnames and addresses by default (`--show-secrets`
is the opt-in), but that masking is for reading on screen, not for producing a file you
can post. For that:

```bash
romfile solve romfile.cfg -o config.xml
romfile redact config.xml -o config.redacted.xml
# [redact] 109 values across 46 attributes masked
```

It replaces the values of password/PSK/RADIUS/SNMP attributes, usernames, SSIDs,
hostnames, MACs and every routable IPv4 address with `REDACTED`, and leaves
everything else byte-for-byte intact — section order, entry counts, firmware quirks
like illegal entity refs — so `romfile report` still renders it the same way and is
still useful as a structural reference. `--keep-ssid`, `--keep-macs` and `--keep-ips`
relax it when those do not identify you. Vendor/ISP constants (`www.dlink.com`, the NTP
server, the APN profile) are deliberately left alone.

`report` and `redact` share one policy (`src/dlink_romfile/redact.py`), so a value that
`redact` removes can never be printed in the clear by `report` — including the `--json`
form.

`*.cfg`, `*.bin`, `input/`, `work/` and `secrets/` are gitignored here. That only
protects `git add .` — it does nothing for a snippet pasted into an issue, which is how
these files usually leak.

## Security note

On `EG_1.00b15` the web server serves the **plaintext** running config at
`http://<router>/romfile.cfg` with **no authentication**, exposing every stored password
to anyone on the LAN (same class as CVE-2018-8898). `EG_1.00b28` closes it (see the
table above), but the config is still encrypted with a vendor-wide constant key, so that
encryption is an obfuscation layer, not a control.

The default worth checking on your own unit is telnet: filtered on the b15 unit this was
tested against, open on the LAN by default on b28 (`ACL/Entry2`, `Activate=Yes`) with the
shipped `admin` / `1234` account until someone changes it. Any credential in the config
that you did not set yourself is a factory default and should be replaced.

If your config has been exposed, treat every credential in it as compromised and change
them. Report firmware issues to the vendor's PSIRT.

## License

MIT (see `LICENSE`). Vendor firmware binaries are **not** included — see
`THIRD-PARTY-BINARIES.md`.
