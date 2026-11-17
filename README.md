# D-Link DSL-X1852E — `romfile.cfg` decryptor

First public tool and format writeup for the **D-Link DSL-X1852E** VDSL/ADSL
modem-router (EG region firmware, `EG_1.00bxx`). It decrypts the device's
`romfile.cfg` configuration backup, which this model encrypts.

This is defensive/educational reverse engineering of a device you own. It is not a
remote exploit — recovering the key requires either the firmware image or a shell on
your own unit. Use it only on hardware you are authorized to work on.

## TL;DR

```bash
# decrypt a backup you exported from your own router
python romfile_tool.py solve romfile.cfg -o config.xml

# edit config.xml, then re-pack it into a restorable backup
python romfile_tool.py encrypt config.xml -o new_romfile.cfg
```

The config comes out as plain `<ROMFILE>…</ROMFILE>` XML/`name=value` text.

### Verified correct (not just "looks like XML")

The model is proven, not guessed: re-encrypting the full decrypted buffer reproduces
the original backup **byte-for-byte** (identical SHA-256), and an edited config survives
an `encrypt`→`solve` round-trip byte-for-byte. The static IV makes CBC deterministic, so
this is an exact oracle, not a heuristic.

```bash
# reproduce the proof on your own file
python romfile_tool.py encrypt full_plaintext.bin --length <cfg_len> \
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

### Scope (what's confirmed vs open)

Confirmed on `EG_1.00b15`. The AU-region firmware (`1.12`–`1.20`) does **not** encrypt
`romfile.cfg` at all — `azencrypt` is absent and the config ships as plaintext — so this
scheme is specific to the **EG (encrypted) firmware line**. Whether the same
`0123456789abcdef` / `aa55…` key is reused across sibling Airoha/TrendChip models
(DSL-X3052E, DSL-3782, ISP-branded units) is **open** — it needs one such device's
`azencrypt`/`libtcapi` to check. PRs with other models' findings welcome.

## Tools

| file | purpose |
|------|---------|
| `romfile_tool.py` | `info` / `solve` / `encrypt` / `decrypt` / `try` / `findkey` for `romfile.cfg` |
| `tools/fetch_live_config.py` | pull the plaintext running config the EG web server serves |
| `tools/romfile_report.py` | pretty-print a decrypted/plaintext config (redacts secrets by default) |
| `tools/telnet_exec.py` | run one command over telnet (raw-socket; Py3.13+ has no telnetlib) |
| `tools/tftp_recv.py` | one-shot TFTP receiver, to pull a file off the device |

Requires `openssl` on PATH. No third-party Python packages.

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

## Security note

On the tested EG firmware the web server also serves the **plaintext** running config at
`http://<router>/romfile.cfg` with **no authentication**, exposing every stored password
to anyone on the LAN (same class as CVE-2018-8898). If that is true of your unit, treat
all stored credentials as compromised and change them. Report firmware issues to the
vendor's PSIRT.

## License

MIT (see `LICENSE`). Vendor firmware binaries are **not** included — see
`THIRD-PARTY-BINARIES.md`.
