#!/usr/bin/env python3
"""Mask the sensitive attributes in a decrypted ``romfile.cfg`` (XML).

A decrypted config is a full credential dump: PPPoE login, WiFi PSKs, web/telnet/FTP
accounts, DDNS and SNMP secrets, the serial number, MACs, the LAN/WAN addressing and
the hostnames of the machines on the network. Keep the raw file out of git and share
this redacted copy instead.

    python tools/redact_config.py romfile_decrypted.xml -o romfile.redacted.xml
    python tools/redact_config.py cfg.xml --keep-ssid --keep-macs --keep-ips

Values are replaced with ``REDACTED``; every other byte - section order, entry
counts, firmware quirks like illegal entity refs - is preserved, so the result is
still useful as a structural reference (and still parses with ``romfile report``).

Vendor/ISP constants (``www.dlink.com``, NTP server, APN profile) are left alone:
they say nothing about you.
"""
import argparse
import os
import re
import sys

# Attribute names whose values are always redacted (matched whole, case-insensitive).
SECRET_ATTRS = {
    "password", "password_def", "passwd", "web_passwd", "telnet_passwd",
    "ftp_passwd", "console_passwd", "ddns_passwd", "wpapsk", "wdskey",
    "radius_key", "wpskeyascii", "wpskeyword", "secret", "psk", "authkey",
    "pin", "community", "snmp_community",
}

# Names, hardware IDs and per-site identifiers.
IDENTITY_ATTRS = {
    "username", "username_def", "telnet_username", "ftp_username",
    "console_username", "serialnum", "serialnumber", "oob_ssid", "ssid",
    "ssidalias", "hostname", "tmphostname", "netbiosname",
    "ddns_hostname", "ddns_name",
}

MAC_ATTRS = {
    "mac", "wan_mac", "activemac", "bssid",
    "wds_mac0", "wds_mac1", "wds_mac2", "wds_mac3",
}

ATTR_RE = re.compile(r'([A-Za-z_][\w.]*)=("([^"]*)")')
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def is_address(value):
    """True for anything that looks like a routable IPv4 address or a LAN address."""
    if not IPV4_RE.match(value) or value == "0.0.0.0":
        return False
    return not value.startswith("255.255.")


def redact(text, keep_ssid=False, keep_macs=False, keep_ips=False):
    """Return (redacted_text, {attribute: count})."""
    counts = {}

    def hit(name):
        counts[name] = counts.get(name, 0) + 1
        return '%s="REDACTED"' % name

    def repl(m):
        name, value = m.group(1), m.group(3)
        if not value:
            return m.group(0)
        low = name.lower()
        if not keep_ips and is_address(value):
            return hit(name)
        if low in MAC_ATTRS and not keep_macs:
            return hit(name)
        if low in SECRET_ATTRS:
            return hit(name)
        if low in IDENTITY_ATTRS and not (keep_ssid and "ssid" in low):
            return hit(name)
        return m.group(0)

    return ATTR_RE.sub(repl, text), counts


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Redact secrets in a decrypted romfile.cfg so it can be shared")
    ap.add_argument("cfg")
    ap.add_argument("-o", "--output", help="write here (default: stdout)")
    ap.add_argument("--keep-ssid", action="store_true", help="leave SSID names alone")
    ap.add_argument("--keep-macs", action="store_true", help="leave MAC addresses alone")
    ap.add_argument("--keep-ips", action="store_true", help="leave IPv4 addresses alone")
    args = ap.parse_args(argv)

    with open(args.cfg, "r", encoding="latin-1") as fh:
        text = fh.read()
    if not text.lstrip().startswith("<ROMFILE>"):
        print("%s does not look like a plaintext romfile (expected <ROMFILE>); "
              "decrypt it first with `romfile solve`" % args.cfg, file=sys.stderr)
        return 2

    out, counts = redact(text, args.keep_ssid, args.keep_macs, args.keep_ips)
    if not args.output:
        sys.stdout.write(out)
        return 0

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="latin-1", newline="") as fh:
        fh.write(out)
    print("wrote %s (%d bytes, %d values masked across %d attributes)"
          % (args.output, len(out), sum(counts.values()), len(counts)))
    for name in sorted(counts):
        print("  %-18s %d" % (name, counts[name]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
