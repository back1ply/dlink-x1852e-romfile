"""One masking policy for every view of a decrypted ``romfile.cfg``.

A decrypted config is a credential dump, so both the on-screen ``romfile report``
and a redacted copy on disk have to agree about what is sensitive. Keeping the
attribute rules here means they cannot drift: a value that redaction removes can
never be printed in the clear by the report.

Two output shapes share the rules:

- :func:`mask` - partial, for reading on screen (``hu******yz``).
- :func:`redact_text` - full replacement, for a file you hand to someone else.
"""
from __future__ import annotations

import re

# Attribute values that carry a credential.
SECRET_ATTRS = {
    "password", "password_def", "passwd", "web_passwd", "telnet_passwd",
    "ftp_passwd", "console_passwd", "ddns_passwd", "wpapsk", "wdskey",
    "radius_key", "wpskeyascii", "wpskeyword", "secret", "psk", "authkey",
    "pin", "community", "snmp_community",
}

# Names and per-site identifiers: who you are, where you are, what you called things.
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

# Values that mean "unset" and must not be masked into readability.
EMPTY_VALUES = {"", "0", "-", "None", "N/A"}

ATTR_RE = re.compile(r'([A-Za-z_][\w.\-]*)=("([^"]*)")')
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
MAC_VALUE_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
PLACEHOLDER_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "00-00-00-00-00-00"}

REDACTED = "REDACTED"


def is_address(value: str) -> bool:
    """True for a routable or LAN IPv4 address (not 0.0.0.0 or a netmask)."""
    if not IPV4_RE.match(value) or value == "0.0.0.0":
        return False
    return not value.startswith("255.255.")


def classify(name, value, keep_ssid=False, keep_macs=False, keep_ips=False):
    """Return "secret", "identity", "mac", "ip" or None for one attribute.

    ``name`` is matched case-insensitively and should be bare (no leading underscore
    from the XML repair step).
    """
    if not value or value in EMPTY_VALUES:
        return None
    low = name.lower()
    if is_address(value):
        return None if keep_ips else "ip"
    # Detect hardware addresses by value as well: the firmware uses names like
    # "AL-MAC" and "Wds_MAC0", and a new name should not leak by default.
    if low in MAC_ATTRS or MAC_VALUE_RE.match(value):
        if value.lower() in PLACEHOLDER_MACS:
            return None
        return None if keep_macs else "mac"
    if low in SECRET_ATTRS:
        return "secret"
    if low in IDENTITY_ATTRS:
        return None if (keep_ssid and "ssid" in low) else "identity"
    return None


def mask(value: str) -> str:
    """Partial mask for on-screen output: keeps the first and last two characters."""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def redact_text(text, keep_ssid=False, keep_macs=False, keep_ips=False):
    """Replace sensitive attribute values in raw config text.

    Returns ``(text, {attribute: count})``. Byte structure outside attribute values
    is untouched, so the result is still a valid, reportable config.
    """
    counts: dict = {}

    def repl(m):
        name, value = m.group(1), m.group(3)
        if classify(name, value, keep_ssid, keep_macs, keep_ips) is None:
            return m.group(0)
        counts[name] = counts.get(name, 0) + 1
        return '%s="%s"' % (name, REDACTED)

    return ATTR_RE.sub(repl, text), counts
