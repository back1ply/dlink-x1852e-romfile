"""Toggle the DSL-X1852E 'Telnet / LAN' ACL rule through the web UI.

The telnet daemon always runs, but an ACL rule filters port 23 on the LAN side. The
romfile calls that rule ``Entry2`` (Application=Telnet, Interface=LAN); the web UI
calls the same thing rule index 2, and flipping it there is the only way to open the
port without already having a shell. This logs in, posts the ACL form, and reports.
"""
from __future__ import annotations

import hashlib
import http.cookiejar
import re
import urllib.parse
import urllib.request

from . import DeviceError

TELNET_RULE_INDEX = "2"


def parse_rules(html: str) -> list[dict]:
    """Extract the ACL rule table from the Acl.asp JavaScript array."""
    rules = []
    for m in re.finditer(r'\["([^"]*)",\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]*)"\]', html):
        act, start, end, app, iface = m.groups()
        rules.append({"activate": act, "src_begin": start, "src_end": end,
                      "application": app, "interface": iface})
    return rules


class Router:
    def __init__(self, host: str, user: str, passwd: str, timeout: float = 25):
        self.base = f"http://{host}"
        self.user, self.passwd, self.timeout = user, passwd, timeout
        self.op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.op.addheaders = [("User-Agent", "Mozilla/5.0")]

    def login(self) -> None:
        md5 = hashlib.md5(self.passwd.encode()).hexdigest()
        url = f"{self.base}/cgi-bin/Login.asp?User={self.user}&Pwd={md5}"
        body = self.op.open(url, timeout=self.timeout).read().strip()
        if body != b"1":
            raise DeviceError(f"login failed: device answered {body!r}")

    def acl_page(self) -> str:
        return self.op.open(self.base + "/cgi-bin/New_GUI/Acl.asp",
                            timeout=self.timeout).read().decode("latin-1", "replace")

    def session_key(self) -> str:
        """The ACL form posts a per-session token; a request without it is ignored."""
        raw = self.op.open(self.base + "/cgi-bin/get/New_GUI/get_sessionKey.asp",
                           timeout=self.timeout).read().decode("latin-1", "replace")
        digits = re.sub(r"\D", "", raw)
        if not digits:
            raise DeviceError(f"could not read sessionKey (got {raw[:80]!r})")
        return digits

    def post_acl(self, rule_active: str) -> int:
        form = {
            "sessionKey": self.session_key(),
            "buttonType": "",
            "ACLActionFlag": "0",
            "ActivateRDOValue": "Yes",
            "RuleIndexSEL": TELNET_RULE_INDEX,
            "RuleActiveRDOValue": rule_active,
            "ScrIPaddrBeginTXT": "0.0.0.0",
            "ScrIPaddrEndTXT": "0.0.0.0",
            "ApplicationSEL": "Telnet",
            "InterfaceSEL": "LAN",
            "port": "",
        }
        data = urllib.parse.urlencode(form).encode()
        req = urllib.request.Request(self.base + "/cgi-bin/New_GUI/Acl.asp", data=data)
        with self.op.open(req, timeout=self.timeout) as resp:
            return resp.status
