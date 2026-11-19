#!/usr/bin/env python3
"""Toggle the DSL-X1852E 'Telnet / LAN' ACL rule through the web UI.

The telnet daemon always runs, but an ACL rule filters port 23 on the LAN side.
The romfile calls that rule Entry2 (Application=Telnet, Interface=LAN); the web
UI calls the same thing rule index 2 and it is the only way to flip it without a
shell (chicken and egg). This script logs in, posts the ACL form, and saves.

    python acl_toggle.py show          # print the four ACL rules
    python acl_toggle.py on            # enable Telnet/LAN  (opens port 23)
    python acl_toggle.py off           # restore Activate=No

Credentials come from --user/--passwd, the X1852E_WEB_USER / X1852E_WEB_PASS
environment variables, or secrets.local.env next to this repo (gitignored).
Nothing secret is stored in the source.
"""
import argparse
import hashlib
import http.cookiejar
import os
import re
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from router_secrets import get  # noqa: E402

DEFAULT_HOST = "192.168.1.1"
TELNET_RULE_INDEX = "2"


class Router(object):
    def __init__(self, host, user, passwd, timeout=25):
        self.base = "http://%s" % host
        self.user, self.passwd, self.timeout = user, passwd, timeout
        self.op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.op.addheaders = [("User-Agent", "Mozilla/5.0")]

    def login(self):
        md5 = hashlib.md5(self.passwd.encode()).hexdigest()
        url = "%s/cgi-bin/Login.asp?User=%s&Pwd=%s" % (self.base, self.user, md5)
        body = self.op.open(url, timeout=self.timeout).read().strip()
        if body != b"1":
            raise SystemExit("login failed: device answered %r" % body)

    def acl_page(self):
        return self.op.open(self.base + "/cgi-bin/New_GUI/Acl.asp",
                            timeout=self.timeout).read().decode("latin-1", "replace")

    def session_key(self):
        """The ACL page posts a per-session token; a request without it is ignored."""
        raw = self.op.open(self.base + "/cgi-bin/get/New_GUI/get_sessionKey.asp",
                           timeout=self.timeout).read().decode("latin-1", "replace")
        digits = re.sub(r"\D", "", raw)
        if not digits:
            raise SystemExit("could not read sessionKey (got %r)" % raw[:80])
        return digits

    def post_acl(self, rule_active):
        form = {
            "sessionKey": self.session_key(),
            "buttonType": "",
            "ACLActionFlag": "0",          # add/update a rule
            "ActivateRDOValue": "Yes",     # ACL_Common.Activate stays on
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


def parse_rules(html):
    rules = []
    for m in re.finditer(r'\["([^"]*)",\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]*)"\]', html):
        act, start, end, app, iface = m.groups()
        rules.append({"activate": act, "src_begin": start, "src_end": end,
                      "application": app, "interface": iface})
    return rules


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("action", choices=["show", "on", "off"])
    ap.add_argument("--host", default=None)
    ap.add_argument("--user", default=None)
    ap.add_argument("--passwd", default=None)
    args = ap.parse_args(argv)

    r = Router(get("X1852E_HOST", args.host, DEFAULT_HOST),
               get("X1852E_WEB_USER", args.user, "root"),
               get("X1852E_WEB_PASS", args.passwd, required=True))
    r.login()

    if args.action in ("on", "off"):
        status = r.post_acl("Yes" if args.action == "on" else "No")
        print("posted ACL update (http %s): Telnet/LAN -> %s" %
              (status, "Yes" if args.action == "on" else "No"))

    rules = parse_rules(r.acl_page())
    if not rules:
        print("could not parse the ACL rule table", file=sys.stderr)
        return 2
    for i, rule in enumerate(rules):
        mark = "  <-- telnet" if (rule["application"] == "Telnet" and rule["interface"] == "LAN") else ""
        print("  [%d] active=%-3s %-6s %-3s %s-%s%s" % (
            i, rule["activate"], rule["application"], rule["interface"],
            rule["src_begin"], rule["src_end"], mark))
    return 0


if __name__ == "__main__":
    sys.exit(main())
