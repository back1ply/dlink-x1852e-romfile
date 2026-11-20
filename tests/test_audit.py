"""Tests for the effective-state audit layer.

Fabricated configs only -- no device, no network. The point of these tests is the
gating logic: a raw flag that says "on" must resolve to *off* when an ACL or master
switch upstream disables it, and the reason must name the deciding gate.
"""
import json

from dlink_romfile import audit
from dlink_romfile.cli import main


def _cfg(acl_rules: str = "", extra: str = "") -> str:
    return (
        "<ROMFILE> "
        "<Account> "
        '<TelnetEntry Active="Yes" telnet_port="23" /> '
        '<Common Activate="Yes" sshOption="support" /> '
        '<FtpCommon Active="No" ftp_port="21" /> '
        "</Account> "
        "<Samba> "
        '<Entry0 Active="No" username="admin" /> '
        "</Samba> "
        '<DMS> <Entry Enable="No" /> <Basic PortNumber="12345" /> </DMS> '
        '<Dproxy> <Entry Active="Yes" /> </Dproxy> '
        '<Snmpd> <Entry Active="No" /> </Snmpd> '
        "<Upnpd> <Entry Active=\"No\" /> </Upnpd> "
        "<Cwmp> "
        '<Entry Active="No" acsUrl="" Tr069Enable="1" /> '
        "</Cwmp> "
        "<ACL> " + acl_rules + "</ACL> "
        + extra +
        "</ROMFILE>"
    )


def _by_name(results):
    return {r.name: r for r in results}


def test_telnet_on_but_acl_blocks_is_not_reachable():
    acl = '<Entry0 Application="Telnet" Interface="LAN" Activate="No" /> '
    r = _by_name(audit.evaluate_text(_cfg(acl)))["Telnet"]
    assert r.effective is False
    assert r.configured == "Active=Yes"      # raw flag says on...
    assert "ACL Telnet/LAN=No" in r.reason   # ...but the ACL is the reason it's off


def test_telnet_reachable_when_both_flag_and_acl_on():
    acl = '<Entry0 Application="Telnet" Interface="LAN" Activate="Yes" /> '
    r = _by_name(audit.evaluate_text(_cfg(acl)))["Telnet"]
    assert r.effective is True


def test_samba_service_master_off_wins_over_acl_permit():
    acl = '<Entry0 Application="Samba" Interface="LAN" Activate="Yes" /> '
    r = _by_name(audit.evaluate_text(_cfg(acl)))["Samba/SMB"]
    assert r.effective is False
    assert "service off" in r.reason


def test_tr069_inert_when_deactivated_with_empty_acs():
    r = _by_name(audit.evaluate_text(_cfg()))["TR-069"]
    assert r.effective is False
    assert "deactivated" in r.reason.lower()


def test_tr069_reachable_needs_active_and_acs_url():
    extra_cwmp = '<Cwmp> <Entry Active="Yes" acsUrl="http://acs.isp.net" Tr069Enable="1" /> </Cwmp> '
    # replace the default inert Cwmp by appending; last section wins in lenient parse order,
    # so build a config with only the active one.
    cfg = (
        '<ROMFILE> <Account> <TelnetEntry Active="No" /> <Common sshOption="off" /> </Account> '
        '<Samba> <Entry0 Active="No" /> </Samba> <Upnpd> <Entry Active="No" /> </Upnpd> '
        + extra_cwmp + "<ACL> </ACL> </ROMFILE>"
    )
    r = _by_name(audit.evaluate_text(cfg))["TR-069"]
    assert r.effective is True
    assert "acs.isp.net" in r.reason


def test_wan_web_admin_is_flagged_exposed():
    acl = '<Entry0 Application="Web" Interface="WAN" Activate="Yes" /> '
    results = audit.evaluate_text(_cfg(acl))
    web_wan = _by_name(results)["Web (WAN)"]
    assert web_wan.effective is True
    assert web_wan.wan_exposed is True


def test_ftp_and_dlna_off_by_default():
    res = _by_name(audit.evaluate_text(_cfg()))
    assert res["FTP"].effective is False
    assert res["FTP"].configured == "Active=No"
    assert res["DLNA"].effective is False
    assert res["DLNA"].configured == "Enable=No"


def test_dlna_reachable_when_enabled():
    cfg = _cfg().replace('<Entry Enable="No" />', '<Entry Enable="Yes" />')
    assert _by_name(audit.evaluate_text(cfg))["DLNA"].effective is True


def test_dns_gated_by_domain_acl():
    # DNS service on, but the domain ACL blocks it -> not reachable
    acl = '<Entry0 Application="domain" Interface="LAN" Activate="No" /> '
    r = _by_name(audit.evaluate_text(_cfg(acl)))["DNS"]
    assert r.effective is False
    assert "domain/LAN" in r.reason


def test_dns_reachable_when_service_and_acl_on():
    acl = '<Entry0 Application="domain" Interface="LAN" Activate="Yes" /> '
    assert _by_name(audit.evaluate_text(_cfg(acl)))["DNS"].effective is True


def test_snmp_off_by_default():
    assert _by_name(audit.evaluate_text(_cfg()))["SNMP"].effective is False


def test_udp_services_excluded_from_reconcile():
    # TFTP and SNMP are UDP; a TCP probe can't judge them, so reconcile omits them.
    results = audit.evaluate_text(_cfg())
    observed = {"Telnet": False}        # only a TCP surface observed
    rows = {r["surface"] for r in audit.reconcile(results, observed)}
    assert "TFTP" not in rows and "SNMP" not in rows


def test_reconcile_checks_dedicated_wan_port_skips_shared():
    # TR-069 has its own port (7547) -> reconciled; Web (WAN) shares 80 with Web (LAN) -> skipped
    results = audit.evaluate_text(_cfg())
    observed = {"TR-069": True, "Web (WAN)": True, "Web (LAN)": True}
    rows = {r["surface"] for r in audit.reconcile(results, observed)}
    assert "TR-069" in rows
    assert "Web (WAN)" not in rows


def test_ssh_console_is_advisory_only():
    r = _by_name(audit.evaluate_text(_cfg()))["SSH (console)"]
    assert r.advisory is True
    assert r.effective is None


def test_annotate_maps_flag_locations():
    acl = '<Entry0 Application="Telnet" Interface="LAN" Activate="No" /> '
    data, _ = __import__("dlink_romfile.report", fromlist=["parse"]).parse(_cfg(acl))
    notes = audit.annotate(data)
    assert notes[("Account", "TelnetEntry", "Active")].startswith("effective: off")


def test_cli_audit_json_and_exit_code(tmp_path, capsys):
    acl = '<Entry0 Application="Web" Interface="WAN" Activate="Yes" /> '
    cfg = tmp_path / "c.xml"
    cfg.write_text(_cfg(acl))

    rc = main(["audit", str(cfg), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert any(s["surface"] == "Web (WAN)" and s["wan_exposed"] for s in out["surfaces"])

    rc = main(["audit", str(cfg), "--exit-code"])
    capsys.readouterr()
    assert rc == 1   # a WAN-reachable surface exists


def test_cli_audit_needs_file_or_live(capsys):
    rc = main(["audit"])
    assert rc == 2
    assert "needs a config file" in capsys.readouterr().err
