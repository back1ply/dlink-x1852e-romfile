"""Tests for the live-device subpackage.

No real router: the pure helpers (secrets, response classification, ACL-table
parsing, telnet IAC handling) are tested directly, the TFTP receiver over the
loopback interface, and the CLI credential-error paths without opening a socket.
"""
import socket
import struct
import threading
import time

import pytest

from dlink_romfile import cli
from dlink_romfile.device import DeviceError, acl, live, secrets, telnet
from dlink_romfile.device import receivers


# --- secrets precedence ----------------------------------------------------

def test_secrets_flag_beats_everything(monkeypatch):
    monkeypatch.setenv("X1852E_HOST", "from-env")
    assert secrets.get("X1852E_HOST", "from-flag", "default") == "from-flag"


def test_secrets_env_beats_file_and_default(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secrets.local.env").write_text("X1852E_HOST=from-file\n")
    monkeypatch.setenv("X1852E_HOST", "from-env")
    assert secrets.get("X1852E_HOST") == "from-env"


def test_secrets_file_used_when_no_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("X1852E_WEB_PASS", raising=False)
    # quotes are stripped; a full-line # comment is ignored; inline # is NOT special
    # (passwords may contain #), so it stays part of the value.
    (tmp_path / "secrets.local.env").write_text(
        '# creds\nX1852E_WEB_PASS="s3cr3t"\n')
    assert secrets.get("X1852E_WEB_PASS") == "s3cr3t"


def test_secrets_required_raises(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("X1852E_WEB_PASS", raising=False)
    with pytest.raises(DeviceError):
        secrets.get("X1852E_WEB_PASS", required=True)


def test_secrets_custom_path(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    alt = tmp_path / "creds.env"
    alt.write_text("X1852E_HOST=1.2.3.4\n")
    monkeypatch.setenv("X1852E_SECRETS", str(alt))
    assert secrets.get("X1852E_HOST") == "1.2.3.4"


# --- response classification ----------------------------------------------

def test_classify_plaintext():
    assert live.classify(b"  <ROMFILE> <Lan/></ROMFILE>") == "plaintext"


def test_classify_encrypted():
    assert live.classify(live.MAGIC + b"\x00\x01\x02\x03rest") == "encrypted"


def test_classify_unknown():
    assert live.classify(b"<html>404</html>") == "unknown"


# --- ACL table parsing -----------------------------------------------------

def test_parse_rules_extracts_telnet_row():
    html = '''var acl = [
        ["Yes","0.0.0.0","0.0.0.0","Ping","WAN"],
        ["No","0.0.0.0","0.0.0.0","Telnet","LAN"]
    ];'''
    rules = acl.parse_rules(html)
    assert len(rules) == 2
    telnet_rule = rules[1]
    assert telnet_rule["application"] == "Telnet" and telnet_rule["interface"] == "LAN"
    assert telnet_rule["activate"] == "No"


# --- telnet IAC handling ---------------------------------------------------

def test_negotiate_strips_iac_and_keeps_payload():
    IAC, DO, WILL = 255, 253, 251
    data = bytes([IAC, DO, 1]) + b"hello" + bytes([IAC, WILL, 3]) + b"!"
    out = bytearray()
    telnet.negotiate(None, data, out)  # sock=None: we only check extracted bytes
    assert bytes(out) == b"hello!"


# --- TFTP receiver over loopback ------------------------------------------

def _free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_tftp_receiver_accepts_one_upload(tmp_path):
    port = _free_udp_port()
    payload = b"A" * 300  # < 512 -> single DATA block ends transfer

    def client():
        time.sleep(0.3)
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        c.settimeout(5)
        c.sendto(struct.pack("!H", 2) + b"dump.bin\0octet\0", ("127.0.0.1", port))
        c.recvfrom(64)  # ACK 0
        c.sendto(struct.pack("!HH", 3, 1) + payload, ("127.0.0.1", port))
        c.recvfrom(64)  # ACK 1
        c.close()

    t = threading.Thread(target=client, daemon=True)
    t.start()
    dest = receivers.tftp_receiver(str(tmp_path), port=port, bind="127.0.0.1",
                                   timeout=5, log=lambda m: None)
    t.join(2)
    assert dest.endswith("dump.bin")
    with open(dest, "rb") as fh:
        assert fh.read() == payload


# --- CLI credential-error paths (no socket opened) -------------------------

def test_cli_telnet_missing_creds_exit_1(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    for var in ("X1852E_TELNET_USER", "X1852E_TELNET_PASS"):
        monkeypatch.delenv(var, raising=False)
    rc = cli.main(["telnet", "id", "--host", "10.255.255.1"])
    assert rc == 1
    assert "X1852E_TELNET_USER" in capsys.readouterr().err


def test_cli_acl_missing_passwd_exit_1(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("X1852E_WEB_PASS", raising=False)
    rc = cli.main(["acl", "show", "--host", "10.255.255.1"])
    assert rc == 1
    assert "X1852E_WEB_PASS" in capsys.readouterr().err
