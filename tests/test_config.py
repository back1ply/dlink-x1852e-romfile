"""Tests for get/set/diff: the config-interactivity layer.

Fabricated configs only -- no device secrets. The set-path tests assert the
byte-exactness that the whole project rests on: a `set` changes only the bytes of
the one value it targets.
"""
import json
import shutil

import pytest

from dlink_romfile import config, core
from dlink_romfile.cli import main

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not on PATH")

SAMPLE = (
    "<ROMFILE> "
    "<Lan> "
    '<Entry0 IP="192.168.1.1" netmask="255.255.255.0" /> '
    "</Lan> "
    "<ACL> "
    '<Entry1 Application="Ping" Interface="WAN" Activate="Yes" /> '
    '<Entry2 Application="Telnet" Interface="LAN" Activate="No" /> '
    "</ACL> "
    "<Account> "
    '<Entry0 username="root" web_passwd="hunter2xyz" /> '
    "</Account> "
    "<Dhcpd MaxStaticNum=\"8\"> "
    '<Common lease="86400" /> '
    "</Dhcpd> "
    "</ROMFILE>"
)


# --- get -------------------------------------------------------------------

def test_get_single_value():
    assert config.get(SAMPLE, "Lan/Entry0/IP") == "192.168.1.1"
    assert config.get(SAMPLE, "ACL/Entry2/Activate") == "No"


def test_get_section_tag_attr():
    assert config.get(SAMPLE, "Dhcpd/MaxStaticNum") == "8"


def test_get_element_dict():
    d = config.get(SAMPLE, "Account/Entry0")
    assert d["username"] == "root" and d["web_passwd"] == "hunter2xyz"


def test_get_missing_attr_lists_available():
    with pytest.raises(config.PathError) as e:
        config.get(SAMPLE, "Lan/Entry0/Nope")
    assert "IP" in str(e.value) and "netmask" in str(e.value)


# --- set (byte-exactness) --------------------------------------------------

def test_set_changes_only_target_bytes():
    new, old, label = config.set_value(SAMPLE, "ACL/Entry2/Activate", "Yes")
    assert old == "No" and label == "ACL/Entry2"
    assert config.get(new, "ACL/Entry2/Activate") == "Yes"
    # byte-exactness: restoring just the target value reproduces the original exactly,
    # which is only possible if nothing else changed.
    restored, _, _ = config.set_value(new, "ACL/Entry2/Activate", "No")
    assert restored == SAMPLE
    # the sibling Entry1 (which also has Activate=) was untouched
    assert config.get(new, "ACL/Entry1/Activate") == "Yes"


def test_set_longer_value_preserves_rest():
    new, old, _ = config.set_value(SAMPLE, "Lan/Entry0/IP", "10.0.0.1")
    assert old == "192.168.1.1"
    assert config.get(new, "Lan/Entry0/IP") == "10.0.0.1"
    assert config.get(new, "Lan/Entry0/netmask") == "255.255.255.0"  # neighbour intact


def test_set_rejects_quote():
    with pytest.raises(config.PathError):
        config.set_value(SAMPLE, "Lan/Entry0/IP", 'a"b')


def test_set_cli_roundtrips_through_encrypt(tmp_path):
    # the full human/agent loop: solve -> set -> encrypt -> solve -> read back
    xml = tmp_path / "c.xml"
    xml.write_bytes(SAMPLE.encode("latin-1"))
    assert main(["set", str(xml), "ACL/Entry2/Activate", "Yes"]) == 0
    packed = tmp_path / "c.cfg"
    assert main(["encrypt", str(xml), "-o", str(packed)]) == 0
    back = tmp_path / "back.xml"
    assert main(["solve", str(packed), "-o", str(back)]) == 0
    assert config.get(back.read_bytes().decode("latin-1"), "ACL/Entry2/Activate") == "Yes"


# --- diff ------------------------------------------------------------------

def test_diff_detects_change():
    b, _, _ = config.set_value(SAMPLE, "ACL/Entry2/Activate", "Yes")
    d = config.diff(SAMPLE, b)
    assert d["ACL"]["changed"][0]["element"] == "Entry2"
    assert d["ACL"]["changed"][0]["attrs"]["Activate"] == ["No", "Yes"]


def test_diff_identical_is_empty():
    assert config.diff(SAMPLE, SAMPLE) == {}


def test_diff_masks_secret_by_default(tmp_path, capsys):
    a = tmp_path / "a.xml"; a.write_bytes(SAMPLE.encode("latin-1"))
    b_text, _, _ = config.set_value(SAMPLE, "Account/Entry0/web_passwd", "newsecret9")
    b = tmp_path / "b.xml"; b.write_bytes(b_text.encode("latin-1"))
    assert main(["diff", str(a), str(b)]) == 0
    out = capsys.readouterr().out
    assert "hunter2xyz" not in out and "newsecret9" not in out
    assert "hidden" in out


def test_diff_exit_code(tmp_path):
    a = tmp_path / "a.xml"; a.write_bytes(SAMPLE.encode("latin-1"))
    b_text, _, _ = config.set_value(SAMPLE, "Lan/Entry0/IP", "10.0.0.1")
    b = tmp_path / "b.xml"; b.write_bytes(b_text.encode("latin-1"))
    assert main(["diff", str(a), str(b), "--exit-code"]) == 1
    assert main(["diff", str(a), str(a), "--exit-code"]) == 0


def test_diff_json_roundtrips(tmp_path, capsys):
    a = tmp_path / "a.xml"; a.write_bytes(SAMPLE.encode("latin-1"))
    b_text, _, _ = config.set_value(SAMPLE, "Lan/Entry0/IP", "10.0.0.1")
    b = tmp_path / "b.xml"; b.write_bytes(b_text.encode("latin-1"))
    assert main(["diff", str(a), str(b), "--json", "--show-secrets"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["Lan"]["changed"][0]["attrs"]["IP"] == ["192.168.1.1", "10.0.0.1"]


def test_get_requires_plaintext(tmp_path, capsys):
    not_cfg = tmp_path / "x.cfg"
    not_cfg.write_bytes(core.pack_romfile(SAMPLE.encode("latin-1")))  # encrypted container
    rc = main(["get", str(not_cfg), "Lan/Entry0/IP"])
    assert rc == 2
    assert "solve" in capsys.readouterr().err
