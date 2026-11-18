"""Redaction and the masking shared with `romfile report`.

The failure mode that matters is failing open - a password left in a file someone
then posts - so every sensitive class is asserted to disappear.
"""
import json

import pytest

from dlink_romfile import redact
from dlink_romfile.cli import main

SAMPLE = (
    "<ROMFILE> <Wan> <Entry username=\"me@isp.example\" password=\"s3cret\" "
    "IP=\"203.0.113.9\"/> </Wan> "
    "<WLan><Entry SSID=\"MyHomeNet\" WPAPSK=\"wifi-pass\" MAC=\"aa:bb:cc:dd:ee:ff\"/>"
    "</WLan> <SysInfo><Entry SerialNum=\"TK37133001784\"/></SysInfo> </ROMFILE>"
)

IDENTIFIERS = ("me@isp.example", "MyHomeNet", "aa:bb:cc:dd:ee:ff", "203.0.113.9",
               "TK37133001784")


def test_redact_text_masks_every_class():
    out, counts = redact.redact_text(SAMPLE)
    for value in IDENTIFIERS + ("s3cret", "wifi-pass"):
        assert value not in out
    assert counts["password"] == 1
    assert counts["SSID"] == 1


def test_redact_text_keeps_structure_and_harmless_values():
    out, _ = redact.redact_text(SAMPLE)
    assert out.startswith("<ROMFILE> <Wan>")
    assert out.count('"REDACTED"') == 7
    keep, _ = redact.redact_text(
        '<ROMFILE><X IP="0.0.0.0" Server="ntp1.dlink.com" Empty="" '
        'AL-MAC="00:00:00:00:00:00"/></ROMFILE>')
    assert 'IP="0.0.0.0"' in keep and "ntp1.dlink.com" in keep
    assert "00:00:00:00:00:00" in keep


def test_mac_is_detected_by_value_not_name():
    out, counts = redact.redact_text('<ROMFILE><X AL-MAC="0c:0e:76:b3:38:56"/></ROMFILE>')
    assert "0c:0e:76" not in out and counts["AL-MAC"] == 1


def test_keep_flags_relax_but_never_credentials():
    out, _ = redact.redact_text(SAMPLE, keep_ssid=True, keep_macs=True, keep_ips=True)
    assert "MyHomeNet" in out
    assert "aa:bb:cc:dd:ee:ff" in out
    assert "203.0.113.9" in out
    assert "s3cret" not in out


def test_redact_command(tmp_path, capsys):
    src = tmp_path / "plain.xml"
    src.write_bytes(SAMPLE.encode("latin-1"))
    dest = tmp_path / "share.xml"
    assert main(["redact", str(src), "-o", str(dest)]) == 0
    cap = capsys.readouterr()
    assert cap.out.strip() == str(dest)
    assert "masked" in cap.err
    assert "s3cret" not in dest.read_bytes().decode("latin-1")


def test_redact_rejects_non_config(tmp_path, capsys):
    bad = tmp_path / "page.xml"
    bad.write_text("<html></html>", encoding="latin-1")
    assert main(["redact", str(bad)]) == 2
    assert "not a plaintext config" in capsys.readouterr().err


def test_report_masks_identifiers_by_default(tmp_path, capsys):
    src = tmp_path / "plain.xml"
    src.write_bytes(SAMPLE.encode("latin-1"))
    assert main(["report", str(src)]) == 0
    out = capsys.readouterr().out
    for value in IDENTIFIERS:
        assert value not in out


def test_report_json_masks_identifiers(tmp_path, capsys):
    src = tmp_path / "plain.xml"
    src.write_bytes(SAMPLE.encode("latin-1"))
    assert main(["report", str(src), "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    blob = json.dumps(doc)
    for value in IDENTIFIERS + ("s3cret",):
        assert value not in blob


@pytest.mark.parametrize("argv", (["report", "--show-secrets"],))
def test_report_show_secrets_is_opt_in(tmp_path, capsys, argv):
    src = tmp_path / "plain.xml"
    src.write_bytes(SAMPLE.encode("latin-1"))
    assert main(argv + [str(src)]) == 0
    assert "MyHomeNet" in capsys.readouterr().out


def test_encrypt_refuses_binary_input(tmp_path, capsys):
    blob = tmp_path / "not-a-config.bin"
    blob.write_bytes(bytes(range(256)) * 4)
    assert main(["encrypt", str(blob), "-o", str(tmp_path / "x.cfg")]) == 2
    assert "does not look like a config" in capsys.readouterr().err
