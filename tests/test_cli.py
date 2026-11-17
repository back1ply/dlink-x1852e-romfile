"""Behavioural tests: one per subcommand, asserting exit code + stdout + stderr.

The fixture is a *fabricated* config packed with the real key -- no device secrets.
Requires openssl on PATH (same runtime dependency as the tool).
"""
import json
import shutil

import pytest

from dlink_romfile import core
from dlink_romfile.cli import COMMANDS, main

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not on PATH")

SAMPLE = (
    b"<ROMFILE> <Lan> "
    b'<Entry IP="192.168.1.1" netmask="255.255.255.0" web_passwd="hunter2xyz"/> '
    b"</Lan> </ROMFILE>"
)


@pytest.fixture()
def cfg(tmp_path):
    p = tmp_path / "sample.cfg"
    p.write_bytes(core.pack_romfile(SAMPLE))
    return p


def test_dispatch_map_resolves():
    # LAY-06: every advertised subcommand maps to a callable
    for name, fn in COMMANDS.items():
        assert callable(fn), name


def test_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--help"])
    assert e.value.code == 0
    out = capsys.readouterr()
    assert "romfile" in out.out and out.err == ""


def test_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert capsys.readouterr().out.strip().startswith("romfile ")


def test_usage_error_exit_2(capsys):
    with pytest.raises(SystemExit) as e:
        main(["definitely-not-a-command"])
    assert e.value.code == 2
    out = capsys.readouterr()
    assert out.out == ""  # CLI-08: nothing on stdout
    assert out.err  # message on stderr


def test_info_json(cfg, capsys):
    rc = main(["info", str(cfg), "--json"])
    assert rc == 0
    out = capsys.readouterr()
    doc = json.loads(out.out)  # AGT-01: stdout is exactly one JSON document
    assert doc["crc32_ciphertext"] == doc["magic_hex"]


def test_solve_roundtrips(cfg, tmp_path, capsys):
    out_xml = tmp_path / "out.xml"
    rc = main(["solve", str(cfg), "-o", str(out_xml)])
    assert rc == 0
    assert out_xml.read_bytes() == SAMPLE
    # data (the path) on stdout; the key/header notes on stderr
    cap = capsys.readouterr()
    assert cap.out.strip() == str(out_xml)
    assert "AES-128-CBC" in cap.err


def test_encrypt_then_solve_roundtrips(cfg, tmp_path):
    xml = tmp_path / "plain.xml"
    xml.write_bytes(SAMPLE)
    packed = tmp_path / "repacked.cfg"
    assert main(["encrypt", str(xml), "-o", str(packed)]) == 0
    back = tmp_path / "back.xml"
    assert main(["solve", str(packed), "-o", str(back)]) == 0
    assert back.read_bytes() == SAMPLE


def test_encrypt_verify_byte_identical(cfg, tmp_path):
    # full block-aligned buffer -> re-encrypt must reproduce the exact container
    full, h = core.aes_cbc_decrypt(cfg.read_bytes()[core.HEADER:], core.EG_KEY, core.EG_IV), core.read_header(cfg.read_bytes())
    buf = tmp_path / "full.bin"
    buf.write_bytes(full)
    rc = main(["encrypt", str(buf), "--length", str(h["plaintext_len"]),
               "-o", str(tmp_path / "re.cfg"), "--verify-against", str(cfg)])
    assert rc == 0


def test_report_masks_secret(tmp_path, capsys):
    xml = tmp_path / "plain.xml"
    xml.write_bytes(SAMPLE)
    assert main(["report", str(xml)]) == 0
    out = capsys.readouterr().out
    assert "hunter2xyz" not in out  # CFG-04: secret masked by default
    assert "hu" in out  # masked form present


def test_report_show_secrets(tmp_path, capsys):
    xml = tmp_path / "plain.xml"
    xml.write_bytes(SAMPLE)
    assert main(["report", str(xml), "--show-secrets"]) == 0
    assert "hunter2xyz" in capsys.readouterr().out


def test_missing_file_exit_1(tmp_path, capsys):
    rc = main(["info", str(tmp_path / "nope.cfg")])
    assert rc == 1
    assert capsys.readouterr().err  # one-line error, no traceback
