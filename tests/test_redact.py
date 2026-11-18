"""Tests for tools/redact_config.py, which lives outside the installed package.

Redaction failing open (leaving a password in a file someone then posts) is the one
failure mode that matters here, so the tool is loaded by path and exercised directly.
"""
import importlib.util
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[1] / "tools" / "redact_config.py"

SAMPLE = (
    "<ROMFILE> <Wan> <Entry username=\"me@isp.example\" password=\"s3cret\" "
    "IP=\"203.0.113.9\"/> </Wan> "
    "<WLan><Entry SSID=\"MyHomeNet\" WPAPSK=\"wifi-pass\" MAC=\"aa:bb:cc:dd:ee:ff\"/>"
    "</WLan> </ROMFILE>"
)


@pytest.fixture(scope="module")
def redact():
    spec = importlib.util.spec_from_file_location("redact_config", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_masks_secrets_and_identifiers(redact):
    out, counts = redact.redact(SAMPLE)
    for value in ("s3cret", "wifi-pass", "me@isp.example", "MyHomeNet",
                  "aa:bb:cc:dd:ee:ff", "203.0.113.9"):
        assert value not in out
    assert counts["password"] == 1
    assert counts["SSID"] == 1


def test_keeps_structure_and_harmless_values(redact):
    out, _ = redact.redact(SAMPLE)
    assert out.startswith("<ROMFILE> <Wan>")
    assert out.count('"REDACTED"') == 6
    # placeholder addresses and vendor constants are not identifying
    keep, _ = redact.redact('<ROMFILE><X IP="0.0.0.0" Server="ntp1.dlink.com"/></ROMFILE>')
    assert 'IP="0.0.0.0"' in keep and "ntp1.dlink.com" in keep


def test_keep_flags_relax_but_never_credentials(redact):
    out, _ = redact.redact(SAMPLE, keep_ssid=True, keep_macs=True, keep_ips=True)
    assert "MyHomeNet" in out
    assert "aa:bb:cc:dd:ee:ff" in out
    assert "203.0.113.9" in out
    assert "s3cret" not in out


def test_rejects_non_config_with_exit_2(redact, tmp_path, capsys):
    bad = tmp_path / "page.xml"
    bad.write_text("<html></html>", encoding="latin-1")
    assert redact.main([str(bad)]) == 2
    assert "does not look like" in capsys.readouterr().err
