import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from portmapper.cli import app
from portmapper.scanner import NmapNotFoundError

FIXTURES_DIR = Path(__file__).parent / "fixtures"
POLICY_PATH = FIXTURES_DIR / "sample_policy.yaml"
XML_PATH = FIXTURES_DIR / "sample_nmap_subnet.xml"

runner = CliRunner()


def test_scan_command_prints_markdown_report_by_default(scan_hosts):
    with patch("portmapper.cli.Scanner.scan", return_value=scan_hosts):
        result = runner.invoke(app, ["scan", "192.168.1.0/24", "--policy", str(POLICY_PATH)])

    assert result.exit_code == 0
    assert "# PortMapper Triage Report" in result.output


def test_scan_command_supports_json_format(scan_hosts):
    with patch("portmapper.cli.Scanner.scan", return_value=scan_hosts):
        result = runner.invoke(
            app,
            ["scan", "192.168.1.0/24", "--policy", str(POLICY_PATH), "--format", "json"],
        )

    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert isinstance(parsed, list)
    assert len(parsed) > 0


def test_audit_command_reads_xml_and_policy_and_prints_report():
    result = runner.invoke(app, ["audit", "--xml", str(XML_PATH), "--policy", str(POLICY_PATH)])

    assert result.exit_code == 0
    assert "# PortMapper Triage Report" in result.output


def test_audit_command_supports_json_format():
    result = runner.invoke(
        app,
        ["audit", "--xml", str(XML_PATH), "--policy", str(POLICY_PATH), "--format", "json"],
    )

    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert isinstance(parsed, list)
    assert len(parsed) > 0


def test_scan_command_missing_policy_file_returns_nonzero_exit_with_message(tmp_path):
    missing_policy = tmp_path / "does-not-exist.yaml"

    result = runner.invoke(app, ["scan", "192.168.1.0/24", "--policy", str(missing_policy)])

    assert result.exit_code == 2
    assert isinstance(result.exception, SystemExit)
    assert "Policy file not found" in result.output
    assert "Traceback" not in result.output


def test_audit_command_invalid_xml_returns_nonzero_exit_with_message(tmp_path):
    bad_xml = tmp_path / "bad.xml"
    bad_xml.write_text("this is not xml <<<")

    result = runner.invoke(app, ["audit", "--xml", str(bad_xml), "--policy", str(POLICY_PATH)])

    assert result.exit_code == 2
    assert isinstance(result.exception, SystemExit)
    assert "Failed to parse" in result.output
    assert "Traceback" not in result.output


def test_scan_command_missing_nmap_binary_returns_nonzero_exit_with_message():
    with patch(
        "portmapper.cli.Scanner.scan",
        side_effect=NmapNotFoundError("nmap binary not found: nmap"),
    ):
        result = runner.invoke(app, ["scan", "192.168.1.0/24", "--policy", str(POLICY_PATH)])

    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)
    assert "nmap binary not found" in result.output
    assert "Traceback" not in result.output
