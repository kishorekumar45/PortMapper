import json

from portmapper.models import (
    DriftFinding,
    DriftStatus,
    Host,
    MacStatus,
    Protocol,
    Severity,
    TriageFinding,
)
from portmapper.reporter import Reporter


def _triage(
    severity: Severity,
    host_label: str,
    port_number: int | None = None,
    protocol: Protocol | None = None,
) -> TriageFinding:
    host = Host(mac="AA:BB:CC:00:00:00", mac_status=MacStatus.KNOWN, hostname=host_label)
    status = DriftStatus.DRIFT_DETECTED if port_number is not None else DriftStatus.OK
    finding = DriftFinding(status=status, host=host, port_number=port_number, protocol=protocol)
    return TriageFinding(finding=finding, severity=severity, rationale=f"{host_label} rationale")


def test_markdown_report_sorts_findings_most_severe_first():
    low = _triage(Severity.LOW, "low-host")
    critical = _triage(Severity.CRITICAL, "critical-host")
    medium = _triage(Severity.MEDIUM, "medium-host")

    report = Reporter().to_markdown([low, critical, medium])

    assert report.index("critical-host") < report.index("medium-host") < report.index("low-host")


def test_markdown_report_includes_severity_label_and_rationale():
    finding = _triage(Severity.CRITICAL, "nas", port_number=23, protocol=Protocol.TCP)

    report = Reporter().to_markdown([finding])

    assert "[CRITICAL]" in report
    assert "nas" in report
    assert "23/tcp" in report
    assert "nas rationale" in report


def test_json_report_is_valid_json_sorted_by_severity():
    low = _triage(Severity.LOW, "low-host")
    critical = _triage(Severity.CRITICAL, "critical-host")

    report = Reporter().to_json([low, critical])
    parsed = json.loads(report)

    assert [entry["host"]["hostname"] for entry in parsed] == ["critical-host", "low-host"]


def test_json_report_includes_expected_fields():
    finding = _triage(Severity.HIGH, "printer", port_number=445, protocol=Protocol.TCP)

    report = Reporter().to_json([finding])
    [entry] = json.loads(report)

    assert entry["severity"] == "high"
    assert entry["status"] == "drift_detected"
    assert entry["port_number"] == 445
    assert entry["protocol"] == "tcp"
    assert entry["service_name"] is None
    assert entry["description"] == ""
    assert entry["rationale"] == "printer rationale"
    assert entry["host"]["hostname"] == "printer"
    assert entry["host"]["mac"] == "AA:BB:CC:00:00:00"
