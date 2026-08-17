from portmapper.models import (
    DriftFinding,
    DriftStatus,
    Host,
    MacStatus,
    Protocol,
    Severity,
)
from portmapper.risk_scorer import RiskScorer, score_port


def _host(mac_status: MacStatus = MacStatus.KNOWN) -> Host:
    return Host(mac="AA:BB:CC:00:11:22", mac_status=mac_status, hostname="test-host")


def test_telnet_port_scored_critical_with_rationale():
    severity, rationale = score_port(23, Protocol.TCP)

    assert severity is Severity.CRITICAL
    assert rationale


def test_rdp_port_scored_critical():
    severity, _ = score_port(3389, Protocol.TCP)

    assert severity is Severity.CRITICAL


def test_smb_port_scored_high():
    severity, _ = score_port(445, Protocol.TCP)

    assert severity is Severity.HIGH


def test_http_port_scored_medium():
    severity, _ = score_port(80, Protocol.TCP)

    assert severity is Severity.MEDIUM


def test_https_port_scored_low():
    severity, _ = score_port(443, Protocol.TCP)

    assert severity is Severity.LOW


def test_unknown_ephemeral_port_scored_info():
    severity, _ = score_port(51413, Protocol.TCP)

    assert severity is Severity.INFO


def test_score_finding_drift_detected_uses_port_risk_table():
    finding = DriftFinding(
        status=DriftStatus.DRIFT_DETECTED,
        host=_host(),
        port_number=23,
        protocol=Protocol.TCP,
        service_name="telnet",
    )

    [triage] = RiskScorer().score([finding])

    assert triage.severity is Severity.CRITICAL
    assert triage.finding is finding


def test_score_finding_ok_status_scored_info():
    finding = DriftFinding(status=DriftStatus.OK, host=_host())

    [triage] = RiskScorer().score([finding])

    assert triage.severity is Severity.INFO


def test_score_finding_missing_expected_port_scored_medium():
    finding = DriftFinding(
        status=DriftStatus.MISSING_EXPECTED_PORT,
        host=_host(),
        port_number=22,
        protocol=Protocol.TCP,
    )

    [triage] = RiskScorer().score([finding])

    assert triage.severity is Severity.MEDIUM


def test_score_finding_new_host_scored_medium():
    finding = DriftFinding(status=DriftStatus.NEW_HOST, host=_host())

    [triage] = RiskScorer().score([finding])

    assert triage.severity is Severity.MEDIUM


def test_score_finding_unverified_identity_scored_medium():
    finding = DriftFinding(
        status=DriftStatus.UNVERIFIED_IDENTITY,
        host=_host(mac_status=MacStatus.RANDOMIZED),
    )

    [triage] = RiskScorer().score([finding])

    assert triage.severity is Severity.MEDIUM
