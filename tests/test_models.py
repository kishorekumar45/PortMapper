from datetime import datetime

from portmapper.models import (
    DriftFinding,
    DriftStatus,
    Host,
    MacStatus,
    PolicyPort,
    PolicyRule,
    Port,
    PortState,
    Protocol,
    Service,
    Severity,
    TriageFinding,
)


def test_protocol_and_portstate_enums_have_expected_values():
    assert Protocol.TCP.value == "tcp"
    assert Protocol.UDP.value == "udp"
    assert PortState.OPEN.value == "open"
    assert PortState.CLOSED.value == "closed"
    assert PortState.FILTERED.value == "filtered"


def test_service_dataclass_holds_fields_with_defaults():
    service = Service(name="ssh")
    assert service.name == "ssh"
    assert service.product is None
    assert service.version is None
    assert service.banner is None

    full = Service(name="ssh", product="OpenSSH", version="9.6", banner="SSH-2.0-OpenSSH_9.6")
    assert full.product == "OpenSSH"
    assert full.version == "9.6"
    assert full.banner == "SSH-2.0-OpenSSH_9.6"


def test_port_dataclass_holds_fields_with_defaults():
    port = Port(number=22, protocol=Protocol.TCP, state=PortState.OPEN)
    assert port.number == 22
    assert port.protocol is Protocol.TCP
    assert port.state is PortState.OPEN
    assert port.service is None

    with_service = Port(
        number=22,
        protocol=Protocol.TCP,
        state=PortState.OPEN,
        service=Service(name="ssh"),
    )
    assert with_service.service.name == "ssh"


def test_mac_status_enum_has_known_randomized_unknown():
    assert MacStatus.KNOWN.value == "known"
    assert MacStatus.RANDOMIZED.value == "randomized"
    assert MacStatus.UNKNOWN.value == "unknown"


def test_host_dataclass_defaults_and_identity_key_for_known_mac():
    host = Host(mac="AA:BB:CC:00:11:22", mac_status=MacStatus.KNOWN)
    assert host.ip_addresses == []
    assert host.hostname is None
    assert host.ports == []
    assert host.first_seen is None
    assert host.last_seen is None
    assert host.identity_key == "AA:BB:CC:00:11:22"

    full = Host(
        mac="AA:BB:CC:00:11:22",
        mac_status=MacStatus.KNOWN,
        ip_addresses=["192.168.1.10"],
        hostname="nas.lan",
        ports=[Port(number=22, protocol=Protocol.TCP, state=PortState.OPEN)],
        first_seen=datetime(2026, 8, 1, 9, 0, 0),
        last_seen=datetime(2026, 8, 17, 9, 0, 0),
    )
    assert full.ip_addresses == ["192.168.1.10"]
    assert full.hostname == "nas.lan"
    assert len(full.ports) == 1


def test_host_identity_key_falls_back_for_unknown_or_randomized_mac():
    randomized = Host(mac="DE:AD:BE:EF:00:01", mac_status=MacStatus.RANDOMIZED)
    assert randomized.identity_key == "unresolved:randomized"

    unknown = Host(mac=None, mac_status=MacStatus.UNKNOWN)
    assert unknown.identity_key == "unresolved:unknown"


def test_policy_port_dataclass_is_hashable_and_comparable():
    a = PolicyPort(number=22, protocol=Protocol.TCP)
    b = PolicyPort(number=22, protocol=Protocol.TCP)
    c = PolicyPort(number=23, protocol=Protocol.TCP)

    assert a == b
    assert a != c
    assert len({a, b, c}) == 2


def test_policy_rule_dataclass_holds_fields_with_defaults():
    rule = PolicyRule(host_label="nas")
    assert rule.mac is None
    assert rule.hostname is None
    assert rule.allowed_ports == []
    assert rule.required_ports == []

    full = PolicyRule(
        host_label="nas",
        mac="AA:BB:CC:00:11:22",
        hostname="nas.lan",
        allowed_ports=[PolicyPort(number=22, protocol=Protocol.TCP)],
        required_ports=[PolicyPort(number=22, protocol=Protocol.TCP)],
    )
    assert full.mac == "AA:BB:CC:00:11:22"
    assert full.allowed_ports == [PolicyPort(number=22, protocol=Protocol.TCP)]


def test_drift_status_enum_has_expected_values():
    assert DriftStatus.OK.value == "ok"
    assert DriftStatus.DRIFT_DETECTED.value == "drift_detected"
    assert DriftStatus.MISSING_EXPECTED_PORT.value == "missing_expected_port"
    assert DriftStatus.NEW_HOST.value == "new_host"
    assert DriftStatus.UNVERIFIED_IDENTITY.value == "unverified_identity"


def test_drift_finding_dataclass_holds_fields_with_defaults():
    host = Host(mac="AA:BB:CC:00:11:22", mac_status=MacStatus.KNOWN)
    finding = DriftFinding(status=DriftStatus.OK, host=host)
    assert finding.port_number is None
    assert finding.protocol is None
    assert finding.service_name is None
    assert finding.rule is None
    assert finding.description == ""

    rule = PolicyRule(host_label="nas")
    full = DriftFinding(
        status=DriftStatus.DRIFT_DETECTED,
        host=host,
        port_number=23,
        protocol=Protocol.TCP,
        service_name="telnet",
        rule=rule,
        description="unapproved port open",
    )
    assert full.port_number == 23
    assert full.protocol is Protocol.TCP
    assert full.service_name == "telnet"
    assert full.rule is rule
    assert full.description == "unapproved port open"


def test_severity_enum_declares_critical_to_info_in_order():
    assert list(Severity) == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    assert Severity.CRITICAL.value == "critical"
    assert Severity.INFO.value == "info"


def test_triage_finding_dataclass_holds_fields():
    host = Host(mac="AA:BB:CC:00:11:22", mac_status=MacStatus.KNOWN)
    finding = DriftFinding(status=DriftStatus.OK, host=host)

    triage = TriageFinding(finding=finding, severity=Severity.INFO, rationale="compliant")

    assert triage.finding is finding
    assert triage.severity is Severity.INFO
    assert triage.rationale == "compliant"
