from portmapper.drift_engine import DriftEngine
from portmapper.models import DriftStatus, Host, MacStatus, PolicyRule, Port, PortState, Protocol


def _host(hosts: list[Host], hostname: str) -> Host:
    return next(h for h in hosts if h.hostname == hostname)


def _rule(rules: list[PolicyRule], host_label: str) -> PolicyRule:
    return next(r for r in rules if r.host_label == host_label)


def test_compliant_host_all_ports_allowed_and_required_present_yields_ok(scan_hosts, policy_rules):
    nas = _host(scan_hosts, "nas.lan")
    nas_rule = _rule(policy_rules, "nas")

    findings = DriftEngine().evaluate([nas], [nas_rule])

    assert len(findings) == 1
    assert findings[0].status is DriftStatus.OK
    assert findings[0].host is nas


def test_unapproved_open_port_flagged_as_drift_detected(scan_hosts, policy_rules):
    printer = _host(scan_hosts, "printer.lan")
    printer_rule = _rule(policy_rules, "printer")

    findings = DriftEngine().evaluate([printer], [printer_rule])

    drift = [f for f in findings if f.status is DriftStatus.DRIFT_DETECTED]
    assert len(drift) == 1
    assert drift[0].port_number == 23
    assert drift[0].protocol is Protocol.TCP
    assert drift[0].service_name == "telnet"


def test_missing_required_port_flagged(scan_hosts, policy_rules):
    router = _host(scan_hosts, "router.lan")
    router_rule = _rule(policy_rules, "router")

    findings = DriftEngine().evaluate([router], [router_rule])

    missing = [f for f in findings if f.status is DriftStatus.MISSING_EXPECTED_PORT]
    assert len(missing) == 1
    assert missing[0].port_number == 22
    assert missing[0].protocol is Protocol.TCP


def test_compliant_host_produces_no_drift_or_missing_findings(scan_hosts, policy_rules):
    nas = _host(scan_hosts, "nas.lan")
    nas_rule = _rule(policy_rules, "nas")

    findings = DriftEngine().evaluate([nas], [nas_rule])

    bad_statuses = {DriftStatus.DRIFT_DETECTED, DriftStatus.MISSING_EXPECTED_PORT}
    assert not [f for f in findings if f.status in bad_statuses]


def test_randomized_mac_host_is_flagged_unverified_identity_without_crashing(scan_hosts, policy_rules):
    guest = next(h for h in scan_hosts if h.mac_status is MacStatus.RANDOMIZED)

    findings = DriftEngine().evaluate([guest], policy_rules)

    assert len(findings) == 1
    assert findings[0].status is DriftStatus.UNVERIFIED_IDENTITY
    assert findings[0].port_number is None
    assert findings[0].rule is None


def test_unverified_identity_host_does_not_also_emit_phantom_drift_findings(scan_hosts, policy_rules):
    guest = next(h for h in scan_hosts if h.mac_status is MacStatus.RANDOMIZED)

    findings = DriftEngine().evaluate([guest], policy_rules)

    assert len(findings) == 1
    assert not [f for f in findings if f.status is DriftStatus.DRIFT_DETECTED]


def test_known_mac_host_with_no_policy_entry_is_flagged_new_host(policy_rules):
    unlisted = Host(
        mac="AA:BB:CC:00:99:99",
        mac_status=MacStatus.KNOWN,
        hostname="mystery-device.lan",
        ports=[Port(number=80, protocol=Protocol.TCP, state=PortState.OPEN)],
    )

    findings = DriftEngine().evaluate([unlisted], policy_rules)

    assert len(findings) == 1
    assert findings[0].status is DriftStatus.NEW_HOST
    assert findings[0].status is not DriftStatus.UNVERIFIED_IDENTITY


def test_mac_matching_is_case_insensitive(scan_hosts, policy_rules):
    nas = _host(scan_hosts, "nas.lan")
    nas.mac = nas.mac.lower()
    nas_rule = _rule(policy_rules, "nas")

    findings = DriftEngine().evaluate([nas], [nas_rule])

    assert len(findings) == 1
    assert findings[0].status is DriftStatus.OK
