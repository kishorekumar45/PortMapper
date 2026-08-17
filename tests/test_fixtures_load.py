from portmapper.models import Host, MacStatus, PolicyRule


def test_scan_hosts_fixture_has_four_hosts_with_expected_status(scan_hosts: list[Host]):
    assert len(scan_hosts) == 4

    statuses_by_hostname = {h.hostname: h.mac_status for h in scan_hosts}
    assert statuses_by_hostname["nas.lan"] is MacStatus.KNOWN
    assert statuses_by_hostname["printer.lan"] is MacStatus.KNOWN
    assert statuses_by_hostname["router.lan"] is MacStatus.KNOWN

    guest = next(h for h in scan_hosts if h.hostname is None)
    assert guest.mac_status is MacStatus.RANDOMIZED


def test_policy_rules_fixture_has_three_rules(policy_rules: list[PolicyRule]):
    labels = {r.host_label for r in policy_rules}
    assert labels == {"nas", "printer", "router"}
