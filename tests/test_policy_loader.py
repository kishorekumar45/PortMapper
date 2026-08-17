from pathlib import Path

from portmapper.models import PolicyPort, Protocol
from portmapper.policy_loader import load_policy

FIXTURE = Path(__file__).parent / "fixtures" / "sample_policy.yaml"


def test_load_policy_returns_one_rule_per_host():
    rules = load_policy(FIXTURE)

    assert {r.host_label for r in rules} == {"nas", "printer", "router"}


def test_load_policy_parses_allowed_and_required_ports():
    rules = load_policy(FIXTURE)
    nas = next(r for r in rules if r.host_label == "nas")

    assert PolicyPort(number=22, protocol=Protocol.TCP) in nas.allowed_ports
    assert PolicyPort(number=445, protocol=Protocol.TCP) in nas.allowed_ports
    assert PolicyPort(number=22, protocol=Protocol.TCP) in nas.required_ports
    assert nas.mac == "AA:BB:CC:00:11:22"
    assert nas.hostname == "nas.lan"
