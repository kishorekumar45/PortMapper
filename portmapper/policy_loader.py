"""
Loads a network owner's declared policy (YAML) into PolicyRule objects.

YAML was chosen over a stdlib-only format (e.g. TOML) because a policy file is
meant to be hand-written and hand-edited by whoever owns the network - this is
the one deliberate exception to keeping the rest of the project stdlib-only,
since that rule is scoped to network/scanning code, not config parsing.
"""

from pathlib import Path

import yaml  # policy files are meant to be hand-written; see module docstring

from portmapper.models import PolicyPort, PolicyRule, Protocol


def _parse_policy_port(data: dict) -> PolicyPort:
    """Parse one {port, protocol} mapping from the YAML into a PolicyPort."""
    return PolicyPort(number=data["port"], protocol=Protocol(data["protocol"]))


def _parse_policy_rule(data: dict) -> PolicyRule:
    """Parse one host entry from the policy YAML into a PolicyRule."""
    return PolicyRule(
        host_label=data["host"],
        mac=data.get("mac"),
        hostname=data.get("hostname"),
        allowed_ports=[_parse_policy_port(p) for p in data.get("allowed_ports", [])],
        required_ports=[_parse_policy_port(p) for p in data.get("required_ports", [])],
    )


def load_policy(path: Path | str) -> list[PolicyRule]:
    """Load and parse a policy YAML file into a list of PolicyRules, one per declared host."""
    data = yaml.safe_load(Path(path).read_text())
    return [_parse_policy_rule(h) for h in data["hosts"]]
