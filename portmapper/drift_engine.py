"""
Policy-drift detection: the core differentiator of PortMapper.

Most home-network scanners only diff "what's open now" against "what was open
last scan". DriftEngine instead compares live scan results against a policy the
network owner explicitly wrote down - so a port that has ALWAYS been open but
never should have been is still caught, not just newly-opened ports.

Host <-> policy matching is done by MAC address (case/whitespace-normalized),
not IP, because DHCP-assigned IPs aren't stable across scans.
"""

from portmapper.models import (
    DriftFinding,
    DriftStatus,
    Host,
    MacStatus,
    PolicyPort,
    PolicyRule,
    PortState,
)


def _normalize_mac(mac: str | None) -> str | None:
    """
    Normalize a MAC address for comparison (uppercase, no surrounding whitespace).

    Needed because a hand-typed policy YAML and nmap's own MAC formatting won't
    necessarily match byte-for-byte even when they refer to the same address.
    """
    return mac.strip().upper() if mac else None


class DriftEngine:
    """Compares scanned hosts against declared policy rules and produces findings."""

    def evaluate(self, hosts: list[Host], rules: list[PolicyRule]) -> list[DriftFinding]:
        """Evaluate every scanned host against the policy and return all findings."""
        findings = []
        for host in hosts:
            findings.extend(self._evaluate_host(host, rules))
        return findings

    def _find_rule(self, host: Host, rules: list[PolicyRule]) -> PolicyRule | None:
        """
        Find the policy rule matching this host's MAC address, if any.

        Returns None both when the host's MAC simply isn't in the policy, and
        when the host has no usable MAC to match on at all - the caller tells
        those two cases apart using the host's mac_status (see _evaluate_host).
        """
        host_mac = _normalize_mac(host.mac)
        if host_mac is None:
            return None
        for rule in rules:
            if _normalize_mac(rule.mac) == host_mac:
                return rule
        return None

    def _evaluate_host(self, host: Host, rules: list[PolicyRule]) -> list[DriftFinding]:
        """
        Produce the finding(s) for a single host.

        A host with no matching policy rule short-circuits into exactly one
        finding: NEW_HOST if its MAC is trustworthy (just not yet declared in
        policy), or UNVERIFIED_IDENTITY if the MAC itself can't be trusted
        (randomized or unknown). Port-by-port comparison only runs once a
        matching rule is found.
        """
        rule = self._find_rule(host, rules)
        if rule is None:
            status = (
                DriftStatus.NEW_HOST
                if host.mac_status is MacStatus.KNOWN
                else DriftStatus.UNVERIFIED_IDENTITY
            )
            return [DriftFinding(status=status, host=host)]

        open_ports = [p for p in host.ports if p.state is PortState.OPEN]
        allowed = set(rule.allowed_ports)
        open_keys = {PolicyPort(number=p.number, protocol=p.protocol) for p in open_ports}

        findings = []

        # Anything open that isn't on the allow-list is an unexpected exposure.
        for port in open_ports:
            key = PolicyPort(number=port.number, protocol=port.protocol)
            if key not in allowed:
                findings.append(
                    DriftFinding(
                        status=DriftStatus.DRIFT_DETECTED,
                        host=host,
                        port_number=port.number,
                        protocol=port.protocol,
                        service_name=port.service.name if port.service else None,
                        rule=rule,
                        description=f"unapproved open port {port.number}/{port.protocol.value}",
                    )
                )

        # Anything required that ISN'T open is a possible outage or misconfiguration.
        for required in rule.required_ports:
            if required not in open_keys:
                findings.append(
                    DriftFinding(
                        status=DriftStatus.MISSING_EXPECTED_PORT,
                        host=host,
                        port_number=required.number,
                        protocol=required.protocol,
                        rule=rule,
                        description=f"required port {required.number}/{required.protocol.value} not open",
                    )
                )

        if not findings:
            findings.append(DriftFinding(status=DriftStatus.OK, host=host, rule=rule))

        return findings
