"""
Static risk scoring for drift findings.

RiskScorer turns a DriftFinding (what changed) into a TriageFinding (how bad is
it, and why) using a hand-curated table of known-risky ports/services. This is
what turns PortMapper from a "things changed" alert into something a SOC
analyst would recognize as triage output - findings can be sorted and acted on
by severity instead of read as an undifferentiated list.

Only DRIFT_DETECTED findings (an unexpectedly OPEN port) are scored against the
port-risk table below, because that table describes exposure risk specifically.
The other statuses (OK, MISSING_EXPECTED_PORT, NEW_HOST, UNVERIFIED_IDENTITY)
get fixed severities reflecting what they actually mean operationally - see
RiskScorer._score_finding.
"""

from dataclasses import dataclass

from portmapper.models import (
    DriftFinding,
    DriftStatus,
    Protocol,
    Severity,
    TriageFinding,
)


@dataclass(frozen=True)
class _PortRisk:
    """A severity + human-readable rationale pair, reused for both port-table
    entries and the fixed severities assigned to non-port-specific statuses."""

    severity: Severity
    rationale: str


# Known-risky ports. These entries ARE the security judgment calls in this
# project: Telnet/RDP are CRITICAL because they're a direct-compromise path or
# a leading ransomware target respectively; SMB is HIGH for its RCE/lateral-
# movement history; SSH/HTTPS are LOW because they're encrypted, standard
# remote-management/web protocols.
_PORT_RISK_TABLE: dict[tuple[int, Protocol], _PortRisk] = {
    (23, Protocol.TCP): _PortRisk(
        Severity.CRITICAL,
        "Telnet transmits credentials and session data in cleartext; an open telnet "
        "port is a direct path to full device compromise.",
    ),
    (3389, Protocol.TCP): _PortRisk(
        Severity.CRITICAL,
        "RDP is a leading target for ransomware and credential-stuffing attacks when "
        "exposed on a network.",
    ),
    (445, Protocol.TCP): _PortRisk(
        Severity.HIGH,
        "SMB has a history of critical remote-code-execution exploits (e.g. "
        "EternalBlue) and is commonly used for lateral movement.",
    ),
    (80, Protocol.TCP): _PortRisk(
        Severity.MEDIUM,
        "Unencrypted HTTP traffic can be intercepted or tampered with in transit.",
    ),
    (443, Protocol.TCP): _PortRisk(
        Severity.LOW,
        "HTTPS is encrypted in transit; standard low-risk web service exposure.",
    ),
    (22, Protocol.TCP): _PortRisk(
        Severity.LOW,
        "SSH is an encrypted, standard remote-management protocol; low baseline risk.",
    ),
}

# Any port not explicitly listed above - the table's silence on a port IS the
# signal that nothing elevated is known about it, rather than a guess based on
# port-number range.
_UNKNOWN_PORT_RISK = _PortRisk(
    Severity.INFO,
    "Port is not in the known-service risk table; likely an ephemeral or "
    "unclassified service.",
)

_MISSING_EXPECTED_PORT_RISK = _PortRisk(
    Severity.MEDIUM,
    "A port required by policy is not open; the expected service may be down or "
    "misconfigured.",
)

_NEW_HOST_RISK = _PortRisk(
    Severity.MEDIUM,
    "A device with a known MAC was seen but has no policy entry yet; review and add "
    "it to the declared policy.",
)

_UNVERIFIED_IDENTITY_RISK = _PortRisk(
    Severity.MEDIUM,
    "Device identity could not be verified (randomized/unknown MAC); manually "
    "confirm this is an expected device.",
)

_OK_RISK = _PortRisk(Severity.INFO, "Host matches declared policy; no action needed.")


def score_port(port_number: int, protocol: Protocol) -> tuple[Severity, str]:
    """Look up the severity and rationale for a specific open port/protocol pair."""
    risk = _PORT_RISK_TABLE.get((port_number, protocol), _UNKNOWN_PORT_RISK)
    return risk.severity, risk.rationale


class RiskScorer:
    """Attaches a Severity + rationale to each DriftFinding, producing TriageFindings."""

    def score(self, findings: list[DriftFinding]) -> list[TriageFinding]:
        """Score every finding in the list, preserving input order."""
        return [self._score_finding(finding) for finding in findings]

    def _score_finding(self, finding: DriftFinding) -> TriageFinding:
        """
        Choose a severity/rationale for one finding based on its DriftStatus.

        Only DRIFT_DETECTED looks up the port-risk table (see module docstring
        for why); every other status maps to a fixed, pre-written severity.
        """
        if finding.status is DriftStatus.DRIFT_DETECTED:
            severity, rationale = score_port(finding.port_number, finding.protocol)
        elif finding.status is DriftStatus.OK:
            severity, rationale = _OK_RISK.severity, _OK_RISK.rationale
        elif finding.status is DriftStatus.MISSING_EXPECTED_PORT:
            severity, rationale = (
                _MISSING_EXPECTED_PORT_RISK.severity,
                _MISSING_EXPECTED_PORT_RISK.rationale,
            )
        elif finding.status is DriftStatus.NEW_HOST:
            severity, rationale = _NEW_HOST_RISK.severity, _NEW_HOST_RISK.rationale
        else:
            severity, rationale = (
                _UNVERIFIED_IDENTITY_RISK.severity,
                _UNVERIFIED_IDENTITY_RISK.rationale,
            )
        return TriageFinding(finding=finding, severity=severity, rationale=rationale)
