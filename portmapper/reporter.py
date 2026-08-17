"""
Renders scored findings (TriageFinding) as either a human-readable Markdown/
terminal report or structured JSON, both sorted most-severe-first.

This is the final stage of the pipeline:
    Scanner/nmap_parser -> DriftEngine -> RiskScorer -> Reporter (here)
"""

import json

from portmapper.models import Severity, TriageFinding

# Severity's declaration order (CRITICAL..INFO) IS the priority ranking - this
# just turns that ordering into a lookup usable as a sort key.
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(Severity)}


def _sorted_by_severity(findings: list[TriageFinding]) -> list[TriageFinding]:
    """Sort findings most-severe-first; shared by both report formats below."""
    return sorted(findings, key=lambda triage: _SEVERITY_RANK[triage.severity])


class Reporter:
    """Formats a list of TriageFindings as either Markdown or JSON."""

    def to_markdown(self, findings: list[TriageFinding]) -> str:
        """Render findings as a Markdown bullet list, most severe first."""
        lines = ["# PortMapper Triage Report", ""]
        for triage in _sorted_by_severity(findings):
            host = triage.finding.host
            host_label = host.hostname or host.mac or "unknown host"
            port_part = ""
            if triage.finding.port_number is not None:
                port_part = f" — {triage.finding.port_number}/{triage.finding.protocol.value}"
            lines.append(
                f"- [{triage.severity.value.upper()}] {host_label}{port_part}: {triage.rationale}"
            )
        return "\n".join(lines)

    def to_json(self, findings: list[TriageFinding]) -> str:
        """Render findings as a JSON array, most severe first, for downstream tooling."""
        payload = [self._to_dict(triage) for triage in _sorted_by_severity(findings)]
        return json.dumps(payload, indent=2)

    def _to_dict(self, triage: TriageFinding) -> dict:
        """
        Flatten a TriageFinding into a JSON-safe dict.

        Deliberately omits Host.first_seen/last_seen - datetime objects aren't
        JSON-serializable by default, and they aren't needed for triage output.
        """
        finding = triage.finding
        return {
            "severity": triage.severity.value,
            "status": finding.status.value,
            "host": {
                "mac": finding.host.mac,
                "hostname": finding.host.hostname,
                "ip_addresses": finding.host.ip_addresses,
            },
            "port_number": finding.port_number,
            "protocol": finding.protocol.value if finding.protocol else None,
            "service_name": finding.service_name,
            "description": finding.description,
            "rationale": triage.rationale,
        }
