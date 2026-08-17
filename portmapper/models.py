"""
Domain models for PortMapper.

These dataclasses and enums define the vocabulary used throughout the pipeline:
a scanned Host and its Ports/Services, a declared PolicyRule describing what
*should* be running on a host, and the DriftFinding/TriageFinding objects
produced when live scan results are compared against that policy.

Two design decisions are worth flagging for anyone reviewing this code:
  - Host identity is MAC-based, not IP-based, because DHCP-assigned IPs are not
    stable across scans. MacStatus explicitly distinguishes a trustworthy,
    vendor-assigned MAC (KNOWN) from a privacy/randomized MAC (RANDOMIZED) or an
    address that couldn't be determined at all (UNKNOWN) - see Host.identity_key.
  - DriftStatus has five values, not the "open port bad, closed port fine" binary
    a plain diff tool would give you. NEW_HOST (a known device with no policy
    entry yet) and UNVERIFIED_IDENTITY (an untrustworthy MAC) are kept separate
    because each needs a different response from whoever owns the network.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Protocol(str, Enum):
    """Transport-layer protocol for a scanned port (nmap reports both tcp and udp)."""

    TCP = "tcp"
    UDP = "udp"


class PortState(str, Enum):
    """
    A port's state as reported by a live scan.

    Only the three states this project's drift logic actually acts on are
    modeled. Real nmap output can also report combined states like
    "open|filtered" (usually behind a stateful firewall that swallows probes) -
    that's a known, deliberate gap rather than something silently mishandled;
    see the design notes in nmap_parser.py.
    """

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class MacStatus(str, Enum):
    """
    How much a scanned MAC address can be trusted as a stable device identity.

    KNOWN: a vendor-assigned (globally unique) MAC - the IEEE "locally
        administered" bit is clear. Safe to use as a long-term device identifier.
    RANDOMIZED: the locally-administered bit is set, matching the pattern used
        by modern OS privacy features (iOS/Android MAC randomization). Treated
        as an untrustworthy identity rather than silently accepted as a
        legitimate new device.
    UNKNOWN: no MAC address was observed at all - e.g. the host isn't on the
        same L2 segment, so ARP-based MAC discovery wasn't possible.
    """

    KNOWN = "known"
    RANDOMIZED = "randomized"
    UNKNOWN = "unknown"


@dataclass
class Service:
    """A service fingerprint for one open port, as reported by nmap's -sV detection."""

    name: str
    product: str | None = None
    version: str | None = None
    banner: str | None = None


@dataclass
class Port:
    """A single scanned port on a host: its number, protocol, state, and service (if detected)."""

    number: int
    protocol: Protocol
    state: PortState
    service: Service | None = None


@dataclass
class Host:
    """
    A single device observed in a scan.

    Identity is MAC-based (see MacStatus) rather than IP-based, because DHCP
    leases change and can't be relied on to recognize "the same device" from
    one scan to the next.
    """

    mac: str | None
    mac_status: MacStatus
    ip_addresses: list[str] = field(default_factory=list)
    hostname: str | None = None
    ports: list[Port] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def identity_key(self) -> str:
        """
        A stable key for matching this host across scans and against policy.

        Only returns the actual MAC address when mac_status is KNOWN. A
        randomized or unknown MAC deliberately falls back to a generic
        "unresolved:<status>" key instead of the raw address, so a rotating
        privacy MAC is never mistaken for a stable, trackable device identity.
        """
        if self.mac_status is MacStatus.KNOWN and self.mac:
            return self.mac
        return f"unresolved:{self.mac_status.value}"


@dataclass(frozen=True)
class PolicyPort:
    """One port/protocol pair, as referenced by a PolicyRule's allow-list or require-list."""

    number: int
    protocol: Protocol


@dataclass
class PolicyRule:
    """
    The declared, expected state for one host, as written by the network owner.

    allowed_ports is a whitelist: anything open on the host that isn't listed
    here is drift. required_ports is the opposite: anything listed here that
    ISN'T open is a missing-service finding. A host with no matching rule is
    treated as unmanaged (see DriftStatus.NEW_HOST / UNVERIFIED_IDENTITY), never
    silently trusted just because it's unlisted.
    """

    host_label: str
    mac: str | None = None
    hostname: str | None = None
    allowed_ports: list[PolicyPort] = field(default_factory=list)
    required_ports: list[PolicyPort] = field(default_factory=list)


class DriftStatus(str, Enum):
    """
    The outcome of comparing one scanned host against the declared policy.

    Five values instead of a plain pass/fail, because a network owner needs to
    respond differently to each one:
      OK                     - matches policy, no action needed.
      DRIFT_DETECTED         - an unapproved port is open (exposure risk).
      MISSING_EXPECTED_PORT  - a required service isn't running (availability risk).
      NEW_HOST                - a known-MAC device with no policy entry yet.
      UNVERIFIED_IDENTITY     - a randomized/unknown MAC; identity can't be trusted.
    """

    OK = "ok"
    DRIFT_DETECTED = "drift_detected"
    MISSING_EXPECTED_PORT = "missing_expected_port"
    NEW_HOST = "new_host"
    UNVERIFIED_IDENTITY = "unverified_identity"


@dataclass
class DriftFinding:
    """
    One result of DriftEngine.evaluate(): a host's status plus, if relevant, the
    specific port/service/policy rule involved.

    port_number/protocol/service_name are flattened here rather than nested in
    a Port object, because a MISSING_EXPECTED_PORT finding has no observed
    state to attach to a real Port - the port simply isn't there.
    """

    status: DriftStatus
    host: Host
    port_number: int | None = None
    protocol: Protocol | None = None
    service_name: str | None = None
    rule: PolicyRule | None = None
    description: str = ""


class Severity(str, Enum):
    """
    Triage severity for a scored finding.

    Declaration order IS the severity ranking, most severe first - reporter.py
    sorts findings by walking this enum's declaration order rather than using a
    separate ordering table.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class TriageFinding:
    """A DriftFinding after RiskScorer has attached a severity and a human-readable rationale."""

    finding: DriftFinding
    severity: Severity
    rationale: str
