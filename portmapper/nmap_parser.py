"""
Parses nmap's XML output (`nmap -oX -`) into PortMapper's domain models.

The one security-relevant judgment call in this module is MAC classification:
_mac_status() uses the IEEE-defined "locally administered" bit (bit 1 of the
first octet) to tell a real, vendor-assigned MAC apart from a randomized or
private one - the same bit iOS/Android privacy MAC features rely on. That bit
is checked directly rather than trusting nmap's own vendor-lookup output, so
classification doesn't depend on nmap's OUI database being present or current.
"""

import xml.etree.ElementTree as ET  # stdlib XML parsing - no extra dependency needed

from portmapper.models import Host, MacStatus, Port, PortState, Protocol, Service

_LOCALLY_ADMINISTERED_BIT = 0b10


def _mac_status(mac: str) -> MacStatus:
    """
    Classify a MAC address as KNOWN (vendor-assigned) or RANDOMIZED
    (locally-administered), based on the locally-administered bit of its first
    octet.
    """
    first_octet = int(mac.split(":")[0], 16)
    if first_octet & _LOCALLY_ADMINISTERED_BIT:
        return MacStatus.RANDOMIZED
    return MacStatus.KNOWN


def _parse_service(port_elem: ET.Element) -> Service | None:
    """Parse nmap's <service> element for one port, if service detection ran."""
    service_elem = port_elem.find("service")
    if service_elem is None:
        return None
    return Service(
        name=service_elem.get("name", ""),
        product=service_elem.get("product"),
        version=service_elem.get("version"),
    )


def _parse_port(port_elem: ET.Element) -> Port:
    """Parse one <port> element: its number, protocol, state, and service (if present)."""
    state_elem = port_elem.find("state")
    return Port(
        number=int(port_elem.get("portid")),
        protocol=Protocol(port_elem.get("protocol")),
        state=PortState(state_elem.get("state")),
        service=_parse_service(port_elem),
    )


def _parse_host(host_elem: ET.Element) -> Host:
    """
    Parse one <host> element into a Host.

    MAC addresses only appear in nmap's output for devices on the same L2
    segment (discovered via ARP) - a host with no <address addrtype="mac">
    element gets mac_status=UNKNOWN rather than being guessed at.
    """
    mac = None
    mac_status = MacStatus.UNKNOWN
    ip_addresses = []
    for address_elem in host_elem.findall("address"):
        addrtype = address_elem.get("addrtype")
        if addrtype == "ipv4":
            ip_addresses.append(address_elem.get("addr"))
        elif addrtype == "mac":
            mac = address_elem.get("addr")
            mac_status = _mac_status(mac)

    hostname_elem = host_elem.find("hostnames/hostname")
    hostname = hostname_elem.get("name") if hostname_elem is not None else None

    ports = [_parse_port(port_elem) for port_elem in host_elem.findall("ports/port")]

    return Host(
        mac=mac,
        mac_status=mac_status,
        ip_addresses=ip_addresses,
        hostname=hostname,
        ports=ports,
    )


def parse_hosts(xml_text: str) -> list[Host]:
    """
    Parse a full `nmap -oX` document into a list of Hosts.

    Hosts with status="down" are excluded entirely - a host that didn't respond
    has nothing to report for this scan snapshot. (Tracking "used to respond,
    now doesn't" is a cross-scan-history concern, outside this module's job.)
    """
    root = ET.fromstring(xml_text)
    hosts = []
    for host_elem in root.findall("host"):
        status_elem = host_elem.find("status")
        if status_elem is None or status_elem.get("state") != "up":
            continue
        hosts.append(_parse_host(host_elem))
    return hosts
