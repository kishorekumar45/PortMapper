from portmapper.models import MacStatus, PortState, Protocol
from portmapper.nmap_parser import parse_hosts

_HOST_WITHOUT_MAC_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
<status state="up"/>
<address addr="203.0.113.5" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="443">
<state state="open"/>
<service name="https"/>
</port>
</ports>
</host>
</nmaprun>
"""


def _find_host(hosts, ip: str):
    return next(h for h in hosts if ip in h.ip_addresses)


def _find_port(host, number: int):
    return next(p for p in host.ports if p.number == number)


def test_parses_all_up_hosts_from_subnet_sweep(nmap_subnet_xml):
    hosts = parse_hosts(nmap_subnet_xml)

    assert len(hosts) == 3


def test_down_host_excluded_from_results(nmap_subnet_xml):
    hosts = parse_hosts(nmap_subnet_xml)

    assert all("192.168.1.200" not in h.ip_addresses for h in hosts)


def test_parses_port_states_open_closed_filtered(nmap_subnet_xml):
    hosts = parse_hosts(nmap_subnet_xml)
    nas = _find_host(hosts, "192.168.1.10")

    assert _find_port(nas, 22).state is PortState.OPEN
    assert _find_port(nas, 80).state is PortState.CLOSED
    assert _find_port(nas, 8080).state is PortState.FILTERED
    assert _find_port(nas, 22).protocol is Protocol.TCP


def test_parses_service_details(nmap_subnet_xml):
    hosts = parse_hosts(nmap_subnet_xml)
    nas = _find_host(hosts, "192.168.1.10")
    ssh_port = _find_port(nas, 22)

    assert ssh_port.service.name == "ssh"
    assert ssh_port.service.product == "OpenSSH"
    assert ssh_port.service.version == "9.6"


def test_known_vendor_mac_classified_as_known(nmap_subnet_xml):
    hosts = parse_hosts(nmap_subnet_xml)
    nas = _find_host(hosts, "192.168.1.10")

    assert nas.mac == "B8:27:EB:12:34:56"
    assert nas.mac_status is MacStatus.KNOWN


def test_locally_administered_mac_classified_as_randomized(nmap_subnet_xml):
    hosts = parse_hosts(nmap_subnet_xml)
    guest = _find_host(hosts, "192.168.1.144")

    assert guest.mac == "02:1A:2B:3C:4D:5E"
    assert guest.mac_status is MacStatus.RANDOMIZED


def test_parses_hostname_from_ptr_record(nmap_subnet_xml):
    hosts = parse_hosts(nmap_subnet_xml)
    nas = _find_host(hosts, "192.168.1.10")

    assert nas.hostname == "nas.lan"


def test_host_without_mac_address_element_classified_as_unknown():
    [host] = parse_hosts(_HOST_WITHOUT_MAC_XML)

    assert host.mac is None
    assert host.mac_status is MacStatus.UNKNOWN
