import json
from datetime import datetime
from pathlib import Path

import pytest

from portmapper.models import Host, MacStatus, PolicyRule, Port, PortState, Protocol, Service
from portmapper.policy_loader import load_policy

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _build_service_from_dict(data: dict | None) -> Service | None:
    if data is None:
        return None
    return Service(
        name=data["name"],
        product=data.get("product"),
        version=data.get("version"),
        banner=data.get("banner"),
    )


def _build_port_from_dict(data: dict) -> Port:
    return Port(
        number=data["number"],
        protocol=Protocol(data["protocol"]),
        state=PortState(data["state"]),
        service=_build_service_from_dict(data.get("service")),
    )


def _build_host_from_dict(data: dict) -> Host:
    first_seen = data.get("first_seen")
    last_seen = data.get("last_seen")
    return Host(
        mac=data.get("mac"),
        mac_status=MacStatus(data["mac_status"]),
        ip_addresses=list(data.get("ip_addresses", [])),
        hostname=data.get("hostname"),
        ports=[_build_port_from_dict(p) for p in data.get("ports", [])],
        first_seen=datetime.fromisoformat(first_seen) if first_seen else None,
        last_seen=datetime.fromisoformat(last_seen) if last_seen else None,
    )


@pytest.fixture
def scan_hosts() -> list[Host]:
    data = json.loads((FIXTURES_DIR / "sample_scans.json").read_text())
    return [_build_host_from_dict(h) for h in data["hosts"]]


@pytest.fixture
def policy_rules() -> list[PolicyRule]:
    return load_policy(FIXTURES_DIR / "sample_policy.yaml")


@pytest.fixture
def nmap_subnet_xml() -> str:
    return (FIXTURES_DIR / "sample_nmap_subnet.xml").read_text()
