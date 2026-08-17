import subprocess
from unittest.mock import MagicMock, patch

import pytest

from portmapper.scanner import (
    NmapNotFoundError,
    NmapScanError,
    NmapTimeoutError,
    Scanner,
)

_SIMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
<status state="up"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<address addr="AA:BB:CC:00:11:22" addrtype="mac"/>
<ports>
<port protocol="tcp" portid="22">
<state state="open"/>
<service name="ssh"/>
</port>
</ports>
</host>
</nmaprun>
"""


def test_scan_returns_parsed_hosts_on_success():
    fake_result = MagicMock(returncode=0, stdout=_SIMPLE_XML, stderr="")
    with patch("portmapper.scanner.subprocess.run", return_value=fake_result):
        hosts = Scanner().scan("192.168.1.0/24")

    assert len(hosts) == 1
    assert hosts[0].ports[0].number == 22


def test_scan_invokes_nmap_with_xml_output_flag_and_target():
    fake_result = MagicMock(returncode=0, stdout=_SIMPLE_XML, stderr="")
    with patch("portmapper.scanner.subprocess.run", return_value=fake_result) as mock_run:
        Scanner(nmap_path="nmap").scan("192.168.1.0/24")

    command = mock_run.call_args[0][0]
    assert command[0] == "nmap"
    assert "-oX" in command
    assert "192.168.1.0/24" in command


def test_scan_raises_nmap_not_found_when_binary_missing():
    with patch("portmapper.scanner.subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(NmapNotFoundError):
            Scanner().scan("192.168.1.0/24")


def test_scan_raises_scan_error_on_nonzero_exit():
    fake_result = MagicMock(returncode=1, stdout="", stderr="permission denied")
    with patch("portmapper.scanner.subprocess.run", return_value=fake_result):
        with pytest.raises(NmapScanError):
            Scanner().scan("192.168.1.0/24")


def test_scan_raises_timeout_error_on_subprocess_timeout():
    timeout_exc = subprocess.TimeoutExpired(cmd="nmap", timeout=300)
    with patch("portmapper.scanner.subprocess.run", side_effect=timeout_exc):
        with pytest.raises(NmapTimeoutError):
            Scanner().scan("192.168.1.0/24")
