"""
Wraps the nmap CLI as a subprocess, so PortMapper doesn't reimplement raw
packet scanning - nmap already handles host discovery, SYN scanning, and
service detection reliably.

Subprocess failure modes (binary missing, non-zero exit, timeout) are
translated into typed exceptions so callers (see cli.py) can show a clean
error message instead of a raw Python traceback.
"""

import subprocess  # spawns the real `nmap` binary; see Scanner.scan

from portmapper.models import Host
from portmapper.nmap_parser import parse_hosts


class NmapNotFoundError(RuntimeError):
    """Raised when the configured nmap binary can't be found on PATH."""


class NmapScanError(RuntimeError):
    """Raised when nmap runs but exits with a non-zero status."""


class NmapTimeoutError(RuntimeError):
    """Raised when the scan exceeds the configured timeout."""


class Scanner:
    """Invokes nmap against a live target and returns parsed Hosts."""

    def __init__(self, nmap_path: str = "nmap", timeout: float = 300):
        """nmap_path lets callers point at a non-standard install; timeout is in seconds."""
        self._nmap_path = nmap_path
        self._timeout = timeout

    def scan(self, target: str) -> list[Host]:
        """
        Run `nmap -oX - <target>` and parse its XML output.

        target accepts anything nmap itself accepts natively (a single IP, a
        hostname, or a CIDR range) - PortMapper doesn't re-validate it, since
        nmap already owns that job.
        """
        try:
            result = subprocess.run(
                [self._nmap_path, "-oX", "-", target],
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise NmapNotFoundError(f"nmap binary not found: {self._nmap_path}") from exc
        except subprocess.TimeoutExpired as exc:
            raise NmapTimeoutError(
                f"nmap scan of {target} timed out after {self._timeout}s"
            ) from exc

        if result.returncode != 0:
            raise NmapScanError(
                f"nmap exited with status {result.returncode}: {result.stderr.strip()}"
            )

        return parse_hosts(result.stdout)
