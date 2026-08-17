"""
Command-line entry point for PortMapper.

Wires the whole pipeline together behind two subcommands:
    scan  - live target  -> Scanner       -> ...
    audit - nmap XML file -> nmap_parser  -> ...
...both continuing on to DriftEngine -> RiskScorer -> Reporter -> stdout.

Exit codes are deliberate, not accidental:
    2 - the input given was a problem (missing file, malformed XML).
    1 - the operation itself failed (nmap missing/erroring/timing out).
    0 - success.
Anything scripting around this CLI can rely on that distinction rather than
just checking for "non-zero".
"""

import xml.etree.ElementTree as ET
from enum import Enum
from pathlib import Path

import typer

from portmapper.drift_engine import DriftEngine
from portmapper.models import PolicyRule
from portmapper.nmap_parser import parse_hosts
from portmapper.policy_loader import load_policy
from portmapper.reporter import Reporter
from portmapper.risk_scorer import RiskScorer
from portmapper.scanner import NmapNotFoundError, NmapScanError, NmapTimeoutError, Scanner

app = typer.Typer()


class OutputFormat(str, Enum):
    """Selectable report format for both subcommands, validated automatically by Typer/Click."""

    MARKDOWN = "markdown"
    JSON = "json"


def _load_policy_or_exit(policy: Path) -> list[PolicyRule]:
    """Load the policy file, or print a clean error and exit(2) if it doesn't exist."""
    if not policy.exists():
        typer.echo(f"Policy file not found: {policy}", err=True)
        raise typer.Exit(code=2)
    return load_policy(policy)


def _render(hosts, rules: list[PolicyRule], format: OutputFormat) -> str:
    """Run the shared DriftEngine -> RiskScorer -> Reporter pipeline on a host list."""
    findings = DriftEngine().evaluate(hosts, rules)
    triage = RiskScorer().score(findings)
    reporter = Reporter()
    if format is OutputFormat.JSON:
        return reporter.to_json(triage)
    return reporter.to_markdown(triage)


@app.command()
def scan(
    target: str,
    policy: Path = typer.Option(..., "--policy", help="Path to the declared policy YAML file."),
    format: OutputFormat = typer.Option(
        OutputFormat.MARKDOWN, "--format", help="Output format."
    ),
    nmap_path: str = typer.Option("nmap", "--nmap-path", help="Path to the nmap binary."),
):
    """Scan a live target and audit it against the declared policy."""
    rules = _load_policy_or_exit(policy)

    try:
        hosts = Scanner(nmap_path=nmap_path).scan(target)
    except (NmapNotFoundError, NmapScanError, NmapTimeoutError) as exc:
        # All three nmap failure modes are operational, not input errors - same
        # clean-message-then-exit(1) handling regardless of which one fired.
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from None

    typer.echo(_render(hosts, rules, format))


@app.command()
def audit(
    xml: Path = typer.Option(..., "--xml", help="Path to a pre-existing nmap XML output file."),
    policy: Path = typer.Option(..., "--policy", help="Path to the declared policy YAML file."),
    format: OutputFormat = typer.Option(
        OutputFormat.MARKDOWN, "--format", help="Output format."
    ),
):
    """Audit a pre-existing nmap XML file against the declared policy (offline, no live scan)."""
    rules = _load_policy_or_exit(policy)

    if not xml.exists():
        typer.echo(f"Nmap XML file not found: {xml}", err=True)
        raise typer.Exit(code=2)

    try:
        hosts = parse_hosts(xml.read_text())
    except ET.ParseError as exc:
        typer.echo(f"Failed to parse Nmap XML file {xml}: {exc}", err=True)
        raise typer.Exit(code=2) from None

    typer.echo(_render(hosts, rules, format))
