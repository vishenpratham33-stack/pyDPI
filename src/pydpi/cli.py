"""Command-line interface:  pydpi analyze | generate | apps"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from pydpi import __version__
from pydpi.engine import DPIEngine
from pydpi.report import print_report, write_csv, write_json
from pydpi.rules import RuleSet
from pydpi.signatures import SignatureDB

app = typer.Typer(add_completion=False, help="PyDPI - Deep Packet Inspection engine.")
console = Console()


def _version(value: bool):
    if value:
        console.print(f"pydpi {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[bool | None, typer.Option("--version", callback=_version,
                                                    is_eager=True)] = None,
):
    pass


@app.command()
def analyze(
    input: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="Input .pcap/.pcapng")],
    output: Annotated[Path | None, typer.Option("-o", "--output", help="Write forwarded packets here")] = None,
    block_app: Annotated[list[str] | None, typer.Option("--block-app", help="e.g. YouTube")] = None,
    block_ip: Annotated[list[str] | None, typer.Option("--block-ip", help="IP or CIDR")] = None,
    block_domain: Annotated[list[str] | None, typer.Option(
        "--block-domain", help="example.com | *.example.com | keyword")] = None,
    rules: Annotated[Path | None, typer.Option(help="YAML rules file")] = None,
    signatures: Annotated[Path | None, typer.Option(help="Custom signatures YAML")] = None,
    workers: Annotated[int, typer.Option("-w", "--workers", min=1, help="Worker processes")] = 1,
    json_out: Annotated[Path | None, typer.Option("--json", help="Export full report as JSON")] = None,
    csv_out: Annotated[Path | None, typer.Option("--csv", help="Export flows as CSV")] = None,
    top: Annotated[int, typer.Option(help="Rows in the top-N tables")] = 15,
    verbose: Annotated[bool, typer.Option("-v", "--verbose")] = False,
):
    """Inspect a capture, classify traffic, apply blocking rules, print a report."""
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING)
    rule_set = RuleSet.build(block_ip or [], block_app or [], block_domain or [])
    if rules:
        rule_set = RuleSet.from_file(rules).merged_with(rule_set)
    try:
        engine = DPIEngine(rule_set, SignatureDB.load(signatures), workers)
        report = engine.run(input, output)
    except ValueError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(1)
    print_report(report, console, top)
    if json_out:
        write_json(report, json_out)
        console.print(f"JSON report -> {json_out}")
    if csv_out:
        write_csv(report, csv_out)
        console.print(f"Flow CSV   -> {csv_out}")


@app.command()
def generate(
    output: Annotated[Path, typer.Argument(help="Where to write the demo .pcap")] = Path("demo.pcap"),
    seed: int = 7,
):
    """Create a demo capture (TLS, fragmented TLS, ECH, IPv6, HTTP, QUIC, DNS)."""
    from pydpi.synth import generate_pcap
    n = generate_pcap(output, seed)
    console.print(f"Wrote {n} packets -> {output}")


@app.command()
def apps(signatures: Annotated[Path | None, typer.Option()] = None):
    """List the applications the engine can recognise."""
    db = SignatureDB.load(signatures)
    t = Table(title=f"{len(db.app_names)} applications, {len(db)} domain signatures")
    t.add_column("Application")
    for name in db.app_names:
        t.add_row(name)
    console.print(t)
