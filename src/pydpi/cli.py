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


@app.command()
def interfaces():
    """List network adapters that can be used with 'pydpi live'."""
    from pydpi.live import LiveCaptureError, list_interfaces
    try:
        rows = list_interfaces()
    except LiveCaptureError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(1)
    t = Table(title="Network adapters (use the number or part of the name with -i)")
    for col in ("No.", "Name", "Description", "IP address"):
        t.add_column(col)
    for num, name, desc, ip in rows:
        t.add_row(str(num), name, desc, ip)
    console.print(t)


@app.command()
def live(
    interface: Annotated[str | None, typer.Option("-i", "--interface", help="Adapter number or name")] = None,
    seconds: Annotated[int | None, typer.Option("-s", "--seconds", min=1, help="Stop after N seconds")] = None,
    count: Annotated[int | None, typer.Option("-n", "--count", min=1, help="Stop after N packets")] = None,
    bpf: Annotated[str | None, typer.Option("--filter", help="Capture filter, e.g. 'tcp port 443'")] = None,
    save: Annotated[Path | None, typer.Option("--save", help="Also save the captured packets to a .pcap file")] = None,
    replay: Annotated[Path | None, typer.Option(
        "--replay", exists=True, dir_okay=False, help="Demo mode: replay a saved capture as if it were live")] = None,
    delay: Annotated[float, typer.Option(help="Seconds between packets in --replay mode")] = 0.02,
    block_app: Annotated[list[str] | None, typer.Option("--block-app")] = None,
    block_ip: Annotated[list[str] | None, typer.Option("--block-ip")] = None,
    block_domain: Annotated[list[str] | None, typer.Option("--block-domain")] = None,
    rules: Annotated[Path | None, typer.Option(help="YAML rules file")] = None,
    signatures: Annotated[Path | None, typer.Option(help="Custom signatures YAML")] = None,
    json_out: Annotated[Path | None, typer.Option("--json", help="Export the final report as JSON")] = None,
    csv_out: Annotated[Path | None, typer.Option("--csv", help="Export flows as CSV")] = None,
    top: Annotated[int, typer.Option(help="Rows in the final top-N tables")] = 15,
    verbose: Annotated[bool, typer.Option("-v", "--verbose")] = False,
):
    """Watch live traffic on this computer (monitor mode: observes and reports, never blocks)."""
    from pydpi.live import LiveCaptureError, LiveMonitor, replay_source, resolve_interface, run_live, sniff_source
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING)
    rule_set = RuleSet.build(block_ip or [], block_app or [], block_domain or [])
    if rules:
        rule_set = RuleSet.from_file(rules).merged_with(rule_set)
    try:
        sigs = SignatureDB.load(signatures)
        if replay:
            monitor = LiveMonitor(rule_set, sigs, f"replay of {replay.name}", save)

            def source():
                replay_source(monitor, replay, delay)
        else:
            iface = resolve_interface(interface)
            label = str(getattr(iface, "description", "") or getattr(iface, "name", "") or "default adapter")
            monitor = LiveMonitor(rule_set, sigs, f"live: {label}", save)

            def source():
                sniff_source(monitor, iface, seconds, count, bpf)
            console.print(f"Capturing on [bold]{label}[/]. Press [bold]Ctrl+C[/] to stop"
                          + (f" (or wait {seconds} s)." if seconds else "."))
        run_live(monitor, source, console)
    except (LiveCaptureError, ValueError) as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(1)

    report = monitor.finish()
    if rule_set:
        console.print("[yellow]Monitor mode:[/] rules only mark traffic as 'would be blocked'. "
                      "Nothing is stopped on your network.")
    print_report(report, console, top)
    if save:
        console.print(f"Captured packets -> {save}")
    if json_out:
        write_json(report, json_out)
        console.print(f"JSON report -> {json_out}")
    if csv_out:
        write_csv(report, csv_out)
        console.print(f"Flow CSV   -> {csv_out}")


@app.command()
def doctor():
    """Check that everything needed for live capture is in place, and say how to fix what is not."""
    from pydpi.auto import print_checks, run_doctor
    ok = print_checks(run_doctor(need_capture=True), console)
    console.print("[green]Everything needed is ready.[/]" if ok
                  else "[red]Fix the FAIL lines above, then run again.[/]")
    raise typer.Exit(0 if ok else 1)


@app.command()
def auto(
    seconds: Annotated[int, typer.Option("-s", "--seconds", min=0, help="How long to watch. 0 = until Ctrl+C")] = 60,
    interface: Annotated[str | None, typer.Option(
        "-i", "--interface", help="Skip auto-detection, use this adapter")] = None,
    save: Annotated[bool, typer.Option("--save", help="Also keep the captured packets as capture.pcap")] = False,
    out_dir: Annotated[Path, typer.Option(help="Folder for results")] = Path("pydpi_reports"),
    probe: Annotated[float, typer.Option(help="Seconds spent finding the busiest adapter")] = 3.0,
    replay: Annotated[Path | None, typer.Option(
        "--replay", exists=True, dir_okay=False, help="Demo: use a saved capture instead of live traffic")] = None,
    delay: Annotated[float, typer.Option(help="Seconds between packets in --replay mode")] = 0.02,
    block_app: Annotated[list[str] | None, typer.Option("--block-app")] = None,
    block_ip: Annotated[list[str] | None, typer.Option("--block-ip")] = None,
    block_domain: Annotated[list[str] | None, typer.Option("--block-domain")] = None,
    rules: Annotated[Path | None, typer.Option(help="YAML rules file")] = None,
    signatures: Annotated[Path | None, typer.Option(help="Custom signatures YAML")] = None,
    top: Annotated[int, typer.Option(help="Rows in the final tables")] = 15,
):
    """ONE command: check the setup, pick the right adapter, watch live traffic, save the results."""
    from pydpi.auto import choose_interface, make_report_dir, print_checks, probe_interfaces, run_doctor, save_results
    from pydpi.live import LiveCaptureError, LiveMonitor, replay_source, resolve_interface, run_live, sniff_source

    rule_set = RuleSet.build(block_ip or [], block_app or [], block_domain or [])
    if rules:
        rule_set = RuleSet.from_file(rules).merged_with(rule_set)

    console.rule("[bold]Step 1 of 4: checking your setup")
    if not print_checks(run_doctor(need_capture=replay is None), console):
        console.print("[red]Please fix the FAIL lines above and run the command again.[/]")
        raise typer.Exit(1)

    try:
        sigs = SignatureDB.load(signatures)
        iface = None
        if replay is None:
            console.rule("[bold]Step 2 of 4: choosing the network adapter")
            if interface:
                iface = resolve_interface(interface)
            else:
                console.print(f"Listening on every adapter for {probe:g} seconds. "
                              "Open a website if nothing seems to happen...")
                results = probe_interfaces(probe)
                iface = choose_interface(results)
                if iface is None:
                    console.print("[yellow]No adapter showed traffic. Using the system default.[/] "
                                  "(If the dashboard stays empty, run 'pydpi interfaces' and use -i NUMBER.)")
            label = str(getattr(iface, "description", "") or getattr(iface, "name", "") or "default adapter")
            console.print(f"Adapter: [bold]{label}[/]")
        else:
            console.rule("[bold]Step 2 of 4: demo mode (no adapter needed)")

        folder = make_report_dir(out_dir)
        target = f"replay of {replay.name}" if replay else f"live: {label}"
        monitor = LiveMonitor(rule_set, sigs, target, folder / "capture.pcap" if save else None)

        console.rule("[bold]Step 3 of 4: watching traffic")
        if replay:
            run_live(monitor, lambda: replay_source(monitor, replay, delay), console)
        else:
            console.print("Browse as usual. Press [bold]Ctrl+C[/] to stop"
                          + (f" (or wait {seconds} s)." if seconds else "."))
            run_live(monitor, lambda: sniff_source(monitor, iface, seconds or None), console)
    except (LiveCaptureError, ValueError) as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(1)

    console.rule("[bold]Step 4 of 4: saving the results")
    report = monitor.finish()
    if rule_set:
        console.print("[yellow]Monitor mode:[/] rules only mark traffic as 'would be blocked'. Nothing is stopped.")
    print_report(report, console, top)
    files = save_results(report, folder, top)
    console.print(f"\n[bold green]Done.[/] Results are in: [bold]{folder.resolve()}[/]")
    for f in files + ([folder / "capture.pcap"] if save else []):
        console.print(f"  - {f.name}")
    console.print("[dim]This folder is ignored by Git automatically, so it cannot be uploaded by accident.[/]")
