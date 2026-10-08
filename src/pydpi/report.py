"""Rendering and exporting a Report (console tables, JSON, CSV)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pydpi.models import PROTO_NAMES, Report


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def print_report(report: Report, console: Console | None = None, top: int = 15) -> None:
    c = console or Console()
    s = report.stats
    pps = s.total_packets / report.elapsed if report.elapsed else 0

    summary = Table.grid(padding=(0, 3))
    summary.add_row("Input", report.input_path, "Total packets", f"{s.total_packets:,}")
    summary.add_row("Output", report.output_path or "-", "Total bytes", _human(s.total_bytes))
    summary.add_row("Workers", str(len(report.worker_packets)), "TCP / UDP / other",
                    f"{s.tcp_packets:,} / {s.udp_packets:,} / {s.other_packets:,}")
    summary.add_row("Time", f"{report.elapsed:.2f}s ({pps:,.0f} pkt/s)", "Non-IP / malformed",
                    f"{s.non_ip_packets:,} / {s.malformed_packets:,}")
    summary.add_row("Flows", f"{len(report.flows):,}", "Forwarded / Dropped",
                    f"[green]{s.forwarded:,}[/] / [red]{s.dropped:,}[/]")
    c.print(Panel(summary, title="[bold]PyDPI - Processing Report", border_style="cyan"))

    for line in report.rules_summary:
        c.print(f"[yellow][Rules][/] {line}")

    if len(report.worker_packets) > 1:
        t = Table(title="Worker load", show_header=True)
        t.add_column("Worker")
        t.add_column("Packets", justify="right")
        for i, n in enumerate(report.worker_packets):
            t.add_row(f"W{i}", f"{n:,}")
        c.print(t)

    t = Table(title="Application breakdown")
    for col, just in (("Application", "left"), ("Flows", "right"), ("Packets", "right"),
                      ("Share", "right"), ("Traffic", "right"), ("", "left"), ("Dropped", "right"),
                      ("Status", "left")):
        t.add_column(col, justify=just)
    total = max(s.total_packets, 1)
    for row in report.app_breakdown():
        share = 100 * row.packets / total
        status = "[red]BLOCKED[/]" if row.blocked_flows else ""
        t.add_row(row.app, str(row.flows), f"{row.packets:,}", f"{share:.1f}%",
                  _human(row.bytes), "█" * int(share / 4), str(row.dropped_packets), status)
    c.print(t)

    domains = report.domains()
    if domains:
        t = Table(title=f"Detected domains ({len(domains)})")
        t.add_column("Domain")
        t.add_column("Application")
        for dom, app in list(domains.items())[:top * 2]:
            t.add_row(dom, app)
        c.print(t)

    ja3 = {}
    for f in report.flows:
        if f.ja3_hash:
            ja3.setdefault(f.ja3_hash, []).append(f.sni or "-")
    if ja3:
        t = Table(title="TLS client fingerprints (JA3)")
        t.add_column("JA3 hash")
        t.add_column("Flows", justify="right")
        t.add_column("Example SNI")
        for h, snis in sorted(ja3.items(), key=lambda kv: -len(kv[1]))[:top]:
            t.add_row(h, str(len(snis)), snis[0])
        c.print(t)

    blocked = [f for f in report.flows if f.blocked]
    if blocked:
        t = Table(title="Blocked flows")
        for col in ("Client", "Server", "App", "Host", "Reason"):
            t.add_column(col)
        for f in blocked[:top]:
            t.add_row(f.client_str, f.server_str, f.app, f.sni or "-", f.block_reason or "")
        c.print(t)


def flow_to_dict(f) -> dict:
    return {
        "client": f.client_str, "server": f.server_str,
        "protocol": PROTO_NAMES.get(f.proto, str(f.proto)),
        "app": f.app, "host": f.sni, "method": f.method,
        "alpn": list(f.alpn), "ja3": f.ja3_hash, "ech": f.ech,
        "packets": f.packets, "bytes": f.bytes, "dropped_packets": f.dropped_packets,
        "blocked": f.blocked, "block_reason": f.block_reason,
        "first_seen": f.first_ts, "last_seen": f.last_ts,
    }


def write_json(report: Report, path: str | Path) -> None:
    s = report.stats
    doc = {
        "input": report.input_path, "output": report.output_path,
        "elapsed_seconds": round(report.elapsed, 4),
        "stats": {k: getattr(s, k) for k in s.__slots__},
        "workers": report.worker_packets,
        "rules": report.rules_summary,
        "applications": [vars(r) for r in report.app_breakdown()],
        "domains": report.domains(),
        "flows": [flow_to_dict(f) for f in report.flows],
    }
    Path(path).write_text(json.dumps(doc, indent=2), encoding="utf-8")


def write_csv(report: Report, path: str | Path) -> None:
    rows = [flow_to_dict(f) for f in report.flows]
    if not rows:
        Path(path).write_text("", encoding="utf-8")
        return
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        for r in rows:
            r["alpn"] = ",".join(r["alpn"])
            w.writerow(r)
