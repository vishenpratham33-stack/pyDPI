"""Live monitoring: sniff packets from a network adapter and analyse them as they arrive.

This is MONITOR mode. PyDPI watches and reports; it never stops a packet from reaching its
destination. Rules still mark flows as "would be blocked", so you can see the effect.

Packet capture itself is done by the `scapy` library (which uses Npcap on Windows and
libpcap / raw sockets on Linux and macOS). Everything after capture is the same engine
that analyses saved files, so live and offline results always agree.
"""

from __future__ import annotations

import heapq
import logging
import threading
import time
from pathlib import Path

import dpkt
from rich.console import Group
from rich.panel import Panel
from rich.table import Table

from pydpi.engine import open_capture
from pydpi.models import Report
from pydpi.processor import PacketProcessor
from pydpi.report import _human
from pydpi.rules import RuleSet
from pydpi.signatures import SignatureDB

log = logging.getLogger(__name__)

# scapy packet class name -> pcap link type understood by parser.py
_LINKTYPES = {"Ether": 1, "Dot3": 1, "CookedLinux": 113, "Loopback": 0}
LINKTYPE_RAW = 101

NPCAP_HELP = (
    "Could not start packet capture.\n"
    "  * Windows: install Npcap from https://npcap.com (it is also installed together with Wireshark), "
    "then restart VS Code.\n"
    "  * If you see 'permission denied': close VS Code, right-click it and choose 'Run as administrator'.\n"
    "  * Linux / macOS: run with sudo, for example: sudo .venv/bin/pydpi live\n"
    "  * Check the adapter with: pydpi interfaces"
)


class LiveCaptureError(RuntimeError):
    """Capture could not start (driver missing, no permission, bad adapter name)."""


# --------------------------------------------------------------------------- adapters
def list_interfaces() -> list[tuple[int, str, str, str]]:
    """Return [(number, name, description, ip)] for every adapter scapy can see."""
    try:
        from scapy.all import conf
        ifaces = list(conf.ifaces.values())
    except Exception as exc:  # noqa: BLE001
        raise LiveCaptureError(f"{exc}\n{NPCAP_HELP}") from exc
    rows = []
    for i, iface in enumerate(ifaces, 1):
        rows.append((i, str(iface.name), str(getattr(iface, "description", "") or ""),
                     str(getattr(iface, "ip", "") or "")))
    return rows


def resolve_interface(text: str | None):
    """Turn what the user typed (a number, or part of a name) into a scapy interface object."""
    if text is None:
        return None
    from scapy.all import conf
    ifaces = list(conf.ifaces.values())
    if text.isdigit() and 1 <= int(text) <= len(ifaces):
        return ifaces[int(text) - 1]
    wanted = text.lower()
    exact = [i for i in ifaces if str(i.name).lower() == wanted]
    if len(exact) == 1:
        return exact[0]
    part = [i for i in ifaces
            if wanted in str(i.name).lower() or wanted in str(getattr(i, "description", "") or "").lower()]
    if len(part) == 1:
        return part[0]
    if not part:
        raise LiveCaptureError(f"No adapter matches '{text}'. Run: pydpi interfaces")
    names = ", ".join(str(i.name) for i in part)
    raise LiveCaptureError(f"'{text}' matches several adapters ({names}). Use the number from: pydpi interfaces")


def scapy_to_raw(pkt) -> tuple[bytes, int]:
    """Convert a scapy packet to (raw bytes, pcap link type)."""
    name = type(pkt).__name__
    raw = bytes(pkt)
    linktype = _LINKTYPES.get(name)
    if linktype is None:                       # unknown wrapper: fall back to the IP layer itself
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        for layer in (IP, IPv6):
            if pkt.haslayer(layer):
                return bytes(pkt[layer]), LINKTYPE_RAW
        return raw, 1
    return raw, linktype


# --------------------------------------------------------------------------- monitor
class LiveMonitor:
    """Feeds packets to a PacketProcessor and renders a live dashboard from its state."""

    def __init__(self, rules: RuleSet, signatures: SignatureDB, label: str = "live",
                 save_path: str | Path | None = None):
        self.rules = rules
        self.proc = PacketProcessor(rules, signatures, linktype=1)
        self.label = label
        self.save_path = Path(save_path) if save_path else None
        self._lock = threading.Lock()
        self._t0 = time.monotonic()
        self._fh = None
        self._writer = None
        self._save_linktype: int | None = None

    # ---- input ----
    def feed(self, ts: float, raw: bytes, linktype: int) -> bool:
        with self._lock:
            self.proc.linktype = linktype
            forward = self.proc.process(ts, raw)
            if self.save_path:
                self._save(ts, raw, linktype)
            return forward

    def feed_scapy(self, pkt) -> None:
        try:
            raw, linktype = scapy_to_raw(pkt)
            self.feed(float(pkt.time), raw, linktype)
        except Exception:  # noqa: BLE001 - one bad packet must never stop the capture
            log.debug("could not process packet", exc_info=True)

    def _save(self, ts: float, raw: bytes, linktype: int) -> None:
        if self._writer is None:
            self._fh = open(self.save_path, "wb")  # noqa: SIM115 - closed in close()
            self._writer = dpkt.pcap.Writer(self._fh, linktype=linktype)
            self._save_linktype = linktype
        if linktype == self._save_linktype:
            self._writer.writepkt(raw, ts)

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.close()
                self._fh = self._writer = None

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._t0

    # ---- output ----
    def render(self):
        with self._lock:
            elapsed = max(self.elapsed, 1e-9)
            st = self.proc.stats
            total_pk, total_by = st.total_packets, st.total_bytes
            dropped, n_flows = st.dropped, len(self.proc.flows)
            apps: dict[str, list[int]] = {}
            for f in self.proc.flows.values():
                row = apps.setdefault(f.app, [0, 0, 0, 0])
                row[0] += 1
                row[1] += f.packets
                row[2] += f.bytes
                row[3] += 1 if f.blocked else 0
            recent = [(f.sni, f.app, f.method, f.blocked) for f in
                      heapq.nlargest(10, (f for f in self.proc.flows.values() if f.sni), key=lambda f: f.last_ts)]

        head = Table.grid(padding=(0, 3))
        head.add_row("Source", self.label, "Packets", f"{total_pk:,}")
        head.add_row("Running", f"{elapsed:,.0f} s", "Bytes", _human(total_by))
        head.add_row("Rate", f"{total_pk / elapsed:,.0f} pkt/s", "Flows", f"{n_flows:,}")
        if self.rules:
            head.add_row("Rules", "monitor mode", "Would drop", f"[red]{dropped:,}[/] packets")

        t_apps = Table(title="Applications (live)", expand=True)
        for col, just in (("Application", "left"), ("Flows", "right"), ("Packets", "right"),
                          ("Traffic", "right"), ("", "left")):
            t_apps.add_column(col, justify=just)
        for app, (fl, pk, by, bl) in sorted(apps.items(), key=lambda kv: -kv[1][1])[:8]:
            t_apps.add_row(app, str(fl), f"{pk:,}", _human(by), "[red]WOULD BLOCK[/]" if bl else "")

        t_dom = Table(title="Latest websites seen", expand=True)
        for col in ("Website", "Application", "How"):
            t_dom.add_column(col)
        for sni, app, method, blocked in recent:
            t_dom.add_row(sni, f"[red]{app}[/]" if blocked else app, method)

        parts = [head, t_apps, t_dom]
        if total_pk == 0 and elapsed > 5:
            parts.append(Panel("[yellow]No packets yet. Open a website in your browser. If still nothing, "
                               "choose another adapter: run 'pydpi interfaces' and use '-i NUMBER'.[/]"))
        return Panel(Group(*parts), title="[bold green]PyDPI LIVE[/]  (Ctrl+C to stop)", border_style="green")

    def finish(self) -> Report:
        self.close()
        with self._lock:
            flows = self.proc.finish()
            return Report(stats=self.proc.stats, flows=flows, worker_packets=[self.proc.processed],
                          elapsed=self.elapsed, input_path=self.label,
                          output_path=str(self.save_path) if self.save_path else None,
                          rules_summary=self.rules.describe())


# --------------------------------------------------------------------------- sources
def sniff_source(monitor: LiveMonitor, interface=None, seconds: int | None = None, count: int | None = None,
                 bpf: str | None = None, stop: threading.Event | None = None) -> None:
    """Capture from a real adapter until time/count/stop/Ctrl+C."""
    try:
        from scapy.all import sniff
    except Exception as exc:  # noqa: BLE001
        raise LiveCaptureError(f"{exc}\n{NPCAP_HELP}") from exc

    kwargs: dict = {"prn": monitor.feed_scapy, "store": False}
    if interface is not None:
        kwargs["iface"] = interface
    if seconds:
        kwargs["timeout"] = seconds
    if count:
        kwargs["count"] = count
    if bpf:
        kwargs["filter"] = bpf
    if stop is not None:
        kwargs["stop_filter"] = lambda _pkt: stop.is_set()
    try:
        sniff(**kwargs)
    except KeyboardInterrupt:
        raise
    except PermissionError as exc:
        raise LiveCaptureError(f"Permission denied.\n{NPCAP_HELP}") from exc
    except Exception as exc:  # noqa: BLE001 - scapy raises many different error types
        raise LiveCaptureError(f"{exc}\n{NPCAP_HELP}") from exc


def replay_source(monitor: LiveMonitor, path: str | Path, delay: float = 0.02) -> None:
    """Demo mode: feed a saved capture through the live dashboard, as if it were arriving now."""
    reader, linktype, fh = open_capture(path)
    try:
        for ts, buf in reader:
            monitor.feed(ts, buf, linktype)
            if delay:
                time.sleep(delay)
    finally:
        fh.close()


def run_live(monitor: LiveMonitor, source, console, refresh: int = 4) -> None:
    """Run `source()` while a live dashboard is shown. Ctrl+C ends the run cleanly."""
    from rich.live import Live
    try:
        with Live(get_renderable=monitor.render, console=console, refresh_per_second=refresh):
            source()
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped by user.[/]")
