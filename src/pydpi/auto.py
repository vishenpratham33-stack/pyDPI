"""One-command workflow helpers: environment checks ("doctor"), adapter auto-detection, result folders.

These functions exist so that a beginner can run ONE command and get a result, without knowing
which adapter to pick or why a capture fails. Every failure comes with a plain-language fix.
"""

from __future__ import annotations

import importlib
import io
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from pydpi.report import print_report, write_csv, write_json
from pydpi.signatures import SignatureDB

OK, WARN, FAIL = "OK", "WARN", "FAIL"


@dataclass
class Check:
    name: str
    status: str            # OK / WARN / FAIL
    detail: str
    fix: str = ""


@dataclass
class ProbeResult:
    iface: object
    packets: int
    error: str | None = None

    @property
    def name(self) -> str:
        return str(getattr(self.iface, "name", self.iface))

    @property
    def label(self) -> str:
        desc = str(getattr(self.iface, "description", "") or "")
        return desc if desc and desc != self.name else self.name


# ----------------------------------------------------------------------------- doctor
def is_admin() -> bool:
    try:
        if sys.platform.startswith("win"):
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        import os
        return os.geteuid() == 0
    except Exception:  # noqa: BLE001
        return False


def run_doctor(need_capture: bool = True) -> list[Check]:
    checks: list[Check] = []
    v = sys.version_info
    checks.append(Check("Python version", OK if v >= (3, 10) else FAIL, f"{v.major}.{v.minor}.{v.micro}",
                        "Install Python 3.10 or newer from python.org and tick 'Add python.exe to PATH'."))

    for module, label in (("dpkt", "dpkt"), ("cryptography", "cryptography"), ("yaml", "PyYAML"),
                          ("rich", "rich"), ("typer", "typer"), ("scapy", "scapy")):
        try:
            importlib.import_module(module)
            checks.append(Check(f"Library: {label}", OK, "installed"))
        except ImportError:
            checks.append(Check(f"Library: {label}", FAIL, "missing",
                                'Run:  pip install -e ".[dev]"   (inside the project folder, venv active)'))

    try:
        n = len(SignatureDB.load())
        checks.append(Check("Application signatures", OK, f"{n} domain signatures loaded"))
    except Exception as exc:  # noqa: BLE001
        checks.append(Check("Application signatures", FAIL, str(exc), "Reinstall the project with pip install -e ."))

    if not need_capture:
        return checks

    admin = is_admin()
    checks.append(Check("Administrator / root rights", OK if admin else WARN,
                        "yes" if admin else "no",
                        "If capturing fails with 'permission denied', run VS Code (or the terminal) as administrator; "
                        "on Linux/macOS use sudo."))
    checks.append(_capture_driver_check())
    checks.append(_adapter_check())
    return checks


def _capture_driver_check() -> Check:
    try:
        from scapy.all import conf
    except Exception as exc:  # noqa: BLE001
        return Check("Capture driver", FAIL, str(exc), "Reinstall scapy: pip install scapy")
    if sys.platform.startswith("win"):
        if not getattr(conf, "use_pcap", False):
            return Check("Capture driver", FAIL, "Npcap not found",
                         "Install Npcap from https://npcap.com (it is also installed with Wireshark), "
                         "then restart VS Code.")
        return Check("Capture driver", OK, "Npcap")
    return Check("Capture driver", OK, "libpcap" if getattr(conf, "use_pcap", False) else "raw sockets")


def _adapter_check() -> Check:
    try:
        from pydpi.live import list_interfaces
        rows = list_interfaces()
    except Exception as exc:  # noqa: BLE001
        return Check("Network adapters", FAIL, str(exc).splitlines()[0], "Check the capture driver above.")
    if not rows:
        return Check("Network adapters", FAIL, "none found", "Check the capture driver above.")
    return Check("Network adapters", OK, f"{len(rows)} found")


def print_checks(checks: list[Check], console: Console) -> bool:
    """Show the checks. Returns True when nothing failed."""
    t = Table(title="Setup check")
    for col in ("Check", "Result", "Details"):
        t.add_column(col)
    colour = {OK: "green", WARN: "yellow", FAIL: "red"}
    for c in checks:
        t.add_row(c.name, f"[{colour[c.status]}]{c.status}[/]", c.detail)
    console.print(t)
    for c in checks:
        if c.status != OK and c.fix:
            console.print(f"[{colour[c.status]}]{c.status}:[/] {c.name} - {c.fix}")
    return not any(c.status == FAIL for c in checks)


# ----------------------------------------------------------------------------- adapters
def _is_loopback(result: ProbeResult) -> bool:
    text = f"{result.name} {result.label}".lower()
    return result.name == "lo" or "loopback" in text


def choose_interface(results: list[ProbeResult]):
    """Pick the adapter that saw the most packets. Loopback is used only if nothing else has traffic."""
    usable = [r for r in results if r.error is None and r.packets > 0]
    real = [r for r in usable if not _is_loopback(r)]
    pool = real or usable
    if not pool:
        return None
    return max(pool, key=lambda r: (r.packets, bool(getattr(r.iface, "ip", "")))).iface


def probe_interfaces(seconds: float = 3.0) -> list[ProbeResult]:
    """Listen on every adapter at the same time for a few seconds and count the packets."""
    from scapy.all import AsyncSniffer, conf

    running = []
    results: list[ProbeResult] = []
    for iface in conf.ifaces.values():
        counter = [0]

        def count(_pkt, counter=counter):
            counter[0] += 1

        try:
            sniffer = AsyncSniffer(iface=iface, prn=count, store=False)
            sniffer.start()
            running.append((iface, sniffer, counter))
        except Exception as exc:  # noqa: BLE001
            results.append(ProbeResult(iface, 0, str(exc)))
    time.sleep(seconds)
    for iface, sniffer, counter in running:
        try:
            sniffer.stop()
        except Exception:  # noqa: BLE001 - adapters that failed to open raise here
            pass
        results.append(ProbeResult(iface, counter[0]))
    return results


# ----------------------------------------------------------------------------- results
def make_report_dir(base: str | Path) -> Path:
    """Create <base>/<timestamp>/ and make Git ignore everything inside <base>.

    The nested .gitignore contains a single '*', so captured websites can never be uploaded by accident.
    """
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    (base / ".gitignore").write_text("*\n", encoding="utf-8")
    folder = base / datetime.now().strftime("%Y%m%d_%H%M%S")
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def save_results(report, folder: Path, top: int = 15) -> list[Path]:
    """Write report.json, flows.csv and a plain-text summary.txt into the folder."""
    files = [folder / "report.json", folder / "flows.csv", folder / "summary.txt"]
    write_json(report, files[0])
    write_csv(report, files[1])
    buf = io.StringIO()
    text_console = Console(file=buf, width=110, force_terminal=False, color_system=None, record=True)
    print_report(report, text_console, top)
    files[2].write_text(buf.getvalue(), encoding="utf-8")
    return files
