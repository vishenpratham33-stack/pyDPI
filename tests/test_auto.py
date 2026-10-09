import os
import shutil
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from pydpi.auto import FAIL, OK, ProbeResult, choose_interface, make_report_dir, print_checks, run_doctor, save_results
from pydpi.cli import app
from pydpi.engine import DPIEngine
from pydpi.synth import generate_pcap


class FakeIface:
    def __init__(self, name, description="", ip=""):
        self.name, self.description, self.ip = name, description, ip


def test_choose_interface_prefers_busiest_real_adapter():
    wifi, eth, lo = FakeIface("wlan0", "Wi-Fi", "10.0.0.5"), FakeIface("eth0"), FakeIface("lo", ip="127.0.0.1")
    results = [ProbeResult(lo, 900), ProbeResult(eth, 5), ProbeResult(wifi, 120)]
    assert choose_interface(results) is wifi          # loopback ignored although it is the busiest


def test_choose_interface_falls_back_to_loopback_then_none():
    lo = FakeIface("lo")
    assert choose_interface([ProbeResult(lo, 10), ProbeResult(FakeIface("eth0"), 0)]) is lo
    assert choose_interface([ProbeResult(lo, 0), ProbeResult(FakeIface("eth0"), 0, "boom")]) is None


def test_windows_loopback_adapter_is_recognised():
    npcap_lo = FakeIface("{GUID}", "Npcap Loopback Adapter")
    wifi = FakeIface("{GUID2}", "Intel Wi-Fi")
    assert choose_interface([ProbeResult(npcap_lo, 50), ProbeResult(wifi, 3)]) is wifi


def test_doctor_without_capture_checks():
    checks = run_doctor(need_capture=False)
    names = {c.name for c in checks}
    assert "Python version" in names and "Application signatures" in names
    assert all(c.status == OK for c in checks)


def test_print_checks_reports_failure():
    from rich.console import Console

    from pydpi.auto import Check
    ok = print_checks([Check("x", FAIL, "bad", "do this")], Console(file=open(os.devnull, "w")))
    assert ok is False


def test_report_dir_is_git_ignored(tmp_path):
    folder = make_report_dir(tmp_path / "pydpi_reports")
    assert folder.is_dir()
    assert (tmp_path / "pydpi_reports" / ".gitignore").read_text().strip() == "*"
    if shutil.which("git"):
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        (folder / "report.json").write_text("{}")
        out = subprocess.run(["git", "status", "--short"], cwd=tmp_path, capture_output=True, text=True).stdout
        assert out.strip() == ""                       # nothing inside would ever be uploaded


def test_save_results_writes_three_files(tmp_path):
    demo = tmp_path / "d.pcap"
    generate_pcap(demo)
    files = save_results(DPIEngine().run(demo), tmp_path)
    assert [f.name for f in files] == ["report.json", "flows.csv", "summary.txt"]
    assert "Application breakdown" in    files[2].read_text(encoding="utf-8")


def test_cli_auto_demo_mode(tmp_path):
    demo = tmp_path / "d.pcap"
    generate_pcap(demo)
    out = tmp_path / "reports"
    result = CliRunner().invoke(app, ["auto", "--replay", str(demo), "--delay", "0", "--out-dir", str(out),
                                      "--block-app", "YouTube"])
    assert result.exit_code == 0, result.output
    assert "Step 4 of 4" in result.output
    run_dirs = [d for d in out.iterdir() if d.is_dir()]
    assert len(run_dirs) == 1 and (run_dirs[0] / "summary.txt").exists()


def test_cli_doctor_runs():
    assert CliRunner().invoke(app, ["doctor"]).exit_code in (0, 1)


@pytest.mark.skipif(not sys.platform.startswith("linux") or getattr(os, "geteuid", lambda: 1)() != 0,
                    reason="probing real adapters needs Linux and root")
def test_probe_runs_on_real_adapters():
    from pydpi.auto import probe_interfaces
    results = probe_interfaces(0.5)
    assert results and all(isinstance(r.packets, int) for r in results)
