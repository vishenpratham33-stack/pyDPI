import http.server
import os
import socket
import socketserver
import sys
import threading
import time

import dpkt
import pytest
from typer.testing import CliRunner

from pydpi.cli import app
from pydpi.engine import DPIEngine, open_capture
from pydpi.live import LiveCaptureError, LiveMonitor, scapy_to_raw, sniff_source
from pydpi.rules import RuleSet
from pydpi.signatures import SignatureDB
from pydpi.synth import generate_pcap


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    path = tmp_path_factory.mktemp("live") / "demo.pcap"
    generate_pcap(path)
    return path


def _summary(report):
    return sorted((f.app, f.sni, f.blocked, f.packets) for f in report.flows)


def test_monitor_matches_offline_engine(demo):
    """Feeding packets one by one (as live capture does) must give the same result as a file run."""
    rules = RuleSet.build(apps=["YouTube"], domains=["tiktok"])
    offline = DPIEngine(rules).run(demo)
    monitor = LiveMonitor(rules, SignatureDB.load(), "test")
    reader, linktype, fh = open_capture(demo)
    with fh:
        for ts, buf in reader:
            monitor.feed(ts, buf, linktype)
    live = monitor.finish()
    assert _summary(live) == _summary(offline)
    assert live.stats == offline.stats


def test_scapy_packets_are_converted(demo):
    from scapy.layers.l2 import Ether
    monitor = LiveMonitor(RuleSet(), SignatureDB.load(), "scapy-test")
    reader, _, fh = open_capture(demo)
    with fh:
        for ts, buf in reader:
            pkt = Ether(buf)
            pkt.time = ts
            raw, linktype = scapy_to_raw(pkt)
            assert linktype == 1 and raw == buf
            monitor.feed_scapy(pkt)
    report = monitor.finish()
    assert any(f.app == "YouTube" for f in report.flows)


def test_save_writes_a_readable_capture(demo, tmp_path):
    out = tmp_path / "live_saved.pcap"
    monitor = LiveMonitor(RuleSet(), SignatureDB.load(), "save-test", out)
    reader, linktype, fh = open_capture(demo)
    with fh:
        for ts, buf in reader:
            monitor.feed(ts, buf, linktype)
    report = monitor.finish()
    with open(out, "rb") as f:
        assert sum(1 for _ in dpkt.pcap.Reader(f)) == report.stats.total_packets


def test_render_works_before_and_after_packets(demo):
    monitor = LiveMonitor(RuleSet.build(apps=["YouTube"]), SignatureDB.load(), "render-test")
    assert monitor.render() is not None          # empty state must not crash
    reader, linktype, fh = open_capture(demo)
    with fh:
        for ts, buf in reader:
            monitor.feed(ts, buf, linktype)
    assert monitor.render() is not None


def test_cli_replay_demo_mode(demo):
    result = CliRunner().invoke(app, ["live", "--replay", str(demo), "--delay", "0", "--block-app", "YouTube"])
    assert result.exit_code == 0, result.output
    assert "Application breakdown" in result.output
    assert "Nothing is stopped" in result.output     # monitor-mode warning is shown


def test_bad_adapter_gives_friendly_error():
    result = CliRunner().invoke(app, ["live", "-i", "no-such-adapter-xyz", "--seconds", "1"])
    assert result.exit_code == 1
    assert "pydpi interfaces" in result.output


def test_interfaces_command_runs():
    result = CliRunner().invoke(app, ["interfaces"])
    assert result.exit_code in (0, 1)               # 1 only if the capture driver is missing


@pytest.mark.skipif(not sys.platform.startswith("linux") or getattr(os, "geteuid", lambda: 1)() != 0,
                    reason="real capture test needs Linux and root")
def test_real_capture_on_loopback():
    """End-to-end: sniff real packets on the loopback adapter while a local web server is used."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def client():
        time.sleep(1.0)
        s = socket.create_connection(("127.0.0.1", port))
        s.sendall(b"GET / HTTP/1.1\r\nHost: www.github.com\r\n\r\n")
        s.recv(100)
        s.close()

    threading.Thread(target=client, daemon=True).start()
    monitor = LiveMonitor(RuleSet(), SignatureDB.load(), "loopback")
    try:
        sniff_source(monitor, "lo", seconds=3)
    except LiveCaptureError as exc:
        pytest.skip(f"capture not available here: {exc}")
    finally:
        server.shutdown()
    report = monitor.finish()
    assert any(f.sni == "www.github.com" and f.app == "GitHub" for f in report.flows)
