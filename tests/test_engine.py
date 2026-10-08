import filecmp

import dpkt
import pytest

from pydpi.engine import DPIEngine
from pydpi.report import write_csv, write_json
from pydpi.rules import RuleSet
from pydpi.synth import generate_pcap


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    path = tmp_path_factory.mktemp("pcap") / "demo.pcap"
    generate_pcap(path)
    return path


def apps_by_host(report, method=None):
    return {f.sni: f.app for f in report.flows if f.sni and (method is None or f.method == method)}


def test_classification(demo):
    rep = DPIEngine().run(demo)
    got = apps_by_host(rep)
    assert got["www.youtube.com"] == "YouTube"
    assert got["www.facebook.com"] == "Facebook"
    assert got["github.com"] == "GitHub"
    assert got["notyoutube.example.org"] == "HTTPS"       # not a false positive
    assert got["example.com"] == "HTTP"
    assert got["www.instagram.com"] == "Instagram"         # ClientHello spanned 3+ TCP segments
    # decrypted from QUIC, with the ClientHello split over 2 datagrams
    assert apps_by_host(rep, "quic")["www.tiktok.com"] == "TikTok"
    assert rep.stats.total_packets == sum(f.packets for f in rep.flows) + rep.stats.non_ip_packets


def test_quic_flows_are_labelled(demo):
    rep = DPIEngine().run(demo)
    quic_flows = [f for f in rep.flows if f.method == "quic"]
    assert len(quic_flows) == 2


def test_ech_flow_has_flag(demo):
    rep = DPIEngine().run(demo)
    assert any(f.ech for f in rep.flows)


def test_ipv6_flow(demo):
    rep = DPIEngine().run(demo)
    assert any(f.app == "YouTube" and ":" in f.client_str.split("]")[0] and "2001:db8" in f.client_str
               for f in rep.flows)


def test_blocking_drops_whole_flow_both_directions(demo, tmp_path):
    out = tmp_path / "out.pcap"
    rep = DPIEngine(RuleSet.build(apps=["YouTube"])).run(demo, out)
    yt = [f for f in rep.flows if f.app == "YouTube"]
    assert yt and all(f.blocked for f in yt)
    # the packets before the ClientHello (SYN, SYN-ACK, ACK) are forwarded; the rest dropped
    tcp_yt = next(f for f in yt if f.method == "tls")
    assert 0 < tcp_yt.dropped_packets < tcp_yt.packets
    with open(out, "rb") as fh:
        written = sum(1 for _ in dpkt.pcap.Reader(fh))
    assert written == rep.stats.forwarded
    assert rep.stats.forwarded + rep.stats.dropped == rep.stats.total_packets


def test_ip_rule_and_dns_domain_rule(demo):
    rep = DPIEngine(RuleSet.build(ips=["192.168.1.50"], domains=["wikipedia.org"])).run(demo)
    assert any(f.block_reason and f.block_reason.startswith("ip:") for f in rep.flows)
    dns = [f for f in rep.flows if f.method == "dns" and f.sni == "www.wikipedia.org"]
    assert dns and dns[0].blocked


def test_parallel_matches_single(demo, tmp_path):
    rules = RuleSet.build(apps=["YouTube"], domains=["tiktok"], ips=["192.168.1.50"])
    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    r1 = DPIEngine(rules, workers=1).run(demo, a)
    r3 = DPIEngine(rules, workers=3).run(demo, b)
    assert filecmp.cmp(a, b, shallow=False)               # byte-identical output
    assert r1.stats == r3.stats
    assert sum(r3.worker_packets) == r1.stats.total_packets

    def key(f):
        return (f.client, f.server, f.proto)

    assert [(f.app, f.sni, f.blocked) for f in sorted(r1.flows, key=key)] == \
           [(f.app, f.sni, f.blocked) for f in sorted(r3.flows, key=key)]


def test_exports(demo, tmp_path):
    rep = DPIEngine().run(demo)
    write_json(rep, tmp_path / "r.json")
    write_csv(rep, tmp_path / "f.csv")
    assert (tmp_path / "r.json").stat().st_size > 100
    assert len((tmp_path / "f.csv").read_text().splitlines()) == len(rep.flows) + 1


def test_corrupt_packets_do_not_crash(tmp_path):
    p = tmp_path / "bad.pcap"
    with open(p, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        w.writepkt(b"\x00" * 5, 1.0)
        w.writepkt(b"\xff" * 14 + b"\x08\x00" + b"\x45\x00\x00", 2.0)   # truncated IPv4
        w.writepkt(b"", 3.0)
    rep = DPIEngine().run(p)
    assert rep.stats.total_packets == 3 and rep.stats.dropped == 0


def test_not_a_pcap(tmp_path):
    p = tmp_path / "x.pcap"
    p.write_bytes(b"this is not a capture file")
    with pytest.raises(ValueError):
        DPIEngine().run(p)
