"""Build synthetic captures: TLS, QUIC, HTTP and DNS traffic for demos and tests."""

from __future__ import annotations

import os
import random
import socket
import struct
from pathlib import Path

import dpkt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pydpi import quic

MAC_A, MAC_B = b"\x00\x11\x22\x33\x44\x55", b"\xaa\xbb\xcc\xdd\xee\xff"


# ------------------------------------------------------------------ TLS
def build_client_hello(sni: str | None, alpn=("h2", "http/1.1"), grease: bool = True,
                       ech: bool = False, pad_to: int = 0, rng: random.Random | None = None) -> bytes:
    """Return a ClientHello *handshake message* (no record header)."""
    rng = rng or random.Random(1)

    def ext(t: int, data: bytes) -> bytes:
        return struct.pack("!HH", t, len(data)) + data

    g = 0x0A0A if grease else None
    ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
    if g:
        ciphers.insert(0, g)
    exts = b""
    if g:
        exts += ext(g, b"")
    if sni is not None:
        name = sni.encode()
        entry = b"\x00" + struct.pack("!H", len(name)) + name
        exts += ext(0, struct.pack("!H", len(entry)) + entry)
    groups = [29, 23, 24]
    exts += ext(10, struct.pack("!H", 2 * len(groups)) + b"".join(struct.pack("!H", x) for x in groups))
    exts += ext(11, b"\x01\x00")
    if alpn:
        protos = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
        exts += ext(16, struct.pack("!H", len(protos)) + protos)
    exts += ext(43, b"\x04\x03\x04\x03\x03")
    if ech:
        exts += ext(0xFE0D, b"\x00" * 16)
    if pad_to:
        exts += ext(21, b"\x00" * pad_to)       # padding extension: makes the hello span segments
    body = (b"\x03\x03" + bytes(rng.getrandbits(8) for _ in range(32))
            + b"\x00"                                       # empty session id
            + struct.pack("!H", 2 * len(ciphers)) + b"".join(struct.pack("!H", c) for c in ciphers)
            + b"\x01\x00"                                   # compression: null
            + struct.pack("!H", len(exts)) + exts)
    return b"\x01" + len(body).to_bytes(3, "big") + body


def tls_record(handshake: bytes) -> bytes:
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


# ------------------------------------------------------------------ QUIC
def build_quic_initials(hello: bytes, dcid: bytes, split_at: int | None = None,
                        min_size: int = 1200) -> list[bytes]:
    """Encrypt a ClientHello into one (or two, if split_at) QUIC v1 Initial datagrams."""
    keys = quic.derive_client_initial_keys(dcid)
    pieces = [(0, hello)] if split_at is None else [(0, hello[:split_at]), (split_at, hello[split_at:])]
    datagrams = []
    for pn, (offset, data) in enumerate(pieces):
        frame = b"\x06" + quic.write_varint(offset) + quic.write_varint(len(data)) + data
        pn_len = 2
        scid = b"\x01\x02\x03\x04"
        head_no_len = (bytes([0xC0 | (pn_len - 1)]) + struct.pack("!I", quic.QUIC_V1)
                       + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"\x00")
        overhead = len(head_no_len) + 2 + pn_len + 16
        frame += b"\x00" * max(0, min_size - overhead - len(frame))
        length = pn_len + len(frame) + 16
        header = head_no_len + struct.pack("!H", 0x4000 | length) + pn.to_bytes(pn_len, "big")
        nonce = bytes(a ^ b for a, b in zip(keys.iv, pn.to_bytes(12, "big")))
        ct = AESGCM(keys.key).encrypt(nonce, frame, header)
        pn_offset = len(header) - pn_len
        packet = bytearray(header + ct)
        mask = quic.header_protection_mask(keys.hp, bytes(packet[pn_offset + 4:pn_offset + 20]))
        packet[0] ^= mask[0] & 0x0F
        for i in range(pn_len):
            packet[pn_offset + i] ^= mask[1 + i]
        datagrams.append(bytes(packet))
    return datagrams


# ------------------------------------------------------------------ L2-L4
def _ip(a: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6 if ":" in a else socket.AF_INET, a)


def frame(src: str, dst: str, sport: int, dport: int, payload: bytes = b"", proto: str = "tcp",
          flags: int = dpkt.tcp.TH_ACK, seq: int = 1000) -> bytes:
    if proto == "tcp":
        l4 = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=1, flags=flags, data=payload)
        p = dpkt.ip.IP_PROTO_TCP
    else:
        l4 = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
        l4.ulen = len(l4)
        p = dpkt.ip.IP_PROTO_UDP
    if ":" in src:
        ip = dpkt.ip6.IP6(src=_ip(src), dst=_ip(dst), nxt=p, hlim=64, data=l4)
        ip.plen = len(l4)
        etype = dpkt.ethernet.ETH_TYPE_IP6
    else:
        ip = dpkt.ip.IP(src=_ip(src), dst=_ip(dst), p=p, ttl=64, data=l4)
        etype = dpkt.ethernet.ETH_TYPE_IP
    return bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=etype, data=ip))


def tcp_session(client: str, server: str, sport: int, hello_or_data: bytes,
                dport: int = 443, mss: int | None = None, extra_data: int = 2) -> list[bytes]:
    """SYN, SYN-ACK, ACK, first data (optionally split into MSS-sized segments), then data."""
    S, F = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK
    pkts = [
        frame(client, server, sport, dport, flags=S, seq=1000),
        frame(server, client, dport, sport, flags=S | F, seq=5000),
        frame(client, server, sport, dport, flags=F, seq=1001),
    ]
    seq = 1001
    chunks = [hello_or_data] if not mss else [hello_or_data[i:i + mss] for i in range(0, len(hello_or_data), mss)]
    for c in chunks:
        pkts.append(frame(client, server, sport, dport, c, flags=F | dpkt.tcp.TH_PUSH, seq=seq))
        seq += len(c)
    for i in range(extra_data):
        pkts.append(frame(server, client, dport, sport, os.urandom(60), flags=F, seq=5001 + 60 * i))
        pkts.append(frame(client, server, sport, dport, os.urandom(40), flags=F, seq=seq + 40 * i))
    return pkts


def dns_query(client: str, resolver: str, sport: int, name: str) -> list[bytes]:
    q = dpkt.dns.DNS(id=sport & 0xFFFF, qr=dpkt.dns.DNS_Q, opcode=dpkt.dns.DNS_QUERY,
                     qd=[dpkt.dns.DNS.Q(name=name, type=dpkt.dns.DNS_A)])
    return [frame(client, resolver, sport, 53, bytes(q), proto="udp")]


SAMPLE_SITES = [
    ("192.168.1.100", "142.250.185.206", "www.youtube.com"),
    ("192.168.1.100", "157.240.1.35", "www.facebook.com"),
    ("192.168.1.101", "142.250.185.78", "www.google.com"),
    ("192.168.1.101", "140.82.112.3", "github.com"),
    ("192.168.1.102", "104.244.42.1", "twitter.com"),
    ("192.168.1.102", "23.45.67.89", "www.netflix.com"),
    ("192.168.1.50", "13.107.42.14", "www.microsoft.com"),
    ("192.168.1.103", "162.159.135.232", "discord.com"),
    ("192.168.1.103", "216.58.214.14", "notyoutube.example.org"),   # must NOT be YouTube
]


def generate_pcap(path: str | Path, seed: int = 7) -> int:
    """Write a demo capture with mixed traffic. Returns number of packets."""
    rng = random.Random(seed)
    packets: list[bytes] = []
    sport = 40000
    for client, server, host in SAMPLE_SITES:
        sport += 1
        hello = tls_record(build_client_hello(host, rng=rng))
        packets += tcp_session(client, server, sport, hello)
    # a TLS 1.3 hello that does not fit one segment (post-quantum style, padded)
    big = tls_record(build_client_hello("www.instagram.com", pad_to=2500, rng=rng))
    packets += tcp_session("192.168.1.104", "157.240.2.174", 41001, big, mss=1000)
    # hello with Encrypted Client Hello: no readable SNI
    packets += tcp_session("192.168.1.104", "104.16.1.1", 41002,
                           tls_record(build_client_hello("public.example", ech=True, rng=rng)))
    # IPv6 TLS
    packets += tcp_session("2001:db8::10", "2a00:1450:4001:81b::200e", 41003,
                           tls_record(build_client_hello("www.youtube.com", rng=rng)))
    # plain HTTP
    http = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8\r\n\r\n"
    packets += tcp_session("192.168.1.105", "93.184.216.34", 41004, http, dport=80)
    # QUIC (HTTP/3): one single-datagram, one split across two datagrams
    for i, (host, split) in enumerate([("www.youtube.com", None), ("www.tiktok.com", 150)]):
        hello = build_client_hello(host, rng=rng)
        for dg in build_quic_initials(hello, dcid=bytes(rng.getrandbits(8) for _ in range(8)),
                                      split_at=split):
            packets.append(frame("192.168.1.106", "142.250.1.1", 42000 + i, 443, dg, proto="udp"))
    # DNS
    for i, name in enumerate(["www.tiktok.com", "www.wikipedia.org", "api.github.com"]):
        packets += dns_query("192.168.1.107", "8.8.8.8", 43000 + i, name)
    # non-IP noise (ARP-like)
    packets.append(MAC_B + MAC_A + b"\x08\x06" + b"\x00" * 46)

    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        for i, p in enumerate(packets):
            w.writepkt(p, ts=1_700_000_000 + i * 0.001)
    return len(packets)
