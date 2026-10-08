"""Core data structures shared by the whole engine."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

# A flow key is direction-independent: (protocol, endpoint_a, endpoint_b)
# where endpoint = (packed_ip_address, port) and endpoint_a <= endpoint_b.
Endpoint = tuple[bytes, int]
FlowKey = tuple[int, Endpoint, Endpoint]

PROTO_TCP = 6
PROTO_UDP = 17

PROTO_NAMES = {PROTO_TCP: "TCP", PROTO_UDP: "UDP", 1: "ICMP", 58: "ICMPv6"}

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04

# Used only until deep inspection finds something better.
PORT_HINTS = {
    22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 123: "NTP",
    143: "IMAP", 443: "HTTPS", 465: "SMTP", 587: "SMTP", 853: "DNS-over-TLS",
    993: "IMAP", 3389: "RDP",
}
UNKNOWN = "Unknown"


def ip_to_str(packed: bytes) -> str:
    family = socket.AF_INET if len(packed) == 4 else socket.AF_INET6
    return socket.inet_ntop(family, packed)


@dataclass(slots=True)
class ParsedPacket:
    """Everything the engine needs from one raw packet."""

    ts: float
    wire_len: int
    ip_version: int          # 4 or 6, 0 if not IP
    src: bytes = b""
    dst: bytes = b""
    proto: int = 0
    sport: int = 0
    dport: int = 0
    tcp_flags: int = 0
    tcp_seq: int = 0
    payload: bytes = b""

    @property
    def flow_key(self) -> FlowKey:
        a: Endpoint = (self.src, self.sport)
        b: Endpoint = (self.dst, self.dport)
        return (self.proto, a, b) if a <= b else (self.proto, b, a)


@dataclass(slots=True)
class Flow:
    """State kept for one bidirectional connection."""

    key: FlowKey
    client: Endpoint            # whoever sent the first packet we saw
    server: Endpoint
    proto: int
    first_ts: float
    last_ts: float
    app: str = UNKNOWN
    sni: str | None = None      # TLS SNI, HTTP Host, QUIC SNI or DNS query name
    alpn: tuple[str, ...] = ()
    ja3: str | None = None
    ja3_hash: str | None = None
    ech: bool = False           # Encrypted Client Hello: SNI intentionally hidden
    method: str = ""            # how we classified it: tls / quic / http / dns / port
    packets: int = 0
    bytes: int = 0
    dropped_packets: int = 0
    blocked: bool = False
    block_reason: str | None = None
    # --- internal inspection state (cleared once classification is done) ---
    inspect_budget: int = 8
    classified: bool = False
    tcp_base_seq: int | None = None
    stream: object | None = None   # StreamBuffer

    @property
    def client_str(self) -> str:
        return f"{ip_to_str(self.client[0])}:{self.client[1]}"

    @property
    def server_str(self) -> str:
        return f"{ip_to_str(self.server[0])}:{self.server[1]}"

    def release_inspection_state(self) -> None:
        self.stream = None
        self.tcp_base_seq = None
        self.classified = True


@dataclass(slots=True)
class Stats:
    total_packets: int = 0
    total_bytes: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    other_packets: int = 0
    non_ip_packets: int = 0
    malformed_packets: int = 0
    forwarded: int = 0
    dropped: int = 0

    def merge(self, other: Stats) -> None:
        for name in self.__slots__:
            setattr(self, name, getattr(self, name) + getattr(other, name))


@dataclass
class AppRow:
    app: str
    packets: int = 0
    bytes: int = 0
    flows: int = 0
    blocked_flows: int = 0
    dropped_packets: int = 0


@dataclass
class Report:
    stats: Stats
    flows: list[Flow]
    worker_packets: list[int] = field(default_factory=list)
    elapsed: float = 0.0
    input_path: str = ""
    output_path: str | None = None
    rules_summary: list[str] = field(default_factory=list)

    def app_breakdown(self) -> list[AppRow]:
        rows: dict[str, AppRow] = {}
        for f in self.flows:
            row = rows.setdefault(f.app, AppRow(f.app))
            row.packets += f.packets
            row.bytes += f.bytes
            row.flows += 1
            row.dropped_packets += f.dropped_packets
            if f.blocked:
                row.blocked_flows += 1
        return sorted(rows.values(), key=lambda r: r.packets, reverse=True)

    def domains(self) -> dict[str, str]:
        """Detected domain -> application (first one wins)."""
        found: dict[str, str] = {}
        for f in self.flows:
            if f.sni and f.sni not in found:
                found[f.sni] = f.app
        return dict(sorted(found.items()))
