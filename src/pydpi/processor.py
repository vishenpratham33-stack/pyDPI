"""PacketProcessor: the heart of the engine.

For every packet it: parses headers -> finds/creates the flow -> (if the flow is
not classified yet) looks inside the payload -> applies blocking rules -> returns
a forward/drop verdict. One instance owns its own flow table, so multiple
instances can run in parallel processes without any locking.
"""

from __future__ import annotations

import logging

import dpkt

from pydpi import quic, tls
from pydpi.buffers import StreamBuffer
from pydpi.http_host import extract_http_host
from pydpi.models import (
    PORT_HINTS,
    PROTO_TCP,
    PROTO_UDP,
    Flow,
    FlowKey,
    ParsedPacket,
    Stats,
)
from pydpi.parser import MalformedPacket, parse_packet
from pydpi.rules import RuleSet
from pydpi.signatures import SignatureDB

log = logging.getLogger(__name__)

DNS_PORT = 53
QUIC_PORT = 443


class PacketProcessor:
    def __init__(self, rules: RuleSet, signatures: SignatureDB, linktype: int = 1):
        self.rules = rules
        self.signatures = signatures
        self.linktype = linktype
        self.flows: dict[FlowKey, Flow] = {}
        self.stats = Stats()
        self.processed = 0

    # ------------------------------------------------------------------ API
    def process(self, ts: float, data: bytes) -> bool:
        """Return True to forward the packet, False to drop it."""
        self.processed += 1
        st = self.stats
        st.total_packets += 1
        st.total_bytes += len(data)

        try:
            pkt = parse_packet(ts, data, self.linktype)
        except MalformedPacket as exc:
            st.malformed_packets += 1
            log.debug("malformed packet: %s", exc)
            st.forwarded += 1
            return True

        if pkt.ip_version == 0:
            st.non_ip_packets += 1
            st.forwarded += 1
            return True

        if pkt.proto == PROTO_TCP:
            st.tcp_packets += 1
        elif pkt.proto == PROTO_UDP:
            st.udp_packets += 1
        else:
            st.other_packets += 1

        flow = self._flow_for(pkt)
        flow.packets += 1
        flow.bytes += len(data)
        flow.last_ts = ts

        is_dns = flow.method == "dns"
        if pkt.payload and not flow.classified and flow.inspect_budget > 0:
            from_client = (pkt.src, pkt.sport) == flow.client
            if from_client or is_dns:
                self._inspect(flow, pkt)

        # DNS is judged per query (a socket can ask for many names);
        # everything else is judged per flow, and the verdict is sticky.
        ip_blocked = bool(flow.block_reason and flow.block_reason.startswith("ip:"))
        if is_dns and pkt.payload and pkt.dport == DNS_PORT and not ip_blocked:
            reason = self.rules.check(flow.app, flow.sni)
            drop = reason is not None
            if drop:
                flow.blocked, flow.block_reason = True, reason
        else:
            drop = flow.blocked

        if drop:
            flow.dropped_packets += 1
            st.dropped += 1
            return False
        st.forwarded += 1
        return True

    def finish(self) -> list[Flow]:
        for f in self.flows.values():
            f.release_inspection_state()
        return list(self.flows.values())

    # ------------------------------------------------------------- internals
    def _flow_for(self, pkt: ParsedPacket) -> Flow:
        key = pkt.flow_key
        flow = self.flows.get(key)
        if flow is not None:
            return flow
        client, server = (pkt.src, pkt.sport), (pkt.dst, pkt.dport)
        flow = Flow(key=key, client=client, server=server, proto=pkt.proto,
                    first_ts=pkt.ts, last_ts=pkt.ts)
        hint = PORT_HINTS.get(pkt.dport) if pkt.proto in (PROTO_TCP, PROTO_UDP) else None
        if hint:
            flow.app, flow.method = hint, "port"
        if pkt.proto == PROTO_UDP and DNS_PORT in (pkt.dport, pkt.sport):
            flow.app, flow.method = "DNS", "dns"
            flow.inspect_budget = 1_000_000          # many queries per socket
        # IP rules are decided once, when the flow is created.
        reason = self.rules.check_ip(pkt.src) or self.rules.check_ip(pkt.dst)
        if reason:
            flow.blocked, flow.block_reason = True, reason
            flow.classified = True
        self.flows[key] = flow
        return flow

    def _inspect(self, flow: Flow, pkt: ParsedPacket) -> None:
        if pkt.proto == PROTO_TCP:
            self._inspect_tcp(flow, pkt)
        elif pkt.proto == PROTO_UDP:
            if flow.method == "dns":
                self._inspect_dns(flow, pkt)
            else:
                self._inspect_quic(flow, pkt)

    # ---- TCP: TLS ClientHello (with reassembly) or plain HTTP -------------
    def _inspect_tcp(self, flow: Flow, pkt: ParsedPacket) -> None:
        payload = pkt.payload
        if flow.stream is None and not tls.looks_like_tls_handshake(payload):
            flow.inspect_budget -= 1
            host = extract_http_host(payload)
            if host:
                self._set_result(flow, "HTTP", host, "http")
            return

        # TLS: a modern ClientHello (post-quantum key shares!) often spans several segments.
        if flow.stream is None:
            flow.stream = StreamBuffer(limit=32768)
            flow.tcp_base_seq = pkt.tcp_seq
        offset = (pkt.tcp_seq - flow.tcp_base_seq) & 0xFFFFFFFF
        if offset > 0x7FFFFFFF:                       # segment before our base: ignore
            return
        flow.stream.add(offset, payload)
        flow.inspect_budget -= 1
        try:
            hello = tls.parse_tls_record(flow.stream.contiguous())
        except tls.Incomplete:
            return                                      # wait for the next segment
        except tls.ParseError:
            flow.inspect_budget = 0
            return
        self._apply_hello(flow, hello, "tls", fallback_app="HTTPS")

    # ---- UDP/443: QUIC Initial -> decrypt -> ClientHello ------------------
    def _inspect_quic(self, flow: Flow, pkt: ParsedPacket) -> None:
        if QUIC_PORT not in (pkt.dport, pkt.sport) or not quic.is_quic_long_header(pkt.payload):
            flow.inspect_budget -= 1
            return
        if flow.app in ("Unknown", "HTTPS") or flow.method == "port":
            flow.app, flow.method = "QUIC", "quic"
        flow.inspect_budget -= 1
        try:
            chunks = quic.decrypt_client_initial(pkt.payload)
        except quic.QuicError:
            return
        if flow.stream is None:
            flow.stream = StreamBuffer(limit=32768)
        for offset, data in chunks:
            flow.stream.add(offset, data)
        try:
            hello = tls.parse_client_hello(flow.stream.contiguous())
        except tls.ParseError:
            return
        self._apply_hello(flow, hello, "quic", fallback_app="QUIC")

    # ---- UDP/53: DNS query name -------------------------------------------
    def _inspect_dns(self, flow: Flow, pkt: ParsedPacket) -> None:
        if pkt.dport != DNS_PORT:
            return
        try:
            dns = dpkt.dns.DNS(pkt.payload)
        except (dpkt.UnpackError, UnicodeDecodeError, IndexError, ValueError):
            return
        if dns.qr == dpkt.dns.DNS_Q and dns.qd:
            flow.sni = dns.qd[0].name.lower().rstrip(".")
            flow.app = "DNS"

    # ---- shared result handling -------------------------------------------
    def _apply_hello(self, flow: Flow, hello: tls.ClientHello, method: str, fallback_app: str):
        flow.alpn, flow.ja3, flow.ja3_hash, flow.ech = (
            hello.alpn, hello.ja3, hello.ja3_hash, hello.ech)
        self._set_result(flow, fallback_app, hello.sni, method)

    def _set_result(self, flow: Flow, fallback_app: str, host: str | None, method: str):
        flow.sni = host
        flow.method = method
        flow.app = self.signatures.match(host) or fallback_app
        flow.release_inspection_state()
        reason = self.rules.check(flow.app, host)
        if reason and not flow.blocked:
            flow.blocked, flow.block_reason = True, reason
