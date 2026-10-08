"""Raw bytes -> ParsedPacket, using dpkt instead of hand-written offset math."""

from __future__ import annotations

import struct
import zlib

import dpkt

from pydpi.models import PROTO_TCP, PROTO_UDP, ParsedPacket

# pcap link-layer types we understand
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229


class MalformedPacket(ValueError):
    pass


def parse_packet(ts: float, buf: bytes, linktype: int = LINKTYPE_ETHERNET) -> ParsedPacket:
    """Parse one captured frame. Non-IP traffic returns ip_version == 0."""
    try:
        ip = _network_layer(buf, linktype)
    except (dpkt.UnpackError, struct.error, IndexError, ValueError) as exc:
        raise MalformedPacket(str(exc)) from exc

    pkt = ParsedPacket(ts=ts, wire_len=len(buf), ip_version=0)
    if ip is None:
        return pkt

    if isinstance(ip, dpkt.ip.IP):
        pkt.ip_version = 4
        pkt.proto = ip.p
        l4 = ip.data if ip.offset == 0 else b""    # later fragments have no L4 header
    else:
        pkt.ip_version = 6
        pkt.proto = ip.p            # protocol after any extension headers
        l4 = ip.data
    pkt.src, pkt.dst = ip.src, ip.dst

    if isinstance(l4, dpkt.tcp.TCP) and pkt.proto == PROTO_TCP:
        pkt.sport, pkt.dport = l4.sport, l4.dport
        pkt.tcp_flags, pkt.tcp_seq = l4.flags, l4.seq
        pkt.payload = bytes(l4.data)
    elif isinstance(l4, dpkt.udp.UDP) and pkt.proto == PROTO_UDP:
        pkt.sport, pkt.dport = l4.sport, l4.dport
        pkt.payload = bytes(l4.data)
    return pkt


def _network_layer(buf: bytes, linktype: int):
    if linktype == LINKTYPE_ETHERNET:
        eth = dpkt.ethernet.Ethernet(buf)           # also unwraps 802.1Q / QinQ tags
        data = eth.data
        return data if isinstance(data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        version = buf[0] >> 4
        return dpkt.ip.IP(buf) if version == 4 else dpkt.ip6.IP6(buf) if version == 6 else None
    if linktype == LINKTYPE_LINUX_SLL:
        data = dpkt.sll.SLL(buf).data
        return data if isinstance(data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if linktype == LINKTYPE_NULL:
        family = struct.unpack("=I", buf[:4])[0]
        body = buf[4:]
        if family == 2:
            return dpkt.ip.IP(body)
        if family in (10, 24, 28, 30):
            return dpkt.ip6.IP6(body)
        return None
    raise ValueError(f"unsupported link type {linktype}")


# ---------------------------------------------------------------------------
# Fast flow sharding for the multi-process engine.
# Needs to be cheap (runs in the reader process for every packet) and must send
# both directions of a connection to the same worker.
# ---------------------------------------------------------------------------
def shard_for(buf: bytes, linktype: int, n_workers: int) -> int:
    if n_workers == 1 or linktype != LINKTYPE_ETHERNET:
        return 0
    try:
        off = 12
        ethertype = (buf[off] << 8) | buf[off + 1]
        while ethertype in (0x8100, 0x88A8):       # skip VLAN tags
            off += 4
            ethertype = (buf[off] << 8) | buf[off + 1]
        off += 2
        if ethertype == 0x0800:
            ihl = (buf[off] & 0x0F) * 4
            proto = buf[off + 9]
            a, b = bytes(buf[off + 12:off + 16]), bytes(buf[off + 16:off + 20])
            frag = ((buf[off + 6] & 0x3F) << 8) | buf[off + 7]       # MF flag + offset
            ports = bytes(buf[off + ihl:off + ihl + 4]) if proto in (6, 17) and frag == 0 else b""
        elif ethertype == 0x86DD:
            proto = buf[off + 6]
            a, b = bytes(buf[off + 8:off + 24]), bytes(buf[off + 24:off + 40])
            ports = bytes(buf[off + 40:off + 44]) if proto in (6, 17) else b""
        else:
            return 0
        if len(ports) == 4:
            ea, eb = a + ports[0:2], b + ports[2:4]
        else:
            ea, eb = a, b
        lo, hi = (ea, eb) if ea <= eb else (eb, ea)
        return zlib.crc32(lo + hi + bytes([proto])) % n_workers
    except IndexError:
        return 0
