"""TLS ClientHello parser (SNI, ALPN, JA3, ECH detection).

Every read goes through a bounds-checked cursor, so malformed or truncated
packets raise ParseError instead of crashing or reading out of range
(the classic bug class in hand-written C parsers).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


class ParseError(ValueError):
    """Payload is not a (complete, valid) ClientHello."""


class Incomplete(ParseError):
    """Looks like a ClientHello but more bytes are needed."""


EXT_SNI = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_ECH = 0xFE0D

TLS_RECORD_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01


def is_grease(value: int) -> bool:
    """GREASE values (RFC 8701) look like 0x0a0a, 0x1a1a ... 0xfafa."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


class _Cursor:
    __slots__ = ("buf", "end", "pos")

    def __init__(self, buf: bytes | memoryview, start: int = 0, end: int | None = None):
        self.buf = buf
        self.pos = start
        self.end = len(buf) if end is None else end

    def take(self, n: int) -> memoryview | bytes:
        if n < 0 or self.pos + n > self.end:
            raise Incomplete(f"need {n} bytes at offset {self.pos}")
        chunk = self.buf[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        b = self.take(2)
        return (b[0] << 8) | b[1]

    def u24(self) -> int:
        b = self.take(3)
        return (b[0] << 16) | (b[1] << 8) | b[2]

    def sub(self, n: int) -> _Cursor:
        """A new cursor limited to the next n bytes (advances this one)."""
        start = self.pos
        self.take(n)
        return _Cursor(self.buf, start, start + n)

    def remaining(self) -> int:
        return self.end - self.pos


@dataclass(slots=True, frozen=True)
class ClientHello:
    sni: str | None
    alpn: tuple[str, ...]
    supported_versions: tuple[int, ...]
    ja3: str
    ja3_hash: str
    ech: bool


def tls_record_total_length(buf: bytes) -> int | None:
    """If buf starts like a TLS handshake record, return the full record size."""
    if len(buf) >= 5 and buf[0] == TLS_RECORD_HANDSHAKE and buf[1] == 3 and buf[2] <= 4:
        return 5 + ((buf[3] << 8) | buf[4])
    return None


def looks_like_tls_handshake(buf: bytes) -> bool:
    return len(buf) >= 6 and buf[0] == TLS_RECORD_HANDSHAKE and buf[1] == 3 \
        and buf[5] == HANDSHAKE_CLIENT_HELLO


def parse_tls_record(payload: bytes) -> ClientHello:
    """Parse a TLS record (as seen at the start of a TCP stream)."""
    if not looks_like_tls_handshake(payload):
        raise ParseError("not a TLS ClientHello record")
    total = tls_record_total_length(payload)
    if total is None or len(payload) < total:
        raise Incomplete("TLS record continues in next segment")
    return parse_client_hello(memoryview(payload)[5:total])


def _decode_host(raw: bytes | memoryview) -> str:
    return bytes(raw).decode("ascii", errors="ignore").lower().rstrip(".")


def parse_client_hello(msg: bytes | memoryview) -> ClientHello:
    """Parse a handshake message that starts with the handshake type byte.

    QUIC carries the ClientHello without a TLS record header, so this
    function is shared by the TCP and QUIC paths.
    """
    cur = _Cursor(msg)
    if cur.u8() != HANDSHAKE_CLIENT_HELLO:
        raise ParseError("not a ClientHello")
    body = cur.sub(cur.u24())

    legacy_version = body.u16()
    body.take(32)                                  # random
    body.take(body.u8())                           # session id
    cs = body.sub(body.u16())                      # cipher suites
    ciphers = [cs.u16() for _ in range(cs.remaining() // 2)]
    body.take(body.u8())                           # compression methods

    sni: str | None = None
    alpn: list[str] = []
    versions: list[int] = []
    ext_types: list[int] = []
    groups: list[int] = []
    point_formats: list[int] = []
    ech = False

    if body.remaining() >= 2:
        exts = body.sub(body.u16())
        while exts.remaining() >= 4:
            ext_type = exts.u16()
            data = exts.sub(exts.u16())
            ext_types.append(ext_type)

            if ext_type == EXT_SNI and data.remaining() >= 5:
                names = data.sub(data.u16())
                while names.remaining() >= 3:
                    name_type = names.u8()
                    name = names.take(names.u16())
                    if name_type == 0 and sni is None:
                        sni = _decode_host(name)
            elif ext_type == EXT_ALPN and data.remaining() >= 2:
                protos = data.sub(data.u16())
                while protos.remaining() >= 1:
                    alpn.append(bytes(protos.take(protos.u8())).decode("ascii", "replace"))
            elif ext_type == EXT_SUPPORTED_VERSIONS and data.remaining() >= 1:
                lst = data.sub(data.u8())
                versions = [lst.u16() for _ in range(lst.remaining() // 2)]
            elif ext_type == EXT_SUPPORTED_GROUPS and data.remaining() >= 2:
                lst = data.sub(data.u16())
                groups = [lst.u16() for _ in range(lst.remaining() // 2)]
            elif ext_type == EXT_EC_POINT_FORMATS and data.remaining() >= 1:
                lst = data.sub(data.u8())
                point_formats = [lst.u8() for _ in range(lst.remaining())]
            elif ext_type == EXT_ECH:
                ech = True

    ja3 = ",".join([
        str(legacy_version),
        "-".join(str(c) for c in ciphers if not is_grease(c)),
        "-".join(str(e) for e in ext_types if not is_grease(e)),
        "-".join(str(g) for g in groups if not is_grease(g)),
        "-".join(str(p) for p in point_formats),
    ])
    return ClientHello(
        sni=sni or None,
        alpn=tuple(alpn),
        supported_versions=tuple(v for v in versions if not is_grease(v)),
        ja3=ja3,
        ja3_hash=hashlib.md5(ja3.encode(), usedforsecurity=False).hexdigest(),
        ech=ech,
    )
