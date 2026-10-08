"""Tiny out-of-order stream reassembly (used for TCP segments and QUIC CRYPTO frames)."""

from __future__ import annotations


class StreamBuffer:
    """Collect (offset, data) chunks and return the contiguous prefix."""

    __slots__ = ("_chunks", "limit")

    def __init__(self, limit: int = 65536):
        self._chunks: dict[int, bytes] = {}
        self.limit = limit

    def add(self, offset: int, data: bytes) -> bool:
        if offset < 0 or not data or offset + len(data) > self.limit:
            return False
        old = self._chunks.get(offset)
        if old is None or len(data) > len(old):
            self._chunks[offset] = data
        return True

    def contiguous(self) -> bytes:
        out = bytearray()
        for off in sorted(self._chunks):
            if off > len(out):
                break                      # hole - wait for more data
            chunk = self._chunks[off]
            if off + len(chunk) > len(out):
                out += chunk[len(out) - off:]
        return bytes(out)
