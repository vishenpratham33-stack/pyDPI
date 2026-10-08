"""QUIC v1 Initial packet decryption (RFC 9001) to recover the TLS SNI.

QUIC encrypts everything, but the *Initial* packet is protected with keys
derived from a public salt and the Destination Connection ID that is sent in
clear. So any on-path observer can decrypt it - this is what real DPI
engines do to see which site a QUIC / HTTP-3 connection is going to.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

QUIC_V1 = 0x00000001
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


class QuicError(ValueError):
    pass


# ----------------------------------------------------------------- helpers
def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    """QUIC variable-length integer. Returns (value, new_pos)."""
    if pos >= len(buf):
        raise QuicError("varint out of range")
    length = 1 << (buf[pos] >> 6)
    if pos + length > len(buf):
        raise QuicError("varint truncated")
    value = buf[pos] & 0x3F
    for b in buf[pos + 1:pos + length]:
        value = (value << 8) | b
    return value, pos + length


def write_varint(value: int) -> bytes:
    if value < 1 << 6:
        return struct.pack("!B", value)
    if value < 1 << 14:
        return struct.pack("!H", 0x4000 | value)
    if value < 1 << 30:
        return struct.pack("!I", 0x80000000 | value)
    return struct.pack("!Q", 0xC000000000000000 | value)


def _hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack("!HB", length, len(full)) + full + b"\x00"
    # HKDF-Expand with SHA-256 (single/multi block)
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


@dataclass(frozen=True, slots=True)
class InitialKeys:
    key: bytes
    iv: bytes
    hp: bytes


def derive_client_initial_keys(dcid: bytes) -> InitialKeys:
    initial_secret = hmac.new(INITIAL_SALT_V1, dcid, hashlib.sha256).digest()  # HKDF-Extract
    client_secret = _hkdf_expand_label(initial_secret, "client in", 32)
    return InitialKeys(
        key=_hkdf_expand_label(client_secret, "quic key", 16),
        iv=_hkdf_expand_label(client_secret, "quic iv", 12),
        hp=_hkdf_expand_label(client_secret, "quic hp", 16),
    )


def header_protection_mask(hp_key: bytes, sample: bytes) -> bytes:
    enc = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    return enc.update(sample) + enc.finalize()


# ----------------------------------------------------------------- detection
def is_quic_long_header(payload: bytes) -> bool:
    return len(payload) >= 7 and (payload[0] & 0xC0) == 0xC0


def quic_version(payload: bytes) -> int:
    return struct.unpack_from("!I", payload, 1)[0]


# ----------------------------------------------------------------- decrypt
def decrypt_client_initial(datagram: bytes) -> list[tuple[int, bytes]]:
    """Decrypt a client Initial packet; return its CRYPTO chunks [(offset, data)]."""
    if not is_quic_long_header(datagram):
        raise QuicError("not a long header")
    if quic_version(datagram) != QUIC_V1:
        raise QuicError("unsupported QUIC version")
    if (datagram[0] >> 4) & 0x03 != 0:
        raise QuicError("not an Initial packet")

    pos = 5
    dcid_len = datagram[pos]
    dcid = datagram[pos + 1:pos + 1 + dcid_len]
    pos += 1 + dcid_len
    if pos >= len(datagram):
        raise QuicError("truncated")
    scid_len = datagram[pos]
    pos += 1 + scid_len
    token_len, pos = read_varint(datagram, pos)
    pos += token_len
    length, pos = read_varint(datagram, pos)
    pn_offset = pos
    packet_end = pn_offset + length
    if packet_end > len(datagram) or length < 20:
        raise QuicError("bad length")

    keys = derive_client_initial_keys(dcid)

    # Remove header protection. The sample always starts 4 bytes after pn_offset.
    sample = datagram[pn_offset + 4:pn_offset + 20]
    if len(sample) < 16:
        raise QuicError("packet too short for sample")
    mask = header_protection_mask(keys.hp, sample)
    first = datagram[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(b ^ m for b, m in zip(datagram[pn_offset:pn_offset + pn_len], mask[1:]))
    packet_number = int.from_bytes(pn_bytes, "big")

    header = bytes([first]) + datagram[1:pn_offset] + pn_bytes
    nonce = bytes(a ^ b for a, b in zip(keys.iv, packet_number.to_bytes(12, "big")))
    try:
        plaintext = AESGCM(keys.key).decrypt(nonce, datagram[pn_offset + pn_len:packet_end], header)
    except Exception as exc:  # InvalidTag
        raise QuicError("decryption failed") from exc
    return _crypto_chunks(plaintext)


def _crypto_chunks(frames: bytes) -> list[tuple[int, bytes]]:
    chunks: list[tuple[int, bytes]] = []
    pos = 0
    while pos < len(frames):
        ftype, pos = read_varint(frames, pos)
        if ftype in (0x00, 0x01):                 # PADDING, PING
            continue
        if ftype == 0x06:                         # CRYPTO
            offset, pos = read_varint(frames, pos)
            size, pos = read_varint(frames, pos)
            data = frames[pos:pos + size]
            if len(data) != size:
                raise QuicError("truncated CRYPTO frame")
            chunks.append((offset, data))
            pos += size
        elif ftype in (0x02, 0x03):               # ACK (rare in a client's first flight)
            _, pos = read_varint(frames, pos)      # largest acknowledged
            _, pos = read_varint(frames, pos)      # ack delay
            range_count, pos = read_varint(frames, pos)
            _, pos = read_varint(frames, pos)      # first ack range
            for _ in range(range_count):
                _, pos = read_varint(frames, pos)  # gap
                _, pos = read_varint(frames, pos)  # range length
            if ftype == 0x03:                      # ECN counts
                for _ in range(3):
                    _, pos = read_varint(frames, pos)
        else:
            break                                  # unknown frame: stop, keep what we have
    return chunks
