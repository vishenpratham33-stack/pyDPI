import pytest

from pydpi import quic, tls
from pydpi.buffers import StreamBuffer
from pydpi.synth import build_client_hello, build_quic_initials


def test_rfc9001_initial_key_derivation():
    """Official test vectors from RFC 9001, Appendix A.1."""
    keys = quic.derive_client_initial_keys(bytes.fromhex("8394c8f03e515708"))
    assert keys.key.hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert keys.iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert keys.hp.hex() == "9f50449e04a0e810283a1e9933adedd2"


def test_rfc9001_header_protection_mask():
    """RFC 9001, Appendix A.2."""
    keys = quic.derive_client_initial_keys(bytes.fromhex("8394c8f03e515708"))
    mask = quic.header_protection_mask(keys.hp, bytes.fromhex("d1b1c98dd7689fb8ec11d242b123dc9b"))
    assert mask[:5].hex() == "437b9aec36"


@pytest.mark.parametrize("value", [0, 63, 64, 15293, 16383, 494878333, 2**30, 151288809941952652])
def test_varint_roundtrip(value):
    enc = quic.write_varint(value)
    assert quic.read_varint(enc, 0) == (value, len(enc))


def test_decrypt_initial_recovers_sni():
    hello = build_client_hello("www.youtube.com")
    (dg,) = build_quic_initials(hello, dcid=b"\x83\x94\xc8\xf0\x3e\x51\x57\x08")
    assert len(dg) >= 1200
    buf = StreamBuffer()
    for off, data in quic.decrypt_client_initial(dg):
        buf.add(off, data)
    assert tls.parse_client_hello(buf.contiguous()).sni == "www.youtube.com"


def test_tampered_packet_is_rejected():
    (dg,) = build_quic_initials(build_client_hello("a.com"), dcid=b"12345678")
    bad = bytearray(dg)
    bad[-5] ^= 0xFF
    with pytest.raises(quic.QuicError):
        quic.decrypt_client_initial(bytes(bad))
