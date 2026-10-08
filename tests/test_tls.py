import pytest

from pydpi import tls
from pydpi.buffers import StreamBuffer
from pydpi.http_host import extract_http_host
from pydpi.synth import build_client_hello, tls_record


def test_extracts_sni_alpn_versions():
    h = tls.parse_tls_record(tls_record(build_client_hello("WWW.Example.COM")))
    assert h.sni == "www.example.com"
    assert h.alpn == ("h2", "http/1.1")
    assert 0x0304 in h.supported_versions
    assert not h.ech


def test_grease_is_ignored_in_ja3():
    with_g = tls.parse_client_hello(build_client_hello("a.com", grease=True))
    without = tls.parse_client_hello(build_client_hello("a.com", grease=False))
    assert with_g.ja3_hash == without.ja3_hash
    assert with_g.ja3.startswith("771,")


def test_ech_detected():
    assert tls.parse_client_hello(build_client_hello("outer.example", ech=True)).ech


def test_no_sni():
    assert tls.parse_client_hello(build_client_hello(None)).sni is None


def test_truncated_record_is_incomplete():
    rec = tls_record(build_client_hello("a.com"))
    with pytest.raises(tls.Incomplete):
        tls.parse_tls_record(rec[:40])


@pytest.mark.parametrize("n", range(0, 120, 7))
def test_never_crashes_on_truncated_handshake(n):
    msg = build_client_hello("a.com")[:n]
    with pytest.raises(tls.ParseError):
        tls.parse_client_hello(msg)


def test_garbage_is_rejected():
    with pytest.raises(tls.ParseError):
        tls.parse_tls_record(b"GET / HTTP/1.1\r\n\r\n")


def test_http_host():
    assert extract_http_host(b"GET /x HTTP/1.1\r\nHost: Example.com:8080\r\n\r\n") == "example.com"
    assert extract_http_host(b"hello world") is None


def test_stream_buffer_reorders_and_handles_overlap():
    b = StreamBuffer()
    b.add(5, b"56789")
    assert b.contiguous() == b""            # hole at the start
    b.add(0, b"01234")
    b.add(3, b"34567")                      # overlapping retransmission
    assert b.contiguous() == b"0123456789"
