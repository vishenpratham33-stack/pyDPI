"""Extract the Host header from a plain-HTTP request."""

from __future__ import annotations

import re

_REQUEST_LINE = re.compile(
    rb"^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) \S+ HTTP/1\.[01]\r\n"
)
_HOST = re.compile(rb"\r\nhost:[ \t]*([^\r\n]+)", re.IGNORECASE)


def extract_http_host(payload: bytes) -> str | None:
    head = payload[:2048]
    if not _REQUEST_LINE.match(head):
        return None
    m = _HOST.search(head)
    if not m:
        return None
    host = m.group(1).decode("ascii", errors="ignore").strip().lower()
    # strip ":port" but keep IPv6 literals like [::1]:8080 intact
    if host.startswith("["):
        host = host[1:host.find("]")] if "]" in host else host
    else:
        host = host.split(":", 1)[0]
    return host or None
