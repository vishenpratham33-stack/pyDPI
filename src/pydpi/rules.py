"""Blocking rules: IP / CIDR, application, and domain rules."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

import yaml

from pydpi.signatures import host_suffixes


@dataclass(frozen=True)
class RuleSet:
    """Immutable (so it is safe to share with worker processes)."""

    ips: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    apps: frozenset[str] = frozenset()          # stored casefolded
    domains: tuple[str, ...] = ()               # stored lowercase
    _exact_domains: frozenset[str] = field(default=frozenset(), repr=False)
    _globs: tuple[str, ...] = field(default=(), repr=False)
    _keywords: tuple[str, ...] = field(default=(), repr=False)

    # ---------- construction ----------
    @classmethod
    def build(cls, ips=(), apps=(), domains=()) -> RuleSet:
        nets = tuple(ipaddress.ip_network(i, strict=False) for i in ips)
        apps_cf = frozenset(a.casefold() for a in apps)
        doms = tuple(d.lower().strip() for d in domains)
        exact = frozenset(d for d in doms if "." in d and "*" not in d)
        globs = tuple(d for d in doms if "*" in d or "?" in d)
        # A bare word with no dot ("tiktok") is a keyword: substring match,
        # same behaviour as the original project's --block-domain.
        keywords = tuple(d for d in doms if "." not in d and "*" not in d and "?" not in d)
        return cls(nets, apps_cf, doms, exact, globs, keywords)

    @classmethod
    def from_file(cls, path: str | Path) -> RuleSet:
        data = yaml.safe_load(Path(path).read_text("utf-8")) or {}
        return cls.build(data.get("block_ips", []), data.get("block_apps", []),
                         data.get("block_domains", []))

    def merged_with(self, other: RuleSet) -> RuleSet:
        return RuleSet.build(
            [str(n) for n in self.ips + other.ips],
            list(self.apps | other.apps),
            list(self.domains + other.domains),
        )

    # ---------- evaluation ----------
    def check_ip(self, packed: bytes) -> str | None:
        if not self.ips:
            return None
        addr = ipaddress.ip_address(packed)
        for net in self.ips:
            if addr.version == net.version and addr in net:
                return f"ip:{net}"
        return None

    def check(self, app: str, host: str | None) -> str | None:
        """Return a human-readable reason if (app, host) must be blocked."""
        if app.casefold() in self.apps:
            return f"app:{app}"
        if host:
            host = host.lower().rstrip(".")
            if self._exact_domains:
                for suffix in host_suffixes(host):
                    if suffix in self._exact_domains:
                        return f"domain:{suffix}"
            for pattern in self._globs:
                if fnmatchcase(host, pattern):
                    return f"domain:{pattern}"
            for word in self._keywords:
                if word in host:
                    return f"domain:{word}"
        return None

    def describe(self) -> list[str]:
        out = [f"Blocked IP:     {n}" for n in self.ips]
        out += [f"Blocked app:    {a}" for a in sorted(self.apps)]
        out += [f"Blocked domain: {d}" for d in self.domains]
        return out

    def __bool__(self) -> bool:
        return bool(self.ips or self.apps or self.domains)
