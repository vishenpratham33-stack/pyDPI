"""Data-driven application signatures.

The original C++ project used a chain of `if (sni.find("youtube") ...)`
checks, which wrongly matches hosts like "notyoutube.evil.com".
Here every signature is a *domain suffix* matched on label boundaries,
looked up in a dict - O(number of labels), not O(number of signatures).
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import yaml


def host_suffixes(host: str):
    """'a.b.example.com' -> 'a.b.example.com', 'b.example.com', 'example.com', 'com'."""
    while host:
        yield host
        _, dot, host = host.partition(".")
        if not dot:
            return


class SignatureDB:
    def __init__(self, apps: dict[str, list[str]]):
        self._suffix_to_app: dict[str, str] = {}
        for app, suffixes in apps.items():
            for suffix in suffixes:
                self._suffix_to_app[suffix.lower().strip(".")] = app
        self.app_names = sorted(apps)

    @classmethod
    def load(cls, path: str | Path | None = None) -> SignatureDB:
        if path is None:
            text = (resources.files("pydpi") / "data" / "signatures.yaml").read_text("utf-8")
        else:
            text = Path(path).read_text("utf-8")
        data = yaml.safe_load(text) or {}
        return cls(data.get("apps", {}))

    def match(self, host: str | None) -> str | None:
        """Return the app for a hostname, or None. Longest suffix wins."""
        if not host:
            return None
        for candidate in host_suffixes(host.lower().rstrip(".")):
            app = self._suffix_to_app.get(candidate)
            if app:
                return app
        return None

    def __len__(self) -> int:
        return len(self._suffix_to_app)
