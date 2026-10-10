"""Directory connectors: look people up so an administrator can pre-provision them with a role.

A *directory connector* is distinct from the *authentication provider* (OIDC): SSO proves who someone is;
a connector only helps find people (display name, e-mail). Connectors are read-only and self-diagnosing.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class ConnectorError(Exception):
    """Readable error (never contains a secret) surfaced to the administrator."""


@dataclass
class DirectoryPerson:
    external_id: str
    email: str
    display_name: str


@dataclass
class Step:
    step: str
    status: str  # ok | fail
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"step": self.step, "status": self.status, "detail": self.detail}


class DirectoryConnector(Protocol):
    kind: str

    def diagnose(self) -> list[Step]: ...
    def search(self, query: str, limit: int = 25) -> list[DirectoryPerson]: ...
