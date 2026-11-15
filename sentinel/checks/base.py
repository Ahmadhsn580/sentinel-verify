"""Check base class and registry."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Tier
from ..verify import Engine


class Check(ABC):
    id: str = ""
    title: str = ""
    cwe: str = "CWE-000"
    tier: Tier = Tier.SAFE
    needs_https: bool = False
    description: str = ""

    def applicable(self, engine: Engine) -> bool:
        return not (self.needs_https and engine.target.scheme != "https")

    @abstractmethod
    async def run(self, engine: Engine) -> None:
        """Emit zero or more findings via engine.record()."""


REGISTRY: dict[str, type[Check]] = {}


def register(cls: type[Check]) -> type[Check]:
    if not cls.id:
        raise ValueError(f"{cls.__name__} has no id")
    if cls.id in REGISTRY:
        raise ValueError(f"duplicate check id: {cls.id}")
    REGISTRY[cls.id] = cls
    return cls


def all_checks() -> dict[str, type[Check]]:
    from . import (  # noqa: F401
        api,
        cookies,
        cors,
        dns,
        exposure,
        fingerprint,
        headers,
        host,
        inject,
        methods,
        redirect,
        transport,
    )

    return REGISTRY
