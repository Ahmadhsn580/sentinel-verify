"""Profile loading with a minimal YAML-subset parser (no PyYAML dependency)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class Profile:
    name: str
    description: str = ""
    rate: float = 5.0
    max_requests: int = 300
    timeout: float = 10.0
    concurrency: int = 6
    retries: int = 2
    max_tier: str = "safe"
    follow_redirects: bool = True
    methods: tuple[str, ...] = ("GET", "HEAD")


BUILTIN: dict[str, Profile] = {
    "safe": Profile(
        name="safe",
        description="Read-only, 300 requests, 5 req/s. Safe on production.",
        rate=5.0,
        max_requests=300,
        max_tier="safe",
    ),
    "standard": Profile(
        name="standard",
        description="Adds payload probing and 2 req/s headroom. 800 requests.",
        rate=8.0,
        max_requests=800,
        concurrency=8,
        max_tier="standard",
        methods=("GET", "HEAD", "OPTIONS"),
    ),
    "aggressive": Profile(
        name="aggressive",
        description="Timing probes and cache checks. 2000 requests, higher concurrency.",
        rate=15.0,
        max_requests=2000,
        concurrency=12,
        retries=3,
        max_tier="aggressive",
        methods=("GET", "HEAD", "OPTIONS", "POST"),
    ),
}


def _profile_dir() -> Path:
    env = os.environ.get("SENTINEL_PROFILE_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent / "profiles"


def _parse_subset(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        data[key.strip()] = value.strip().strip("'\"")
    return data


def load(name: str) -> Profile:
    """Load a profile by name, preferring disk over builtins."""
    path = _profile_dir() / f"{name}.yml"
    if not path.is_file():
        if name in BUILTIN:
            return BUILTIN[name]
        raise KeyError(f"unknown profile: {name}")
    data = _parse_subset(path.read_text(encoding="utf-8"))
    base = BUILTIN.get(name, Profile(name=name))
    return Profile(
        name=name,
        description=data.get("description", base.description),
        rate=float(data.get("rate", base.rate)),
        max_requests=int(data.get("max_requests", base.max_requests)),
        timeout=float(data.get("timeout", base.timeout)),
        concurrency=int(data.get("concurrency", base.concurrency)),
        retries=int(data.get("retries", base.retries)),
        max_tier=data.get("max_tier", base.max_tier),
        follow_redirects=data.get("follow_redirects", "true").lower() != "false",
    )
