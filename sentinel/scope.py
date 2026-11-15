"""Scope enforcement, rate limiting and request budgeting."""

from __future__ import annotations

import asyncio
import ipaddress
import time

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.nz", "net.nz", "org.nz",
    "co.za", "org.za",
    "com.br", "net.br", "org.br",
    "co.in", "net.in", "org.in",
    "com.cn", "net.cn", "org.cn",
    "com.tr", "com.mx", "com.ar", "com.sg", "com.hk", "com.tw",
    "co.kr", "or.kr", "com.es", "com.pl", "co.il", "com.ua",
}


class ScopeViolation(Exception):
    """Raised when a request would leave the permitted scope."""


class BudgetExceeded(Exception):
    """Raised when the request budget is exhausted."""


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 without a public-suffix dependency."""
    host = host.lower().rstrip(".")
    if _is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_private(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return host in ("localhost",) or host.endswith(".local")
    return addr.is_private or addr.is_loopback or addr.is_link_local


class RateLimiter:
    """Async token bucket. `rate` is requests per second."""

    def __init__(self, rate: float) -> None:
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self.rate = rate
        self._tokens = 1.0
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(1.0, self._tokens + (now - self._updated) * self.rate)
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                await asyncio.sleep((1.0 - self._tokens) / self.rate)


class Budget:
    """Hard cap on total requests."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0
        self._lock = asyncio.Lock()

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit

    async def spend(self, n: int = 1) -> None:
        async with self._lock:
            if self.used + n > self.limit:
                raise BudgetExceeded(f"request budget of {self.limit} exhausted")
            self.used += n


class ScopePolicy:
    """Decides whether a URL may be requested."""

    def __init__(
        self,
        base_host: str,
        *,
        scope_domain: str | None = None,
        allow_private: bool = False,
        follow_redirects: bool = True,
    ) -> None:
        self.base_host = base_host.lower()
        self.scope_domain = (scope_domain or registrable_domain(base_host)).lower()
        self.allow_private = allow_private
        self.follow_redirects = follow_redirects
        self._allowed: set[str] = {self.base_host}
        self.violations: list[str] = []

    def check_target_host(self, host: str) -> None:
        if is_private(host) and not self.allow_private:
            raise ScopeViolation(f"{host} resolves to a private address (use --allow-private)")

    def allows(self, host: str) -> bool:
        host = host.lower()
        if host in self._allowed:
            return True
        if registrable_domain(host) == self.scope_domain:
            self._allowed.add(host)
            return True
        return False

    def assert_allowed(self, host: str) -> None:
        if not self.allows(host):
            msg = f"{host} is outside scope ({self.scope_domain})"
            self.violations.append(msg)
            raise ScopeViolation(msg)

    def assert_redirect_allowed(self, host: str) -> None:
        if not self.follow_redirects:
            raise ScopeViolation("redirects disabled")
        self.assert_allowed(host)