"""Verification engine: baselines, differential probes, false-positive control."""

from __future__ import annotations

import asyncio
import statistics
import time
from collections.abc import Awaitable, Callable
from typing import Any

from .http import HttpClient, HttpError, Response
from .models import (
    Confidence,
    Evidence,
    Finding,
    ParsedTarget,
    Report,
    ScanMeta,
    Severity,
)
from .scope import BudgetExceeded, ScopeViolation

Mutator = Callable[[], Awaitable[Response]]
Signal = Callable[[Response], Any]


class Engine:
    """Shared state and verification primitives for all checks."""

    def __init__(
        self,
        client: HttpClient,
        target: ParsedTarget,
        *,
        control_url: str | None = None,
        verbose: bool = False,
    ) -> None:
        self.client = client
        self.target = target
        self.control_url = control_url
        self.verbose = verbose
        self.findings: list[Finding] = []
        self.checks_run = 0
        self.checks_skipped = 0
        self.aborted_reason = ""
        self._baseline: Response | None = None

    # ---------- fetching ----------

    async def fetch(self, url: str, **kwargs: Any) -> Response:
        return await self.client.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> Response:
        return await self.client.request("HEAD", url, **kwargs)

    async def send(self, method: str, url: str, **kwargs: Any) -> Response:
        return await self.client.request(method, url, **kwargs)

    async def baseline(self, refresh: bool = False) -> Response:
        if self._baseline is None or refresh:
            self._baseline = await self.fetch(self.target.url)
        return self._baseline

    # ---------- finding construction ----------

    def record(
        self,
        *,
        check_id: str,
        title: str,
        severity: Severity,
        confidence: Confidence,
        cwe: str,
        description: str,
        remediation: str,
        url: str | None = None,
        response: Response | None = None,
        evidence: Evidence | None = None,
        cvss_vector: str = "",
    ) -> Finding:
        ev = evidence or Evidence()
        if response is not None:
            ev.request_line = f"{response.method} {response.url}"
            ev.status = response.status
            ev.headers = response.headers[:40]
            ev.body_snippet = response.snippet()
            ev.body_sha256 = response.sha256
        finding = Finding(
            check_id=check_id,
            title=title,
            severity=severity,
            confidence=confidence,
            cwe=cwe,
            url=url or self.target.url,
            description=description,
            remediation=remediation,
            cvss_vector=cvss_vector,
            evidence=ev,
        )
        self.findings.append(finding)
        if self.verbose:
            print(f"  [{finding.severity.value}/{finding.confidence.value}] {check_id} {finding.url}")
        return finding

    def suppress(self, finding: Finding, reason: str) -> None:
        finding.suppressed_reason = reason
        if self.verbose:
            print(f"  [suppressed] {finding.check_id}: {reason}")

    # ---------- differential verification ----------

    async def differential(
        self,
        *,
        probe: Mutator,
        signal: Signal,
        control: bool = True,
    ) -> tuple[bool, bool, Evidence]:
        """Run baseline → probe → baseline.

        Returns (signal_changed, stable_baseline, evidence). The probe is only
        treated as confirmed when the two baselines agree AND the signal differs.
        """
        first = await self.baseline(refresh=True)
        probed = await probe()
        second = await self.baseline(refresh=True)

        stable = first.signature() == second.signature()
        base_signal = signal(first)
        changed = signal(probed) != base_signal

        ev = Evidence(
            request_line=f"{probed.method} {probed.url}",
            status=probed.status,
            headers=probed.headers[:40],
            body_snippet=probed.snippet(),
            body_sha256=probed.sha256,
            baseline_diff=_diff_signals(base_signal, signal(probed)),
            note="baseline stable" if stable else "baseline drifted between samples",
        )

        if changed and stable and control and self.control_url:
            control_hit = await self._control_reproduces(probe, signal)
            if control_hit:
                ev.note += "; signal also present on control URL"
        return changed, stable, ev

    async def _control_reproduces(self, probe: Mutator, signal: Signal) -> bool:
        assert self.control_url is not None
        try:
            base = await self.fetch(self.control_url)
        except HttpError:
            return False
        # Re-run the probe against the control origin is not always meaningful;
        # the control baseline signal is a cheap proxy for a false positive.
        return signal(base) == signal(await self.baseline())

    async def timing_samples(self, probe: Mutator, samples: int = 3) -> tuple[list[float], list[float]]:
        """Return (baseline_times, probe_times) for time-based verification."""
        base: list[float] = []
        for _ in range(samples):
            start = time.monotonic()
            await self.baseline(refresh=True)
            base.append(time.monotonic() - start)
        probed: list[float] = []
        for _ in range(samples):
            start = time.monotonic()
            await probe()
            probed.append(time.monotonic() - start)
        return base, probed

    @staticmethod
    def delay_is_significant(base: list[float], probed: list[float], floor: float = 0.8) -> bool:
        """True when probe latency exceeds baseline by >= 3 sigma and >= floor seconds."""
        if len(base) < 2 or not probed:
            return False
        mean = statistics.fmean(base)
        sigma = statistics.pstdev(base) or 0.05
        probe_mean = statistics.fmean(probed)
        return probe_mean - mean >= max(3 * sigma, floor)

    # ---------- report ----------

    def build_report(self, started_at: str, profile: str, version: str) -> Report:
        meta = ScanMeta(
            target=self.target.url,
            profile=profile,
            started_at=started_at,
            finished_at=_now_iso(),
            requests=self.client.budget.used,
            checks_run=self.checks_run,
            checks_skipped=self.checks_skipped,
            version=version,
            budget_exhausted=self.client.budget.exhausted,
            aborted_reason=self.aborted_reason,
        )
        return Report(meta=meta, findings=self.findings)


def _diff_signals(a: Any, b: Any) -> str:
    if a == b:
        return "(no change)"
    return f"baseline={_short(a)} probe={_short(b)}"


def _short(value: Any, limit: int = 120) -> str:
    text = repr(value)
    return text[:limit] + ("…" if len(text) > limit else "")


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


async def run_checks(engine: Engine, checks: list[Any], concurrency: int = 4) -> None:
    """Execute checks with bounded concurrency, isolating failures."""
    sem = asyncio.Semaphore(concurrency)

    async def _one(check: Any) -> None:
        async with sem:
            try:
                await check.run(engine)
                engine.checks_run += 1
            except BudgetExceeded as exc:
                engine.aborted_reason = str(exc)
                engine.checks_skipped += 1
            except ScopeViolation:
                engine.checks_skipped += 1
            except HttpError as exc:
                engine.checks_skipped += 1
                if engine.verbose:
                    print(f"  [skip] {check.id}: {exc}")
            except Exception as exc:  # noqa: BLE001 - a check must never kill the scan
                engine.checks_skipped += 1
                if engine.verbose:
                    print(f"  [error] {check.id}: {type(exc).__name__}: {exc}")

    await asyncio.gather(*(_one(c) for c in checks))