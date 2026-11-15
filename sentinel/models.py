"""Core data models: findings, evidence, targets, severity ordering."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlsplit


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    INFO = "info"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.INFO: 0,
    Confidence.LIKELY: 1,
    Confidence.CONFIRMED: 2,
}

PROFILE_RANK = {"safe": 0, "standard": 1, "aggressive": 2}


class Tier(str, Enum):
    """Minimum profile required to run a check."""

    SAFE = "safe"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"


@dataclass(slots=True)
class ParsedTarget:
    """A validated target URL split into components."""

    url: str
    scheme: str
    host: str
    port: int
    path: str
    query: str
    fragment: str = ""

    @property
    def netloc(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.netloc}"

    @property
    def path_qs(self) -> str:
        return self.path + (f"?{self.query}" if self.query else "")

    def with_path(self, path: str) -> str:
        return f"{self.origin}{path}"

    def with_query(self, query: str) -> str:
        base = f"{self.origin}{self.path}"
        return f"{base}?{query}" if query else base

    @classmethod
    def parse(cls, url: str, default_port: int | None = None) -> ParsedTarget:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ValueError(f"unsupported scheme: {parts.scheme or '(none)'}")
        if not parts.hostname:
            raise ValueError("URL has no host")
        scheme = parts.scheme
        port = parts.port or default_port or (443 if scheme == "https" else 80)
        return cls(
            url=url,
            scheme=scheme,
            host=parts.hostname,
            port=port,
            path=parts.path or "/",
            query=parts.query,
            fragment=parts.fragment,
        )


@dataclass(slots=True)
class Evidence:
    """Reproducible proof attached to a finding."""

    request_line: str = ""
    status: int = 0
    headers: list[tuple[str, str]] = field(default_factory=list)
    body_snippet: str = ""
    body_sha256: str = ""
    baseline_diff: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_line": self.request_line,
            "status": self.status,
            "headers": [f"{k}: {v}" for k, v in self.headers],
            "body_snippet": self.body_snippet,
            "body_sha256": self.body_sha256,
            "baseline_diff": self.baseline_diff,
            "note": self.note,
        }


@dataclass(slots=True)
class Finding:
    check_id: str
    title: str
    severity: Severity
    confidence: Confidence
    cwe: str
    url: str
    description: str
    remediation: str
    cvss_vector: str = ""
    evidence: Evidence = field(default_factory=Evidence)
    suppressed_reason: str = ""

    @property
    def fingerprint(self) -> str:
        """Stable identity across runs, independent of ordering or timestamps."""
        material = f"{self.check_id}|{self.url}|{self.evidence.body_sha256}|{self.title}"
        return hashlib.sha256(material.encode()).hexdigest()[:16]

    @property
    def suppressed(self) -> bool:
        return bool(self.suppressed_reason)

    def sort_key(self) -> tuple[int, int, str, str]:
        return (
            -SEVERITY_RANK[self.severity],
            -CONFIDENCE_RANK[self.confidence],
            self.check_id,
            self.url,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "cwe": self.cwe,
            "cvss_vector": self.cvss_vector,
            "url": self.url,
            "description": self.description,
            "remediation": self.remediation,
            "fingerprint": self.fingerprint,
            "suppressed": self.suppressed,
            "suppressed_reason": self.suppressed_reason,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(slots=True)
class ScanMeta:
    target: str
    profile: str
    started_at: str
    finished_at: str = ""
    requests: int = 0
    checks_run: int = 0
    checks_skipped: int = 0
    version: str = ""
    budget_exhausted: bool = False
    aborted_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(slots=True)
class Report:
    meta: ScanMeta
    findings: list[Finding] = field(default_factory=list)

    @property
    def active(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.active:
            out[f.severity.value] += 1
        return out

    def worst(self) -> Severity | None:
        active = self.active
        if not active:
            return None
        return max((f.severity for f in active), key=lambda s: SEVERITY_RANK[s])

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "sentinel-verify/report/v1",
            "meta": self.meta.to_dict(),
            "counts": self.counts(),
            "findings": [f.to_dict() for f in sorted(self.findings, key=Finding.sort_key)],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=False)
