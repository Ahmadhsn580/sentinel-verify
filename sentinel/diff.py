"""Baseline comparison and regression detection."""

from __future__ import annotations

import json
from dataclasses import dataclass

from .models import Confidence, Severity


@dataclass(slots=True)
class DiffResult:
    new: list[dict]
    fixed: list[dict]
    unchanged: list[dict]

    @property
    def regression(self) -> bool:
        return bool(self.new)


def _load(path: str) -> dict[str, dict]:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    findings = data.get("findings", [])
    return {f["fingerprint"]: f for f in findings if not f.get("suppressed")}


def compare(baseline_path: str, current_path: str) -> DiffResult:
    old = _load(baseline_path)
    new = _load(current_path)
    added = [new[k] for k in new if k not in old]
    removed = [old[k] for k in old if k not in new]
    same = [new[k] for k in new if k in old]
    return DiffResult(new=added, fixed=removed, unchanged=same)


def render(result: DiffResult, color: bool = True) -> str:
    reset = "\033[0m" if color else ""
    out: list[str] = []
    if result.new:
        out.append(f"\033[1;31m{len(result.new)} new finding(s){reset}" if color else f"{len(result.new)} new finding(s)")
        for f in result.new:
            out.append(f"  + [{f['severity']}] {f['check_id']} {f['url']}")
    if result.fixed:
        out.append(f"\033[1;32m{len(result.fixed)} resolved{reset}" if color else f"{len(result.fixed)} resolved")
        for f in result.fixed:
            out.append(f"  - [{f['severity']}] {f['check_id']} {f['url']}")
    if not result.new and not result.fixed:
        out.append("no change")
    else:
        out.append(f"{len(result.unchanged)} unchanged")
    return "\n".join(out)


def severity_of(entry: dict) -> Severity:
    try:
        return Severity(entry.get("severity", "info"))
    except ValueError:
        return Severity.INFO


def confidence_of(entry: dict) -> Confidence:
    try:
        return Confidence(entry.get("confidence", "info"))
    except ValueError:
        return Confidence.INFO