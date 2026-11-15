from __future__ import annotations

import json

import pytest

from sentinel.models import (
    Confidence,
    Evidence,
    Finding,
    Report,
    ScanMeta,
    Severity,
)
from sentinel.report import render


def sample() -> Report:
    meta = ScanMeta(target="https://example.com", profile="safe", started_at="now", version="1")
    finding = Finding(
        check_id="hdr.xcto",
        title="Missing nosniff",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        cwe="CWE-430",
        url="https://example.com",
        description="d",
        remediation="r",
        evidence=Evidence(body_sha256="abc123"),
    )
    return Report(meta=meta, findings=[finding])


@pytest.mark.parametrize("fmt", ["text", "json", "md", "html", "sarif"])
def test_renderers_produce_output(fmt: str) -> None:
    out = render(sample(), fmt, color=False)
    assert out
    assert "hdr.xcto" in out or fmt == "text"


def test_sarif_is_valid_structure() -> None:
    doc = json.loads(render(sample(), "sarif", color=False))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"] == "hdr.xcto"


def test_html_escapes_content() -> None:
    report = sample()
    report.findings[0].title = "<script>x</script>"
    assert "&lt;script&gt;" in render(report, "html", color=False)


def test_text_hides_suppressed() -> None:
    report = sample()
    report.findings[0].suppressed_reason = "control hit"
    assert "Missing nosniff" not in render(report, "text", color=False)