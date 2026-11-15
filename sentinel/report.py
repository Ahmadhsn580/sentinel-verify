"""Report renderers: text, json, markdown, html, sarif."""

from __future__ import annotations

import html
import json

from .models import Report, Severity

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

C_RESET = "\033[0m"
C_DIM = "\033[2m"
C_BOLD = "\033[1m"
COLORS = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m",
    Severity.INFO: "\033[1;34m",
}


def render(report: Report, fmt: str, *, color: bool = True) -> str:
    if fmt == "json":
        return report.to_json()
    if fmt == "md":
        return render_markdown(report)
    if fmt == "html":
        return render_html(report)
    if fmt == "sarif":
        return render_sarif(report)
    return render_text(report, color=color)


def render_text(report: Report, *, color: bool = True) -> str:
    def paint(text: str, sev: Severity | None = None) -> str:
        if not color:
            return text
        prefix = COLORS.get(sev, "") if sev else ""
        return f"{prefix}{text}{C_RESET}" if prefix else text

    out: list[str] = []
    meta = report.meta
    out.append(paint(f"sentinel-verify {meta.version}", None))
    out.append(f"target   {meta.target}")
    out.append(f"profile  {meta.profile}   requests {meta.requests}")
    out.append("")
    active = report.active
    if not active:
        out.append(paint("No findings.", Severity.INFO))
    for finding in sorted(active, key=lambda f: f.sort_key()):
        out.append(
            paint(f"[{finding.severity.value.upper():8}] {finding.title}", finding.severity)
            + C_DIM
            + f"  ({finding.confidence.value})"
            + C_RESET
        )
        out.append(f"  {finding.check_id}  {finding.cwe}  {finding.url}")
        if finding.evidence.baseline_diff:
            out.append(f"  diff: {finding.evidence.baseline_diff}")
        out.append(f"  fix:  {finding.remediation}")
        out.append("")
    suppressed = [f for f in report.findings if f.suppressed]
    if suppressed:
        out.append(f"{len(suppressed)} suppressed finding(s)")
    counts = report.counts()
    summary = "  ".join(f"{k}:{v}" for k, v in counts.items() if v)
    out.append(summary or "clean")
    if meta.budget_exhausted:
        out.append("request budget exhausted; results are partial")
    return "\n".join(out)


def render_markdown(report: Report) -> str:
    meta = report.meta
    lines = [
        f"# sentinel-verify report — {meta.target}",
        "",
        f"- Profile: `{meta.profile}`",
        f"- Requests: {meta.requests}",
        f"- Started: {meta.started_at}",
        "",
        "| Severity | Confidence | Check | URL | Finding |",
        "|---|---|---|---|---|",
    ]
    for f in sorted(report.active, key=lambda x: x.sort_key()):
        lines.append(
            f"| {f.severity.value} | {f.confidence.value} | `{f.check_id}` | {f.url} | {f.title} |"
        )
    if not report.active:
        lines.append("| — | — | — | — | No findings |")
    return "\n".join(lines)


def render_html(report: Report) -> str:
    rows = []
    for f in sorted(report.active, key=lambda x: x.sort_key()):
        rows.append(
            "<tr>"
            f"<td class='sev sev-{f.severity.value}'>{html.escape(f.severity.value)}</td>"
            f"<td>{html.escape(f.confidence.value)}</td>"
            f"<td><code>{html.escape(f.check_id)}</code></td>"
            f"<td>{html.escape(f.title)}</td>"
            f"<td><code>{html.escape(f.evidence.body_sha256[:12])}</code></td>"
            "</tr>"
        )
    body = "".join(rows) or "<tr><td colspan='5'>No findings</td></tr>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>sentinel-verify — {html.escape(report.meta.target)}</title>
<style>
:root{{color-scheme:dark light}}
body{{font:14px/1.5 ui-monospace,monospace;margin:2rem;background:#0d1117;color:#c9d1d9}}
table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #30363d;padding:.45rem .6rem;text-align:left;vertical-align:top}}
.sev{{font-weight:700}}
.sev-critical{{color:#d2a8ff}} .sev-high{{color:#ff7b72}}
.sev-medium{{color:#d29922}} .sev-low{{color:#79c0ff}} .sev-info{{color:#8b949e}}
code{{color:#7ee787}}
</style></head><body>
<h1>sentinel-verify</h1>
<p>Target <code>{html.escape(report.meta.target)}</code> · profile <code>{html.escape(report.meta.profile)}</code> · {report.meta.requests} requests</p>
<table><thead><tr><th>Severity</th><th>Confidence</th><th>Check</th><th>Finding</th><th>Evidence</th></tr></thead>
<tbody>{body}</tbody></table>
</body></html>"""


def render_sarif(report: Report) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in report.active:
        rules.setdefault(
            f.check_id,
            {
                "id": f.check_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f.remediation},
                "properties": {"cwe": f.cwe, "confidence": f.confidence.value},
                "defaultConfiguration": {"level": SARIF_LEVEL[f.severity]},
            },
        )
        results.append(
            {
                "ruleId": f.check_id,
                "level": SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title}. {f.description}"},
                "partialFingerprints": {"sentinelFingerprint": f.fingerprint},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.url},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {"severity": f.severity.value, "confidence": f.confidence.value},
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sentinel-verify",
                        "version": report.meta.version,
                        "informationUri": "https://github.com/sentinel-verify/sentinel-verify",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
