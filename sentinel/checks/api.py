"""API-surface checks: GraphQL, JWT, version disclosure."""

from __future__ import annotations

import base64
import json

from ..http import HttpError
from ..models import Confidence, Severity, Tier
from ..verify import Engine
from .base import Check, register

INTROSPECTION = {"query": "{__schema{types{name kind}}}"}


@register
class GraphqlIntrospection(Check):
    id = "api.graphql_introspection"
    title = "GraphQL introspection enabled"
    cwe = "CWE-200"
    tier = Tier.STANDARD
    description = "The full schema is queryable anonymously."

    async def run(self, engine: Engine) -> None:
        for path in ("/graphql", "/api/graphql", "/v1/graphql", "/query"):
            url = engine.target.with_path(path)
            try:
                resp = await engine.send(
                    "POST",
                    url,
                    headers=[("Content-Type", "application/json")],
                    body=json.dumps(INTROSPECTION).encode(),
                )
            except HttpError:
                continue
            if resp.status != 200:
                continue
            try:
                payload = json.loads(resp.text)
            except ValueError:
                continue
            if "data" not in payload or not payload.get("data"):
                continue
            types = payload["data"].get("__schema", {}).get("types", [])
            engine.record(
                check_id=self.id,
                title=f"GraphQL introspection open at {path}",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"{len(types)} schema types enumerated without authentication.",
                remediation="Disable introspection in production or gate it behind auth.",
                response=resp,
            )
            return


@register
class JwtAnalysis(Check):
    id = "api.jwt_analysis"
    title = "Weak JWT configuration"
    cwe = "CWE-347"
    tier = Tier.STANDARD
    description = "A token found in the response or cookies is unsigned, alg=none, or long-lived."

    async def run(self, engine: Engine) -> None:
        resp = await engine.baseline()
        candidates: list[str] = []
        for raw in resp.header_all("set-cookie"):
            for part in raw.split(";"):
                _, _, value = part.partition("=")
                if value.count(".") == 2 and len(value) > 40:
                    candidates.append(value.strip())
        import re

        candidates.extend(re.findall(r"eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{0,}", resp.text)[:3])
        for token in candidates[:3]:
            header = _decode(token.split(".")[0])
            payload = _decode(token.split(".")[1])
            if not header:
                continue
            alg = str(header.get("alg", "")).lower()
            problems = []
            if alg == "none":
                problems.append("alg=none")
            if alg.startswith("hs") and "kid" not in header:
                problems.append("HMAC without kid")
            exp = payload.get("exp")
            if exp is None:
                problems.append("no exp claim")
            if not problems:
                continue
            engine.record(
                check_id=f"{self.id}.{alg or 'unknown'}",
                title=f"JWT issue: {', '.join(problems)}",
                severity=Severity.MEDIUM if "alg=none" in problems else Severity.LOW,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"alg={alg or '(unset)'}; claims={sorted(payload)[:8]}",
                remediation="Enforce a single algorithm, validate exp, and pin keys by kid.",
                response=resp,
            )


def _decode(segment: str) -> dict:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, TypeError):
        return {}


@register
class ApiVersionDisclosure(Check):
    id = "api.version_disclosure"
    title = "API version enumeration"
    cwe = "CWE-200"
    tier = Tier.STANDARD
    description = "Multiple API versions answer, including deprecated ones."

    async def run(self, engine: Engine) -> None:
        live = []
        for version in ("v1", "v2", "v3", "v4", "beta", "internal"):
            path = f"/api/{version}"
            try:
                resp = await engine.fetch(engine.target.with_path(path), follow_redirects=False)
            except HttpError:
                continue
            if resp.status in (200, 401, 403):
                live.append(f"{version}={resp.status}")
        if len(live) < 2:
            return
        engine.record(
            check_id=self.id,
            title=f"{len(live)} API versions respond",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description=", ".join(live),
            remediation="Retire deprecated versions and document the support window.",
        )