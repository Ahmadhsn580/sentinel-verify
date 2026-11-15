"""Exposed file and endpoint checks."""

from __future__ import annotations

from ..http import HttpError
from ..models import Confidence, Severity, Tier
from ..verify import Engine
from .base import Check, register


async def _probe(engine: Engine, path: str) -> tuple[bool, object]:
    try:
        resp = await engine.fetch(engine.target.with_path(path), follow_redirects=False)
    except HttpError:
        return False, None
    if resp.status != 200:
        return False, resp
    if "text/html" in (resp.header("content-type") or "") and len(resp.body) < 120:
        return False, resp
    return True, resp


@register
class GitExposure(Check):
    id = "exp.git"
    title = "Exposed .git directory"
    cwe = "CWE-538"
    tier = Tier.SAFE
    description = "Source repository metadata is downloadable, enabling full source recovery."

    async def run(self, engine: Engine) -> None:
        for path, marker in (("/.git/HEAD", "ref:"), ("/.git/config", "[core]")):
            ok, resp = await _probe(engine, path)
            if ok and marker in resp.text:  # type: ignore[union-attr]
                engine.record(
                    check_id=self.id,
                    title=f"Git metadata exposed at {path}",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    cwe=self.cwe,
                    description=f"{path} served a valid git file; the repository can be reconstructed.",
                    remediation="Deny /.git/ at the web server or deploy from an export.",
                    response=resp,  # type: ignore[arg-type]
                )
                return


@register
class EnvExposure(Check):
    id = "exp.env"
    title = "Exposed environment file"
    cwe = "CWE-538"
    tier = Tier.SAFE
    description = "A dotenv or config file leaks secrets."

    async def run(self, engine: Engine) -> None:
        for path in ("/.env", "/.env.local", "/.env.production", "/config.php.bak"):
            ok, resp = await _probe(engine, path)
            if not ok:
                continue
            text = resp.text  # type: ignore[union-attr]
            if "=" not in text:
                continue
            keys = [
                line.split("=", 1)[0]
                for line in text.splitlines()
                if "=" in line and not line.strip().startswith("#")
            ][:8]
            engine.record(
                check_id=self.id,
                title=f"Environment file exposed at {path}",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"Keys disclosed: {', '.join(keys) or 'n/a'}",
                remediation="Move dotfiles outside the document root or deny them explicitly.",
                response=resp,  # type: ignore[arg-type]
            )
            return


@register
class Dotfiles(Check):
    id = "exp.dotfiles"
    title = "Sensitive dotfile exposed"
    cwe = "CWE-538"
    tier = Tier.STANDARD
    description = "Editor, CI or OS metadata is publicly readable."

    async def run(self, engine: Engine) -> None:
        for path, marker in (
            ("/.DS_Store", b"\x00\x00\x00\x01"),
            ("/.gitignore", "node_modules"),
            ("/.htaccess", "RewriteEngine"),
            ("/.dockerignore", ""),
            ("/Dockerfile", "FROM "),
        ):
            try:
                resp = await engine.fetch(engine.target.with_path(path), follow_redirects=False)
            except HttpError:
                continue
            if resp.status != 200:
                continue
            body = resp.body if isinstance(marker, bytes) else resp.text
            if marker and marker not in body:
                continue
            engine.record(
                check_id=f"{self.id}.{path.strip('/.').replace('.', '_')}",
                title=f"Exposed {path}",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"{path} is served with status 200 and expected content.",
                remediation="Deny dotfiles and build descriptors at the web root.",
                response=resp,
            )


@register
class Backups(Check):
    id = "exp.backups"
    title = "Backup or archive file exposed"
    cwe = "CWE-530"
    tier = Tier.STANDARD
    description = "Common backup extensions return archives or dumps."

    async def run(self, engine: Engine) -> None:
        stem = engine.target.path.rsplit("/", 1)[-1] or "index"
        if "." in stem:
            stem = stem.rsplit(".", 1)[0]
        base = engine.target.path.rsplit("/", 1)[0] or ""
        for suffix in (".bak", ".old", ".orig", ".swp", "~", ".zip", ".tar.gz", ".sql"):
            path = f"{base}/{stem}{suffix}"
            try:
                resp = await engine.fetch(engine.target.with_path(path), follow_redirects=False)
            except HttpError:
                continue
            if resp.status != 200 or len(resp.body) < 64:
                continue
            engine.record(
                check_id=f"{self.id}.{suffix.strip('.')}",
                title=f"Backup exposed: {path}",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"{path} returned {len(resp.body)} bytes.",
                remediation="Exclude backup extensions from the document root.",
                response=resp,
            )
            return


@register
class SourceMaps(Check):
    id = "exp.sourcemap"
    title = "JavaScript source map exposed"
    cwe = "CWE-540"
    tier = Tier.STANDARD
    description = "A .map file reveals unminified original source."

    async def run(self, engine: Engine) -> None:
        base = await engine.baseline()
        if "javascript" not in (base.header("content-type") or ""):
            return
        try:
            resp = await engine.fetch(engine.target.url + ".map", follow_redirects=False)
        except HttpError:
            return
        if resp.status != 200 or '"mappings"' not in resp.text:
            return
        engine.record(
            check_id=self.id,
            title="Source map served alongside script",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description="Original source and comments are recoverable.",
            remediation="Ship maps to a restricted path or strip sourcesContent.",
            response=resp,
        )


@register
class DirectoryListing(Check):
    id = "exp.dirlisting"
    title = "Directory listing enabled"
    cwe = "CWE-548"
    tier = Tier.SAFE
    description = "Autoindex output exposes the file inventory."

    async def run(self, engine: Engine) -> None:
        directory = engine.target.path if engine.target.path.endswith("/") else (
            engine.target.path.rsplit("/", 1)[0] + "/"
        )
        try:
            resp = await engine.fetch(engine.target.with_path(directory), follow_redirects=False)
        except HttpError:
            return
        text = resp.text.lower()
        if resp.status != 200 or "index of /" not in text:
            return
        engine.record(
            check_id=self.id,
            title="Directory index exposed",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description=f"Autoindex at {directory}",
            remediation="Disable autoindex or add index files.",
            response=resp,
        )


@register
class DebugEndpoints(Check):
    id = "exp.debug_endpoints"
    title = "Debug or management endpoint exposed"
    cwe = "CWE-489"
    tier = Tier.STANDARD
    description = "Actuator, debug or profiler endpoints answer publicly."

    async def run(self, engine: Engine) -> None:
        candidates = (
            "/actuator",
            "/actuator/env",
            "/actuator/health",
            "/debug",
            "/_profiler",
            "/server-status",
            "/metrics",
            "/swagger-ui.html",
            "/api-docs",
        )
        for path in candidates:
            try:
                resp = await engine.fetch(engine.target.with_path(path), follow_redirects=False)
            except HttpError:
                continue
            if resp.status != 200:
                continue
            engine.record(
                check_id=f"{self.id}.{path.strip('/').replace('/', '_')}",
                title=f"Debug endpoint live: {path}",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"{path} returned 200 with {len(resp.body)} bytes.",
                remediation="Bind management endpoints to internal networks or add auth.",
                response=resp,
            )