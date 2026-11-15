"""Minimal async HTTP/1.1 client with TLS control and full header access.

Every network call in the project funnels through here.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ssl
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .scope import Budget, RateLimiter, ScopePolicy

DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_BODY = 262_144
MAX_HEADER_BYTES = 65_536
MAX_REDIRECTS = 8
USER_AGENT = "sentinel-verify/0.1 (+https://github.com/sentinel-verify/sentinel-verify)"


class HttpError(Exception):
    """Transport-level failure."""


class TooManyRedirects(HttpError):
    pass


@dataclass(slots=True)
class Response:
    url: str
    method: str
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    elapsed: float
    tls_version: str = ""
    tls_cipher: str = ""
    peer_cert_der: bytes = b""
    history: list[tuple[str, int]] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        low = name.lower()
        for key, value in self.headers:
            if key.lower() == low:
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        low = name.lower()
        return [v for k, v in self.headers if k.lower() == low]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    def snippet(self, limit: int = 320) -> str:
        return self.text[:limit]

    def signature(self) -> tuple:
        """Comparison key for differential testing."""
        interesting = tuple(
            sorted(
                (k.lower(), v)
                for k, v in self.headers
                if k.lower() not in ("date", "set-cookie", "content-length", "etag", "age")
            )
        )
        return (self.status, interesting, self.sha256)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400


def _build_ssl_context(
    *, insecure: bool, tls_min: str | None, tls_max: str | None, ciphers: str | None
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    versions = {
        "1.0": ssl.TLSVersion.TLSv1,
        "1.1": ssl.TLSVersion.TLSv1_1,
        "1.2": ssl.TLSVersion.TLSv1_2,
        "1.3": ssl.TLSVersion.TLSv1_3,
    }
    if tls_min:
        ctx.minimum_version = versions[tls_min]
    if tls_max:
        ctx.maximum_version = versions[tls_max]
    if ciphers:
        try:
            ctx.set_ciphers(ciphers)
        except ssl.SSLError as exc:
            raise HttpError(f"bad cipher string: {exc}") from exc
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_default_certs()
    return ctx


class HttpClient:
    """Concurrency-, rate- and scope-aware HTTP client."""

    def __init__(
        self,
        *,
        policy: ScopePolicy,
        budget: Budget,
        limiter: RateLimiter,
        concurrency: int = 8,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = 2,
        insecure: bool = False,
        user_agent: str = USER_AGENT,
        default_headers: Iterable[tuple[str, str]] = (),
    ) -> None:
        self.policy = policy
        self.budget = budget
        self.limiter = limiter
        self.timeout = timeout
        self.retries = retries
        self.insecure = insecure
        self.user_agent = user_agent
        self.default_headers = list(default_headers)
        self._sem = asyncio.Semaphore(concurrency)
        self.request_log: list[str] = []

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Iterable[tuple[str, str]] = (),
        body: bytes | None = None,
        timeout: float | None = None,
        tls_min: str | None = None,
        tls_max: str | None = None,
        ciphers: str | None = None,
        max_body: int = DEFAULT_MAX_BODY,
        follow_redirects: bool = True,
        read_body: bool = True,
    ) -> Response:
        history: list[tuple[str, int]] = []
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            resp = await self._once(
                method,
                current,
                headers=list(headers),
                body=body,
                timeout=timeout,
                tls_min=tls_min,
                tls_max=tls_max,
                ciphers=ciphers,
                max_body=max_body,
                read_body=read_body,
            )
            resp.history = list(history)
            if not follow_redirects or resp.status not in (301, 302, 303, 307, 308):
                return resp
            location = resp.header("location")
            if not location:
                return resp
            nxt = _absolutize(current, location)
            host = urlsplit(nxt).hostname or ""
            try:
                self.policy.assert_redirect_allowed(host)
            except Exception:
                resp.evidence_blocked = True  # type: ignore[attr-defined]
                return resp
            history.append((current, resp.status))
            current = nxt
            if resp.status == 303:
                method, body = "GET", None
        raise TooManyRedirects(f"more than {MAX_REDIRECTS} redirects from {url}")

    async def _once(
        self,
        method: str,
        url: str,
        *,
        headers: list[tuple[str, str]],
        body: bytes | None,
        timeout: float | None,
        tls_min: str | None,
        tls_max: str | None,
        ciphers: str | None,
        max_body: int,
        read_body: bool,
    ) -> Response:
        parts = urlsplit(url)
        host = parts.hostname or ""
        self.policy.assert_allowed(host)
        tls = parts.scheme == "https"
        port = parts.port or (443 if tls else 80)
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")

        await self.budget.spend()
        await self.limiter.acquire()

        merged = [("Host", host if port in (80, 443) else f"{host}:{port}")]
        merged.append(("User-Agent", self.user_agent))
        merged.append(("Accept", "*/*"))
        merged.append(("Accept-Encoding", "identity"))
        merged.append(("Connection", "close"))
        merged.extend(self.default_headers)
        merged.extend(headers)
        if body is not None:
            merged.append(("Content-Length", str(len(body))))

        head = f"{method} {target} HTTP/1.1\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in merged) + "\r\n"
        self.request_log.append(f"{method} {url}")

        deadline = timeout if timeout is not None else self.timeout
        ctx = _build_ssl_context(
            insecure=self.insecure, tls_min=tls_min, tls_max=tls_max, ciphers=ciphers
        )

        async def _do() -> Response:
            loop = asyncio.get_running_loop()
            started = loop.time()
            try:
                reader, writer = await asyncio.open_connection(
                    host, port, ssl=ctx if tls else None, server_hostname=host if tls else None
                )
            except (OSError, ssl.SSLError) as exc:
                raise HttpError(f"connect failed for {host}:{port}: {exc}") from exc
            try:
                writer.write(head.encode("latin-1") + (body or b""))
                await writer.drain()
                status, reason, hdrs = await _read_head(reader)
                raw = b""
                if read_body:
                    raw = await _read_body(reader, hdrs, max_body)
                elapsed = loop.time() - started
                tls_version = tls_cipher = ""
                cert = b""
                if tls:
                    info = writer.get_extra_info("ssl_object")
                    if info is not None:
                        tls_version = info.version() or ""
                        cipher = info.cipher()
                        tls_cipher = cipher[0] if cipher else ""
                        cert = info.getpeercert(binary_form=True) or b""
                return Response(
                    url=url,
                    method=method,
                    status=status,
                    reason=reason,
                    headers=hdrs,
                    body=raw,
                    elapsed=elapsed,
                    tls_version=tls_version,
                    tls_cipher=tls_cipher,
                    peer_cert_der=cert,
                )
            finally:
                writer.close()
                with contextlib.suppress(OSError, ssl.SSLError):
                    await writer.wait_closed()

        attempt = 0
        while True:
            async with self._sem:
                try:
                    return await asyncio.wait_for(_do(), timeout=deadline)
                except asyncio.TimeoutError as exc:
                    if attempt >= self.retries:
                        raise HttpError(f"timeout after {deadline}s for {url}") from exc
                except HttpError:
                    if attempt >= self.retries:
                        raise
            attempt += 1
            await asyncio.sleep(min(2 ** attempt, 8) * 0.25)


async def _read_head(reader: asyncio.StreamReader) -> tuple[int, str, list[tuple[str, str]]]:
    line = await reader.readline()
    if not line:
        raise HttpError("empty response")
    try:
        text = line.decode("latin-1").rstrip("\r\n")
        _, status_s, *reason_parts = text.split(" ", 2)
        status = int(status_s)
        reason = reason_parts[0] if reason_parts else ""
    except (ValueError, UnicodeDecodeError) as exc:
        raise HttpError(f"malformed status line: {line[:80]!r}") from exc

    headers: list[tuple[str, str]] = []
    total = 0
    while True:
        hline = await reader.readline()
        if not hline or hline in (b"\r\n", b"\n"):
            break
        total += len(hline)
        if total > MAX_HEADER_BYTES:
            raise HttpError("response headers too large")
        decoded = hline.decode("latin-1").rstrip("\r\n")
        if decoded[:1] in (" ", "\t") and headers:
            k, v = headers[-1]
            headers[-1] = (k, f"{v} {decoded.strip()}")
            continue
        if ":" not in decoded:
            continue
        name, _, value = decoded.partition(":")
        headers.append((name.strip(), value.strip()))
    return status, reason, headers


async def _read_body(
    reader: asyncio.StreamReader, headers: list[tuple[str, str]], max_body: int
) -> bytes:
    lookup = {k.lower(): v for k, v in headers}
    if lookup.get("transfer-encoding", "").lower().startswith("chunked"):
        return await _read_chunked(reader, max_body)
    if "content-length" in lookup:
        try:
            want = min(int(lookup["content-length"]), max_body)
        except ValueError:
            want = max_body
        if want <= 0:
            return b""
        try:
            return await reader.readexactly(want)
        except asyncio.IncompleteReadError as exc:
            return exc.partial
    chunks: list[bytes] = []
    size = 0
    while size < max_body:
        piece = await reader.read(min(16384, max_body - size))
        if not piece:
            break
        chunks.append(piece)
        size += len(piece)
    return b"".join(chunks)


async def _read_chunked(reader: asyncio.StreamReader, max_body: int) -> bytes:
    out: list[bytes] = []
    size = 0
    while size < max_body:
        line = await reader.readline()
        if not line:
            break
        try:
            length = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            break
        if length == 0:
            break
        try:
            chunk = await reader.readexactly(length)
        except asyncio.IncompleteReadError as exc:
            out.append(exc.partial)
            break
        out.append(chunk)
        size += len(chunk)
        await reader.readline()
    return b"".join(out)


def _absolutize(base: str, location: str) -> str:
    from urllib.parse import urljoin

    return urljoin(base, location)
