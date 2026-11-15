from __future__ import annotations

import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")


class TlsHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # noqa: ANN002
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b"<html>tls</html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def tls_url(tmp_path_factory: pytest.TempPathFactory) -> str:
    directory = tmp_path_factory.mktemp("tls")
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), TlsHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    yield f"https://{host}:{port}"
    httpd.shutdown()


def test_tls_handshake_metadata(tls_url: str) -> None:
    import asyncio

    from sentinel.http import HttpClient
    from sentinel.scope import Budget, RateLimiter, ScopePolicy

    client = HttpClient(
        policy=ScopePolicy("127.0.0.1", allow_private=True),
        budget=Budget(5),
        limiter=RateLimiter(1000),
        insecure=True,
    )
    resp = asyncio.run(client.request("GET", tls_url + "/"))
    assert resp.tls_version.startswith("TLS")
    assert resp.tls_cipher
    assert resp.peer_cert_der


def test_chain_fails_without_insecure(tls_url: str) -> None:
    import asyncio

    from sentinel.http import HttpClient, HttpError
    from sentinel.scope import Budget, RateLimiter, ScopePolicy

    client = HttpClient(
        policy=ScopePolicy("127.0.0.1", allow_private=True),
        budget=Budget(5),
        limiter=RateLimiter(1000),
        insecure=False,
        retries=0,
    )
    with pytest.raises(HttpError):
        asyncio.run(client.request("GET", tls_url + "/"))