"""Pre-flight against a real local HTTPS server with a self-signed certificate.

Runs with the normal test suite (loopback only); skipped when the ``openssl`` CLI
is not available to create the throwaway certificate.
"""

import http.server
import os
import shutil
import ssl
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from shound.config import Settings
from shound.core.preflight import run_preflight
from shound.core.session import TargetSession
from shound.errors import PreflightError

OPENSSL = shutil.which("openssl")
pytestmark = pytest.mark.skipif(OPENSSL is None, reason="openssl CLI not available")


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"<title>TLS fixture</title>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def https_url(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    assert OPENSSL is not None
    workdir: Path = tmp_path_factory.mktemp("tls")
    cert, key, conf = workdir / "cert.pem", workdir / "key.pem", workdir / "openssl.cnf"
    # Own minimal config: a machine-wide OPENSSL_CONF may point to a missing file.
    conf.write_text("[req]\ndistinguished_name = dn\n[dn]\n", encoding="ascii")
    env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
    subprocess.run(
        [
            OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-config", str(conf),
            "-keyout", str(key), "-out", str(cert), "-days", "10",
            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
        env=env,
    )  # fmt: skip
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()


async def test_self_signed_certificate_fails_with_hint(https_url: str) -> None:
    async with TargetSession(Settings()) as session:
        with pytest.raises(PreflightError, match="--insecure"):
            await run_preflight(https_url, session)


async def test_insecure_connects_and_records_tls(https_url: str) -> None:
    async with TargetSession(Settings(), insecure=True) as session:
        result = await run_preflight(https_url, session)
    assert result.response.status_code == 200
    assert result.tls is not None
    assert result.tls.version in {"TLSv1.2", "TLSv1.3"}
    assert result.tls.cipher
    assert result.tls.verified is False
    assert any("--insecure" in warning for warning in result.warnings)
