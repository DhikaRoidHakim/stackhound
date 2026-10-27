"""Pre-flight and SH-04 against real local HTTPS servers with a self-signed
certificate: one modern (TLS >= 1.2) and one that still accepts TLS 1.0/1.1.

Runs with the normal test suite (loopback only); skipped when the ``openssl`` CLI
is not available to create the throwaway certificate.
"""

import http.server
import os
import shutil
import ssl
import subprocess
import threading
import warnings
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest

from shound.config import Settings
from shound.core.headers_tls import audit_tls
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
def certificate(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
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
    return cert, key


def _serve(certificate: tuple[Path, Path], *, legacy: bool) -> Iterator[str]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*certificate)
    if legacy:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
            context.minimum_version = ssl.TLSVersion.TLSv1
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="module")
def modern_url(certificate: tuple[Path, Path]) -> Iterator[str]:
    yield from _serve(certificate, legacy=False)


@pytest.fixture(scope="module")
def legacy_url(certificate: tuple[Path, Path]) -> Iterator[str]:
    yield from _serve(certificate, legacy=True)


@pytest.fixture
async def insecure_session() -> AsyncIterator[TargetSession]:
    async with TargetSession(Settings(rate_limit=20), insecure=True) as session:
        yield session


def host_port(url: str) -> tuple[str, int]:
    host, port = url.removeprefix("https://").rstrip("/").split(":")
    return host, int(port)


class TestPreflight:
    async def test_self_signed_certificate_fails_with_hint(self, modern_url: str) -> None:
        async with TargetSession(Settings()) as session:
            with pytest.raises(PreflightError, match="--insecure"):
                await run_preflight(modern_url, session)

    async def test_insecure_connects_and_records_tls(
        self, modern_url: str, insecure_session: TargetSession
    ) -> None:
        result = await run_preflight(modern_url, insecure_session)
        assert result.response.status_code == 200
        assert result.tls is not None
        assert result.tls.version in {"TLSv1.2", "TLSv1.3"}
        assert result.tls.cipher
        assert result.tls.verified is False
        assert any("--insecure" in warning for warning in result.warnings)


class TestHandshake:
    async def test_verification_failure_reason(
        self, modern_url: str, insecure_session: TargetSession
    ) -> None:
        result = await insecure_session.tls_handshake(*host_port(modern_url), verify=True)
        assert result.accepted is False
        assert result.error is not None
        assert "self" in result.error.lower()

    async def test_modern_server_rejects_legacy(
        self, modern_url: str, insecure_session: TargetSession
    ) -> None:
        for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            result = await insecure_session.tls_handshake(
                *host_port(modern_url), verify=False, version=version
            )
            assert result.accepted is False, version

    async def test_legacy_server_accepts_legacy(
        self, legacy_url: str, insecure_session: TargetSession
    ) -> None:
        result = await insecure_session.tls_handshake(
            *host_port(legacy_url), verify=False, version=ssl.TLSVersion.TLSv1
        )
        assert result.accepted is True
        assert result.info is not None
        assert result.info.version == "TLSv1"


class TestAuditTls:
    async def test_modern_self_signed(
        self, modern_url: str, insecure_session: TargetSession
    ) -> None:
        result = await run_preflight(modern_url, insecure_session)
        audit = await audit_tls(insecure_session, result)
        assert [f.id for f in audit.findings] == ["SH-04.CERT"]
        assert any("443" in note for note in audit.notes)  # non-standard port: no HTTP probe

    async def test_legacy_self_signed(
        self, legacy_url: str, insecure_session: TargetSession
    ) -> None:
        result = await run_preflight(legacy_url, insecure_session)
        audit = await audit_tls(insecure_session, result)
        found = {f.id: f for f in audit.findings}
        assert set(found) == {"SH-04.CERT", "SH-04.LEGACY"}
        assert [e.snippet for e in found["SH-04.LEGACY"].evidence] == [
            f"127.0.0.1:{host_port(legacy_url)[1]} menerima TLS 1.0",
            f"127.0.0.1:{host_port(legacy_url)[1]} menerima TLS 1.1",
        ]
