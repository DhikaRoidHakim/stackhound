import ssl
from collections.abc import AsyncIterator, Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
import respx

from shound.config import Settings
from shound.core.headers_tls import audit_tls
from shound.core.models import Finding, Severity
from shound.core.preflight import PreflightResult
from shound.core.session import HttpResponse, TargetSession, TlsHandshake, TlsInfo

HTTPS = "https://target.test/"


def preflight(
    url: str = HTTPS,
    tls: TlsInfo | None = None,
    history: tuple[tuple[str, int], ...] = (),
) -> PreflightResult:
    response = HttpResponse("GET", url, 200, httpx.Headers(), b"", False, history, tls)
    return PreflightResult(target=url, addresses=("203.0.113.1",), response=response)


def verified(days: int) -> TlsInfo:
    not_after = datetime.now(timezone.utc) + timedelta(days=days, hours=1)
    return TlsInfo("TLSv1.3", "X", True, subject_cn="target.test", not_after=not_after)


def by_id(findings: list[Finding]) -> dict[str, Finding]:
    return {f.id: f for f in findings}


class FakeHandshakes:
    """Scripted answers for TargetSession.tls_handshake, keyed by (verify, version)."""

    def __init__(self, answers: dict[tuple[bool, ssl.TLSVersion | None], TlsHandshake]) -> None:
        self.answers = answers
        self.calls: list[tuple[bool, ssl.TLSVersion | None]] = []

    async def __call__(
        self, host: str, port: int, *, verify: bool, version: ssl.TLSVersion | None = None
    ) -> TlsHandshake:
        self.calls.append((verify, version))
        return self.answers.get((verify, version), TlsHandshake(False, error="reset"))


@pytest.fixture
def mock() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        router.get("http://target.test/").respond(301, headers={"Location": HTTPS})
        yield router


@pytest.fixture
async def session() -> AsyncIterator[TargetSession]:
    async with TargetSession(Settings(rate_limit=20)) as s:
        yield s


def install(monkeypatch: pytest.MonkeyPatch, session: TargetSession, fake: Any) -> None:
    monkeypatch.setattr(session, "tls_handshake", fake)


class TestPlainHttp:
    async def test_http_site_is_low_without_extra_traffic(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        audit = await audit_tls(session, preflight("http://target.test/"))
        [finding] = audit.findings
        assert (finding.id, finding.severity) == ("SH-04.HTTP", Severity.LOW)
        assert session.request_count == 0


class TestCertificate:
    async def test_verified_and_healthy(
        self, mock: respx.MockRouter, session: TargetSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = FakeHandshakes({})
        install(monkeypatch, session, fake)
        audit = await audit_tls(session, preflight(tls=verified(90)))
        assert audit.findings == []
        # Already verified by the request itself: only the two legacy probes run.
        assert fake.calls == [(False, ssl.TLSVersion.TLSv1), (False, ssl.TLSVersion.TLSv1_1)]

    async def test_expiring_soon(
        self, mock: respx.MockRouter, session: TargetSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        install(monkeypatch, session, FakeHandshakes({}))
        audit = await audit_tls(session, preflight(tls=verified(10)))
        finding = by_id(audit.findings)["SH-04.EXPIRY"]
        assert finding.severity is Severity.MEDIUM
        assert "10 hari" in finding.description

    async def test_insecure_mode_invalid_certificate(
        self, mock: respx.MockRouter, session: TargetSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = FakeHandshakes({(True, None): TlsHandshake(False, error="self-signed certificate")})
        install(monkeypatch, session, fake)
        unverified = TlsInfo("TLSv1.3", "X", verified=False)
        audit = await audit_tls(session, preflight(tls=unverified))
        finding = by_id(audit.findings)["SH-04.CERT"]
        assert finding.severity is Severity.HIGH
        assert "self-signed certificate" in finding.description

    async def test_insecure_mode_valid_certificate_still_checks_expiry(
        self, mock: respx.MockRouter, session: TargetSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = FakeHandshakes({(True, None): TlsHandshake(True, info=verified(5))})
        install(monkeypatch, session, fake)
        audit = await audit_tls(session, preflight(tls=TlsInfo("TLSv1.3", "X", verified=False)))
        assert set(by_id(audit.findings)) == {"SH-04.EXPIRY"}


class TestLegacyProtocols:
    async def test_legacy_accepted(
        self, mock: respx.MockRouter, session: TargetSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = FakeHandshakes(
            {
                (False, ssl.TLSVersion.TLSv1): TlsHandshake(True),
                (False, ssl.TLSVersion.TLSv1_1): TlsHandshake(True),
            }
        )
        install(monkeypatch, session, fake)
        audit = await audit_tls(session, preflight(tls=verified(90)))
        finding = by_id(audit.findings)["SH-04.LEGACY"]
        assert finding.severity is Severity.MEDIUM
        assert [e.snippet for e in finding.evidence] == [
            "target.test:443 menerima TLS 1.0",
            "target.test:443 menerima TLS 1.1",
        ]

    async def test_untestable_locally_is_a_note_not_a_pass(
        self, mock: respx.MockRouter, session: TargetSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        unsupported = TlsHandshake(None, error="tidak didukung OpenSSL lokal")
        fake = FakeHandshakes(
            {
                (False, ssl.TLSVersion.TLSv1): unsupported,
                (False, ssl.TLSVersion.TLSv1_1): unsupported,
            }
        )
        install(monkeypatch, session, fake)
        audit = await audit_tls(session, preflight(tls=verified(90)))
        assert audit.findings == []
        assert len([n for n in audit.notes if "tidak dapat diuji" in n]) == 2

    async def test_proxy_skips_direct_handshakes(self, mock: respx.MockRouter) -> None:
        async with TargetSession(Settings(proxy="http://proxy.test:3128")) as s:
            audit = await audit_tls(s, preflight(tls=verified(90)))
            assert any("proxy" in n for n in audit.notes)
            result = await s.tls_handshake("target.test", 443, verify=True)
        assert result.accepted is None


class TestHttpRedirect:
    async def test_redirect_to_https_passes(
        self, mock: respx.MockRouter, session: TargetSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        install(monkeypatch, session, FakeHandshakes({}))
        audit = await audit_tls(session, preflight(tls=verified(90)))
        assert "SH-04.HTTP" not in by_id(audit.findings)
        assert mock.calls.last.request.url == "http://target.test/"

    async def test_plain_http_served(
        self, mock: respx.MockRouter, session: TargetSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock.get("http://target.test/").respond(200, text="hello")
        install(monkeypatch, session, FakeHandshakes({}))
        finding = by_id((await audit_tls(session, preflight(tls=verified(90)))).findings)[
            "SH-04.HTTP"
        ]
        assert finding.evidence[0].snippet == "GET http://target.test/ -> 200"

    async def test_redirect_to_http_elsewhere_flagged(
        self, mock: respx.MockRouter, session: TargetSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock.get("http://target.test/").respond(
            302, headers={"Location": "http://www.target.test/"}
        )
        install(monkeypatch, session, FakeHandshakes({}))
        audit = await audit_tls(session, preflight(tls=verified(90)))
        assert "SH-04.HTTP" in by_id(audit.findings)

    async def test_port_80_closed_is_a_note(
        self, mock: respx.MockRouter, session: TargetSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock.get("http://target.test/").mock(side_effect=httpx.ConnectError("refused"))
        install(monkeypatch, session, FakeHandshakes({}))
        audit = await audit_tls(session, preflight(tls=verified(90)))
        assert audit.findings == []
        assert any("Port 80" in n for n in audit.notes)

    async def test_redirect_already_seen_in_preflight(
        self, mock: respx.MockRouter, session: TargetSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        install(monkeypatch, session, FakeHandshakes({}))
        history = (("http://target.test/", 301),)
        await audit_tls(session, preflight(tls=verified(90), history=history))
        assert mock.calls.call_count == 0

    async def test_non_standard_port_skipped(
        self, mock: respx.MockRouter, session: TargetSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        install(monkeypatch, session, FakeHandshakes({}))
        audit = await audit_tls(session, preflight("https://target.test:8443/", tls=verified(90)))
        assert mock.calls.call_count == 0
        assert any("8443" in n or "443" in n for n in audit.notes)
