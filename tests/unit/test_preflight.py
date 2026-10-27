import dataclasses
import ssl
from collections.abc import AsyncIterator, Iterator
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

import httpx
import pytest
import respx

from shound.config import Settings
from shound.core.preflight import run_preflight
from shound.core.session import HttpResponse, TargetSession, TlsInfo
from shound.errors import PreflightError

TARGET = "https://target.test/"


async def resolver(host: str, port: int) -> list[str]:
    assert (host, port) == ("target.test", 443)
    return ["203.0.113.10"]


async def failing_resolver(host: str, port: int) -> list[str]:
    raise OSError(11001, "getaddrinfo failed")


async def empty_resolver(host: str, port: int) -> list[str]:
    return []


@pytest.fixture
def mock() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        yield router


@pytest.fixture
async def session() -> AsyncIterator[TargetSession]:
    async with TargetSession(Settings()) as s:
        yield s


class TestSuccess:
    async def test_result(self, mock: respx.MockRouter, session: TargetSession) -> None:
        mock.get(TARGET).respond(200, text="<title>Home</title>")
        result = await run_preflight(TARGET, session, resolve=resolver)
        assert result.addresses == ("203.0.113.10",)
        assert result.response.status_code == 200
        assert result.final_url == TARGET
        assert result.warnings == ()

    async def test_same_host_redirect_followed(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        mock.get(TARGET).respond(302, headers={"Location": "/login"})
        mock.get(f"{TARGET}login").respond(200)
        result = await run_preflight(TARGET, session, resolve=resolver)
        assert result.final_url == f"{TARGET}login"
        assert result.response.history == ((TARGET, 302),)

    async def test_other_host_redirect_warns(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        mock.get(TARGET).respond(301, headers={"Location": "https://other.test/"})
        result = await run_preflight(TARGET, session, resolve=resolver)
        assert result.response.status_code == 301
        assert any("other.test" in w and "tidak diikuti" in w for w in result.warnings)

    async def test_server_error_still_reachable(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        mock.get(TARGET).respond(500)
        result = await run_preflight(TARGET, session, resolve=resolver)
        assert any("HTTP 500" in w for w in result.warnings)

    async def test_proxy_skips_local_dns(self, mock: respx.MockRouter) -> None:
        mock.get(TARGET).respond(200)
        async with TargetSession(Settings(proxy="http://proxy.test:3128")) as s:
            result = await run_preflight(TARGET, s, resolve=failing_resolver)
        assert result.addresses == ()
        assert any("proxy" in w for w in result.warnings)


class TestFailures:
    async def test_dns_failure(self, mock: respx.MockRouter, session: TargetSession) -> None:
        route = mock.get(TARGET).respond(200)
        with pytest.raises(PreflightError, match="Resolusi DNS"):
            await run_preflight(TARGET, session, resolve=failing_resolver)
        assert route.call_count == 0

    async def test_dns_without_addresses(self, session: TargetSession) -> None:
        with pytest.raises(PreflightError, match="tidak menghasilkan alamat"):
            await run_preflight(TARGET, session, resolve=empty_resolver)

    async def test_unreachable(self, mock: respx.MockRouter, session: TargetSession) -> None:
        mock.get(TARGET).mock(side_effect=httpx.ConnectError("All connection attempts failed"))
        with pytest.raises(PreflightError, match="tidak dapat dihubungi"):
            await run_preflight(TARGET, session, resolve=resolver)

    async def test_certificate_failure_suggests_insecure(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        mock.get(TARGET).mock(
            side_effect=httpx.ConnectError(
                "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
                "self-signed certificate"
            )
        )
        with pytest.raises(PreflightError, match="--insecure"):
            await run_preflight(TARGET, session, resolve=resolver)


class TestTlsWarnings:
    @staticmethod
    def patch_tls(monkeypatch: pytest.MonkeyPatch, session: TargetSession, tls: TlsInfo) -> None:
        response = HttpResponse("GET", TARGET, 200, httpx.Headers(), b"", False, tls=tls)

        async def fake_get(url: str, **kwargs: Any) -> HttpResponse:
            return response

        monkeypatch.setattr(session, "get", fake_get)

    @pytest.mark.parametrize(
        ("days", "expected"), [(10, "kedaluwarsa dalam"), (-3, "sudah kedaluwarsa"), (90, None)]
    )
    async def test_expiry(
        self,
        monkeypatch: pytest.MonkeyPatch,
        session: TargetSession,
        days: int,
        expected: str | None,
    ) -> None:
        not_after = datetime.now(timezone.utc) + timedelta(days=days, hours=1)
        self.patch_tls(monkeypatch, session, TlsInfo("TLSv1.3", "X", True, not_after=not_after))
        result = await run_preflight(TARGET, session, resolve=resolver)
        messages = " ".join(result.warnings)
        if expected is None:
            assert "kedaluwarsa" not in messages
        else:
            assert expected in messages

    async def test_insecure_warns(
        self, monkeypatch: pytest.MonkeyPatch, session: TargetSession
    ) -> None:
        self.patch_tls(monkeypatch, session, TlsInfo("TLSv1.2", "X", verified=False))
        result = await run_preflight(TARGET, session, resolve=resolver)
        assert any("--insecure" in w for w in result.warnings)


class FakeSslObject:
    def __init__(self, cert: dict[str, Any], verify_mode: ssl.VerifyMode) -> None:
        self._cert = cert
        self.context = dataclasses.make_dataclass("Ctx", ["verify_mode"])(verify_mode)

    def getpeercert(self) -> dict[str, Any]:
        return self._cert

    def cipher(self) -> tuple[str, str, int]:
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def version(self) -> str:
        return "TLSv1.3"


class TestTlsInfo:
    CERT: ClassVar[dict[str, Any]] = {
        "subject": ((("commonName", "target.test"),),),
        "issuer": ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),)),
        "notAfter": "Jan 30 12:00:00 2027 GMT",
        "subjectAltName": (("DNS", "target.test"), ("DNS", "www.target.test"), ("IP", "1.2.3.4")),
    }

    def test_parses_verified_certificate(self) -> None:
        info = TlsInfo.from_ssl_object(FakeSslObject(self.CERT, ssl.CERT_REQUIRED))  # type: ignore[arg-type]
        assert info.version == "TLSv1.3"
        assert info.cipher == "TLS_AES_256_GCM_SHA384"
        assert info.verified is True
        assert info.subject_cn == "target.test"
        assert info.issuer == "Let's Encrypt"
        assert info.not_after == datetime(2027, 1, 30, 12, tzinfo=timezone.utc)
        assert info.san == ("target.test", "www.target.test")
        assert info.days_remaining(datetime(2027, 1, 20, 12, tzinfo=timezone.utc)) == 10

    def test_unverified_has_no_certificate_details(self) -> None:
        info = TlsInfo.from_ssl_object(FakeSslObject({}, ssl.CERT_NONE))  # type: ignore[arg-type]
        assert info.verified is False
        assert info.subject_cn is None
        assert info.not_after is None
        assert info.days_remaining() is None
