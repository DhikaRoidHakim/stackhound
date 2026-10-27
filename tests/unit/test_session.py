import asyncio
import itertools
from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
import respx

from shound import __version__
from shound.config import DEFAULT_USER_AGENT, Settings
from shound.core.session import (
    IDENTITY_HEADER,
    MAX_BODY_BYTES,
    MAX_RETRY_AFTER,
    MIN_RATE,
    RateLimiter,
    TargetRequestError,
    TargetSession,
    UnsafeMethodError,
)

BASE = "https://target.test"


class FakeClock:
    """Deterministic monotonic clock whose sleep advances time instantly."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def mock() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        yield router


def make_session(clock: FakeClock, **settings: object) -> TargetSession:
    return TargetSession(Settings.model_validate(settings), clock=clock, sleep=clock.sleep)


@pytest.fixture
async def session(clock: FakeClock) -> AsyncIterator[TargetSession]:
    async with make_session(clock) as s:
        yield s


class TestIdentityHeaders:
    async def test_default_headers(self, mock: respx.MockRouter, session: TargetSession) -> None:
        route = mock.get(f"{BASE}/").respond(200)
        await session.get(f"{BASE}/")
        sent = route.calls.last.request.headers
        assert sent["user-agent"] == DEFAULT_USER_AGENT
        assert sent[IDENTITY_HEADER] == f"StackHound/{__version__}"

    async def test_identity_header_kept_with_custom_user_agent(
        self, mock: respx.MockRouter, clock: FakeClock
    ) -> None:
        route = mock.get(f"{BASE}/").respond(200)
        async with make_session(clock, user_agent="Custom/1.0") as s:
            await s.get(f"{BASE}/")
        sent = route.calls.last.request.headers
        assert sent["user-agent"] == "Custom/1.0"
        assert sent[IDENTITY_HEADER] == f"StackHound/{__version__}"

    async def test_caller_cannot_override_identity(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        route = mock.get(f"{BASE}/").respond(200)
        await session.get(
            f"{BASE}/",
            headers={IDENTITY_HEADER: "nope", "User-Agent": "spoof", "Origin": "https://o.test"},
        )
        sent = route.calls.last.request.headers
        assert sent.get_list(IDENTITY_HEADER) == [f"StackHound/{__version__}"]
        assert sent["user-agent"] == DEFAULT_USER_AGENT
        assert sent["origin"] == "https://o.test"  # other caller headers pass through


class TestMethodWhitelist:
    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "get"])
    async def test_safe_methods_allowed(
        self, mock: respx.MockRouter, session: TargetSession, method: str
    ) -> None:
        mock.route(url=f"{BASE}/").respond(200)
        response = await session.request(method, f"{BASE}/")
        assert response.method == method.upper()

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "TRACE"])
    async def test_unsafe_methods_rejected_without_io(
        self, mock: respx.MockRouter, session: TargetSession, method: str
    ) -> None:
        route = mock.route(url=f"{BASE}/").respond(200)
        with pytest.raises(UnsafeMethodError):
            await session.request(method, f"{BASE}/")
        assert route.call_count == 0
        assert session.request_count == 0


class TestPatchProbe:
    async def test_patch_sent_when_allow_excludes_patch(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        mock.options(f"{BASE}/").respond(200, headers={"Allow": "GET, HEAD, OPTIONS"})
        patch = mock.patch(f"{BASE}/").respond(405, text="ignition")
        response = await session.probe_patch(f"{BASE}/")
        assert response is not None
        assert response.status_code == 405
        sent = patch.calls.last.request
        assert sent.content == b""
        assert sent.headers.get("content-length") == "0"
        assert "content-type" not in sent.headers

    @pytest.mark.parametrize("allow", ["GET, PATCH", "get,patch,head"])
    async def test_skipped_when_patch_allowed(
        self, mock: respx.MockRouter, session: TargetSession, allow: str
    ) -> None:
        mock.options(f"{BASE}/").respond(200, headers={"Allow": allow})
        patch = mock.patch(f"{BASE}/").respond(405)
        assert await session.probe_patch(f"{BASE}/") is None
        assert patch.call_count == 0

    async def test_skipped_when_allow_missing(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        mock.options(f"{BASE}/").respond(200)
        patch = mock.patch(f"{BASE}/").respond(405)
        assert await session.probe_patch(f"{BASE}/") is None
        assert patch.call_count == 0

    async def test_disabled_sends_nothing(self, mock: respx.MockRouter, clock: FakeClock) -> None:
        options = mock.options(f"{BASE}/").respond(200, headers={"Allow": "GET"})
        async with TargetSession(
            Settings(), method_probe=False, clock=clock, sleep=clock.sleep
        ) as s:
            assert await s.probe_patch(f"{BASE}/") is None
        assert options.call_count == 0


class TestBodyCap:
    async def test_large_body_truncated(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        mock.get(f"{BASE}/big").respond(200, content=b"a" * (MAX_BODY_BYTES + 4096))
        response = await session.get(f"{BASE}/big")
        assert len(response.body) == MAX_BODY_BYTES
        assert response.truncated is True

    async def test_small_body_intact(self, mock: respx.MockRouter, session: TargetSession) -> None:
        mock.get(f"{BASE}/").respond(
            200,
            content="héllo".encode("latin-1"),
            headers={"Content-Type": "text/html; charset=latin-1"},
        )
        response = await session.get(f"{BASE}/")
        assert response.truncated is False
        assert response.text == "héllo"


class TestRateLimit:
    async def test_limiter_spaces_requests(self, clock: FakeClock) -> None:
        limiter = RateLimiter(5, clock=clock, sleep=clock.sleep)
        stamps = []
        for _ in range(10):
            await limiter.acquire()
            stamps.append(clock.now)
        gaps = [b - a for a, b in itertools.pairwise(stamps)]
        assert all(gap == pytest.approx(0.2) for gap in gaps)

    async def test_concurrent_requests_respect_rate(
        self, mock: respx.MockRouter, clock: FakeClock
    ) -> None:
        stamps: list[float] = []

        def record(request: httpx.Request) -> httpx.Response:
            stamps.append(clock.now)
            return httpx.Response(200)

        mock.get(url__startswith=BASE).mock(side_effect=record)
        async with make_session(clock, rate_limit=5) as s:
            await asyncio.gather(*(s.get(f"{BASE}/{i}") for i in range(12)))
        stamps.sort()
        # In any 1-second window there are at most 5 requests.
        for i, start in enumerate(stamps):
            in_window = [t for t in stamps[i:] if t < start + 1.0]
            assert len(in_window) <= 5
        assert s.request_count == 12


class TestThrottling:
    async def test_429_retried_after_retry_after_and_rate_halved(
        self, mock: respx.MockRouter, clock: FakeClock
    ) -> None:
        route = mock.get(f"{BASE}/").mock(
            side_effect=[httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(200)]
        )
        async with make_session(clock, rate_limit=4) as s:
            response = await s.get(f"{BASE}/")
            assert s.rate_limit == 2.0
        assert response.status_code == 200
        assert route.call_count == 2
        assert clock.sleeps == [pytest.approx(7.0)]

    async def test_retry_after_capped(
        self, mock: respx.MockRouter, session: TargetSession, clock: FakeClock
    ) -> None:
        mock.get(f"{BASE}/").mock(
            side_effect=[httpx.Response(503, headers={"Retry-After": "3600"}), httpx.Response(200)]
        )
        await session.get(f"{BASE}/")
        assert clock.sleeps == [pytest.approx(MAX_RETRY_AFTER)]

    async def test_gives_up_after_max_retries(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        route = mock.get(f"{BASE}/").respond(429, headers={"Retry-After": "1"})
        response = await session.get(f"{BASE}/")
        assert response.status_code == 429
        assert route.call_count == 3  # first try + 2 retries

    async def test_rate_never_below_minimum(self, mock: respx.MockRouter, clock: FakeClock) -> None:
        mock.get(url__startswith=BASE).respond(429, headers={"Retry-After": "0"})
        async with make_session(clock, rate_limit=1) as s:
            for i in range(3):
                await s.get(f"{BASE}/{i}")
            assert s.rate_limit == MIN_RATE


class TestRedirects:
    async def test_not_followed_by_default(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        mock.get(f"{BASE}/telescope").respond(302, headers={"Location": "/login"})
        login = mock.get(f"{BASE}/login").respond(200)
        response = await session.get(f"{BASE}/telescope")
        assert response.status_code == 302
        assert login.call_count == 0

    async def test_same_host_followed(self, mock: respx.MockRouter, session: TargetSession) -> None:
        mock.get("http://target.test/").respond(
            301, headers={"Location": "https://www.target.test/"}
        )
        mock.get("https://www.target.test/").respond(200, text="home")
        response = await session.get("http://target.test/", follow_redirects=True)
        assert response.status_code == 200
        assert response.url == "https://www.target.test/"
        assert response.history == (("http://target.test/", 301),)
        assert session.request_count == 2

    async def test_other_host_not_followed(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        mock.get(f"{BASE}/").respond(302, headers={"Location": "https://evil.test/"})
        evil = mock.get("https://evil.test/").respond(200)
        response = await session.get(f"{BASE}/", follow_redirects=True)
        assert response.status_code == 302
        assert evil.call_count == 0

    async def test_redirect_loop_bounded(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        mock.get(f"{BASE}/loop").respond(302, headers={"Location": "/loop"})
        response = await session.get(f"{BASE}/loop", follow_redirects=True)
        assert response.status_code == 302
        assert session.request_count == 6  # initial + MAX_REDIRECTS


async def test_transport_error_wrapped(mock: respx.MockRouter, session: TargetSession) -> None:
    mock.get(f"{BASE}/").mock(side_effect=httpx.ConnectTimeout("timed out"))
    with pytest.raises(TargetRequestError, match="gagal"):
        await session.get(f"{BASE}/")
