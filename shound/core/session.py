"""The only HTTP path to an audit target (PRD §6.1-6.3, CLAUDE.md rules 1-2).

``TargetSession`` enforces, for every module and plugin at once:

- safe methods only (GET/HEAD/OPTIONS); PATCH exists solely behind ``probe_patch``
- one global rate limit, halved whenever the target answers 429/503
- at most ``MAX_CONCURRENCY`` requests in flight
- response bodies capped at ``MAX_BODY_BYTES``
- the identity header, which callers cannot remove or override
- redirects followed only within the target's own host
"""

import asyncio
import dataclasses
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from types import TracebackType

import httpx

from shound import __version__
from shound.config import Settings

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_BODY_BYTES = 1024 * 1024
MAX_CONCURRENCY = 5
MAX_REDIRECTS = 5
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
THROTTLE_STATUSES = frozenset({429, 503})
MAX_THROTTLE_RETRIES = 2
DEFAULT_RETRY_AFTER = 5.0
MAX_RETRY_AFTER = 60.0
MIN_RATE = 0.5

IDENTITY_HEADER = "X-Security-Audit"
IDENTITY_VALUE = f"StackHound/{__version__}"

Clock = Callable[[], float]
Sleep = Callable[[float], Awaitable[None]]

_CHARSET_RE = re.compile(r"charset=[\"']?([\w.:-]+)", re.IGNORECASE)


class UnsafeMethodError(ValueError):
    """Raised before any network I/O when a non-whitelisted method is requested."""


class TargetRequestError(Exception):
    """Transport-level failure talking to the target (DNS, TLS, timeout, ...)."""


@dataclass(frozen=True)
class HttpResponse:
    method: str
    url: str
    status_code: int
    headers: httpx.Headers
    body: bytes
    truncated: bool  # body was cut at MAX_BODY_BYTES
    history: tuple[tuple[str, int], ...] = ()  # (url, status) of followed redirects

    @property
    def text(self) -> str:
        match = _CHARSET_RE.search(self.headers.get("content-type", ""))
        encoding = match.group(1) if match else "utf-8"
        try:
            return self.body.decode(encoding, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


class RateLimiter:
    """Token bucket with capacity 1: requests are spaced ``1/rate`` seconds apart,
    so no one-second window ever holds more than ``rate`` requests."""

    def __init__(
        self, rate: float, *, clock: Clock = time.monotonic, sleep: Sleep = asyncio.sleep
    ) -> None:
        self._clock = clock
        self._sleep = sleep
        self._lock = asyncio.Lock()
        self._next_slot = float("-inf")
        self.set_rate(rate)

    @property
    def rate(self) -> float:
        return self._rate

    def set_rate(self, rate: float) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self._rate = rate
        self._interval = 1.0 / rate

    def pause(self, seconds: float) -> None:
        """Hold back every request (not just the caller's) for ``seconds``."""
        self._next_slot = max(self._next_slot, self._clock() + seconds)

    async def acquire(self) -> None:
        async with self._lock:
            now = self._clock()
            slot = max(now, self._next_slot)
            self._next_slot = slot + self._interval
        if slot > now:
            await self._sleep(slot - now)


class TargetSession:
    def __init__(
        self,
        settings: Settings,
        *,
        insecure: bool = False,
        method_probe: bool = True,
        clock: Clock = time.monotonic,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self._user_agent = settings.user_agent
        self.method_probe_enabled = method_probe
        self.request_count = 0
        self._limiter = RateLimiter(settings.rate_limit, clock=clock, sleep=sleep)
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
        self._client = httpx.AsyncClient(
            http2=True,
            verify=not insecure,
            proxy=settings.proxy,
            timeout=settings.timeout,
            follow_redirects=False,  # handled here so every hop is rate limited and in scope
            trust_env=False,  # proxy/credentials come from shound config only
            limits=httpx.Limits(max_connections=MAX_CONCURRENCY),
        )

    @property
    def rate_limit(self) -> float:
        return self._limiter.rate

    async def __aenter__(self) -> "TargetSession":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get(
        self, url: str, *, headers: Mapping[str, str] | None = None, follow_redirects: bool = False
    ) -> HttpResponse:
        return await self.request("GET", url, headers=headers, follow_redirects=follow_redirects)

    async def head(
        self, url: str, *, headers: Mapping[str, str] | None = None, follow_redirects: bool = False
    ) -> HttpResponse:
        return await self.request("HEAD", url, headers=headers, follow_redirects=follow_redirects)

    async def options(self, url: str, *, headers: Mapping[str, str] | None = None) -> HttpResponse:
        return await self.request("OPTIONS", url, headers=headers)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> HttpResponse:
        method = method.upper()
        if method not in SAFE_METHODS:
            raise UnsafeMethodError(
                f"Method {method} tidak diizinkan; hanya {', '.join(sorted(SAFE_METHODS))}."
            )
        response = await self._send(method, url, headers)
        history: list[tuple[str, int]] = []
        while follow_redirects and response.status_code in REDIRECT_STATUSES:
            location = response.headers.get("location")
            if not location or len(history) >= MAX_REDIRECTS:
                break
            next_url = str(httpx.URL(response.url).join(location))
            if not _same_host(url, next_url):
                break  # never leave the authorized target
            history.append((response.url, response.status_code))
            response = await self._send(method, next_url, headers)
        return dataclasses.replace(response, history=tuple(history))

    async def probe_patch(self, url: str) -> HttpResponse | None:
        """Guarded PATCH probe for LRV-02 (PRD §3.4.2, MEMORY D-006).

        Sends ``OPTIONS`` first and only issues a body-less ``PATCH`` when the
        ``Allow`` header proves the route rejects PATCH, so the router answers 405
        before any application handler runs. Returns ``None`` when skipped.
        """
        if not self.method_probe_enabled:
            return None
        allow = (await self.options(url)).headers.get("allow")
        if allow is None:
            return None
        allowed = {part.strip().upper() for part in allow.split(",")}
        if "PATCH" in allowed:
            return None
        return await self._send("PATCH", url, None)

    async def _send(self, method: str, url: str, headers: Mapping[str, str] | None) -> HttpResponse:
        attempt = 0
        while True:
            response = await self._send_once(method, url, headers)
            if response.status_code not in THROTTLE_STATUSES or attempt >= MAX_THROTTLE_RETRIES:
                return response
            attempt += 1
            self._limiter.set_rate(max(MIN_RATE, self._limiter.rate / 2))
            self._limiter.pause(_retry_after_seconds(response.headers.get("retry-after")))

    async def _send_once(
        self, method: str, url: str, headers: Mapping[str, str] | None
    ) -> HttpResponse:
        request_headers = httpx.Headers(headers or {})
        request_headers["User-Agent"] = self._user_agent
        request_headers[IDENTITY_HEADER] = IDENTITY_VALUE
        await self._limiter.acquire()
        async with self._semaphore:
            request = self._client.build_request(
                method, url, headers=request_headers, content=b"" if method == "PATCH" else None
            )
            self.request_count += 1
            try:
                response = await self._client.send(request, stream=True)
                try:
                    body, truncated = await _read_capped(response, MAX_BODY_BYTES)
                finally:
                    await response.aclose()
            except httpx.HTTPError as exc:
                raise TargetRequestError(f"Request {method} {url} gagal: {exc}") from exc
        return HttpResponse(
            method=method,
            url=str(response.url),
            status_code=response.status_code,
            headers=response.headers,
            body=body,
            truncated=truncated,
        )


async def _read_capped(response: httpx.Response, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        remaining = limit - size
        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            return b"".join(chunks), True
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks), False


def _retry_after_seconds(value: str | None) -> float:
    if value is None:
        return DEFAULT_RETRY_AFTER
    try:
        seconds = float(value.strip())
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return DEFAULT_RETRY_AFTER
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        seconds = (when - datetime.now(timezone.utc)).total_seconds()
    return min(MAX_RETRY_AFTER, max(0.0, seconds))


def _same_host(original: str, candidate: str) -> bool:
    def host(url: str) -> str:
        name = httpx.URL(url).host.lower()
        return name.removeprefix("www.")

    return host(original) == host(candidate)
