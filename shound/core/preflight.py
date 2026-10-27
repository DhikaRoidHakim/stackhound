"""Pre-flight check (PRD §2.3, BACKLOG T-103).

Runs before any audit module: resolves the host, fetches the landing page and
records basic TLS facts. Any failure raises ``PreflightError`` (exit code 3).
The landing page response is kept so fingerprinting does not request it again.
"""

import asyncio
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from shound.core.session import (
    REDIRECT_STATUSES,
    HttpResponse,
    TargetRequestError,
    TargetSession,
    TlsInfo,
)
from shound.errors import PreflightError

TLS_EXPIRY_WARNING_DAYS = 30

Resolver = Callable[[str, int], Awaitable[list[str]]]


@dataclass(frozen=True)
class PreflightResult:
    target: str
    addresses: tuple[str, ...]  # empty when a proxy resolves the name
    response: HttpResponse  # landing page, after same-host redirects
    warnings: tuple[str, ...] = ()

    @property
    def final_url(self) -> str:
        return self.response.url

    @property
    def tls(self) -> TlsInfo | None:
        return self.response.tls


async def system_resolver(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


async def run_preflight(
    target: str, session: TargetSession, *, resolve: Resolver = system_resolver
) -> PreflightResult:
    parts = urlsplit(target)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    warnings: list[str] = []

    addresses: list[str] = []
    if session.uses_proxy:
        warnings.append("Nama host di-resolve oleh proxy; resolusi DNS lokal dilewati.")
    else:
        try:
            addresses = await resolve(host, port)
        except OSError as exc:
            raise PreflightError(f"Resolusi DNS untuk {host} gagal: {exc}") from exc
        if not addresses:
            raise PreflightError(f"Resolusi DNS untuk {host} tidak menghasilkan alamat.")

    try:
        response = await session.get(target, follow_redirects=True)
    except TargetRequestError as exc:
        message = str(exc)
        if "certificate verify failed" in message.lower():
            raise PreflightError(
                f"Sertifikat TLS {host} tidak dapat diverifikasi. Untuk staging dengan "
                "sertifikat self-signed, ulangi dengan --insecure."
            ) from exc
        raise PreflightError(f"Target tidak dapat dihubungi: {message}") from exc

    if response.status_code in REDIRECT_STATUSES:
        location = response.headers.get("location", "?")
        warnings.append(f"Redirect ke {location} tidak diikuti karena berada di luar host target.")
    if response.status_code >= 500:
        warnings.append(f"Halaman utama membalas HTTP {response.status_code}.")
    if response.tls is not None:
        if not response.tls.verified:
            warnings.append("Verifikasi sertifikat TLS dimatikan (--insecure).")
        days = response.tls.days_remaining()
        if days is not None and days < TLS_EXPIRY_WARNING_DAYS:
            state = "sudah kedaluwarsa" if days < 0 else f"kedaluwarsa dalam {days} hari"
            warnings.append(f"Sertifikat TLS {state}.")

    return PreflightResult(
        target=target,
        addresses=tuple(addresses),
        response=response,
        warnings=tuple(warnings),
    )
