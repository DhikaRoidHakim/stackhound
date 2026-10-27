"""Executes a validated ``ScanRequest``.

Target modes already run the pre-flight check (T-103) and capture the soft-404
baseline (T-104). The audit modules arrive in later tasks; until then the run
ends by reporting that the mode is not available yet (exit code 2, so a CI job
that already calls ``shound`` cannot pass by accident).
"""

import asyncio

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from shound.config import Settings
from shound.core.baseline import Baseline
from shound.core.preflight import PreflightResult, run_preflight
from shound.core.redaction import redact
from shound.core.session import TargetSession
from shound.errors import PreflightError
from shound.exitcodes import ExitCode
from shound.options import Mode, ScanRequest

PENDING_TASKS: dict[Mode, str] = {
    "recon": "T-105 s/d T-107",
    "audit": "T-108, T-109",
    "cve": "T-209",
    "deps": "T-207",
    "scan": "T-309",
}


def _key_value_table(title: str | None = None) -> Table:
    table = Table(show_header=False, box=None, padding=(0, 2), title=title, title_justify="left")
    table.add_column(style="bold")
    table.add_column()
    return table


def describe(request: ScanRequest, settings: Settings) -> Table:
    table = _key_value_table()

    def row(label: str, value: object) -> None:
        table.add_row(label, escape(str(value)))

    row("Mode", request.mode)
    if request.target:
        row("Target", request.target)
    if request.path:
        row("File", request.path)
    if request.framework:
        row("Framework", request.framework)
    if request.versions:
        row("Versi manual", ", ".join(f"{k}={v}" for k, v in request.versions.items()))
    if request.outputs:
        row("Laporan", ", ".join(str(p) for p in request.outputs))
    if request.fail_on:
        row("Fail-on", request.fail_on.value)
    row("Rate limit", f"{settings.rate_limit:g} req/detik")
    row("Timeout", f"{settings.timeout:g} detik")
    if settings.proxy:
        row("Proxy", redact(settings.proxy, max_length=None))
    row("User-Agent", settings.user_agent)
    row("Verifikasi TLS", "tidak (--insecure)" if request.insecure else "ya")
    if request.mode in {"audit", "scan"}:
        row("Method probe", "aktif" if request.method_probe else "nonaktif")
    if request.mode in {"cve", "deps", "scan"}:
        cache = (
            "nonaktif" if not request.use_cache else "refresh" if request.refresh_cache else "aktif"
        )
        row("Cache", cache)
    return table


def preflight_table(result: PreflightResult) -> Table:
    table = _key_value_table("Pre-flight")

    def row(label: str, value: object) -> None:
        table.add_row(label, escape(str(value)))

    row("Alamat", ", ".join(result.addresses) or "(via proxy)")
    response = result.response
    row("HTTP", f"{response.status_code} {response.url}")
    for url, status in response.history:
        row("Redirect", f"{status} {url}")
    tls = result.tls
    if tls is not None:
        row("TLS", " / ".join(filter(None, [tls.version, tls.cipher])))
        if tls.subject_cn:
            row("Sertifikat", f"{tls.subject_cn} (penerbit: {tls.issuer or '-'})")
        if tls.not_after:
            row("Berlaku sampai", f"{tls.not_after:%Y-%m-%d} ({tls.days_remaining()} hari lagi)")
    for warning in result.warnings:
        table.add_row("[yellow]Peringatan[/yellow]", escape(warning))
    return table


def baseline_table(baseline: Baseline) -> Table:
    table = _key_value_table("Baseline soft-404")
    for sample in baseline.samples:
        table.add_row("Probe", escape(f"{sample.status_code} {sample.url}"))
    for error in baseline.errors:
        table.add_row("[yellow]Gagal[/yellow]", escape(error))
    if not baseline.available:
        verdict = "[yellow]tidak tersedia[/yellow] (cek path hanya mengandalkan signature)"
    elif baseline.soft_404:
        verdict = "[yellow]ya[/yellow] - path tak dikenal dijawab 200"
    else:
        verdict = "tidak - path tak dikenal dijawab dengan status error"
    table.add_row("Soft-404", verdict)
    return table


async def probe_target(
    request: ScanRequest, target: str, settings: Settings, console: Console
) -> None:
    async with TargetSession(
        settings, insecure=request.insecure, method_probe=request.method_probe
    ) as session:
        result = await run_preflight(target, session)
        console.print(preflight_table(result))
        baseline = await Baseline.capture(session, result.final_url)
        console.print(baseline_table(baseline))
        console.print(f"[dim]Request terkirim ke target: {session.request_count}[/dim]")


def execute(request: ScanRequest, settings: Settings, console: Console) -> ExitCode:
    console.print(describe(request, settings))
    if request.target is not None:
        try:
            asyncio.run(probe_target(request, request.target, settings, console))
        except PreflightError as exc:
            console.print(f"[red]Pre-flight gagal:[/red] {escape(str(exc))}")
            return ExitCode.PREFLIGHT
    console.print(
        f"[yellow]Pemeriksaan mode {request.mode!r} belum tersedia.[/yellow] "
        f"Sedang dikembangkan (BACKLOG {PENDING_TASKS[request.mode]})."
    )
    return ExitCode.USAGE
