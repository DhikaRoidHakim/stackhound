"""Executes a validated ``ScanRequest``.

The audit pipeline arrives in later tasks; until then each mode prints the resolved
request and reports that it is not available yet (exit code 2, so a CI job that
already calls ``shound`` cannot pass by accident).
"""

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from shound.config import Settings
from shound.core.redaction import redact
from shound.exitcodes import ExitCode
from shound.options import Mode, ScanRequest

PENDING_TASKS: dict[Mode, str] = {
    "recon": "T-103 s/d T-107",
    "audit": "T-108, T-109",
    "cve": "T-209",
    "deps": "T-207",
    "scan": "T-309",
}


def describe(request: ScanRequest, settings: Settings) -> Table:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()

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


def execute(request: ScanRequest, settings: Settings, console: Console) -> ExitCode:
    console.print(describe(request, settings))
    console.print(
        f"[yellow]Mode {request.mode!r} belum tersedia.[/yellow] "
        f"Sedang dikembangkan (BACKLOG {PENDING_TASKS[request.mode]})."
    )
    return ExitCode.USAGE
