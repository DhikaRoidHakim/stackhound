"""Executes a validated ``ScanRequest``.

Target modes already run the pre-flight check (T-103) and capture the soft-404
baseline (T-104). The audit modules arrive in later tasks; until then the run
ends by reporting that the mode is not available yet (exit code 2, so a CI job
that already calls ``shound`` cannot pass by accident).
"""

import asyncio
from urllib.parse import urlsplit

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from shound.config import Settings
from shound.core.baseline import Baseline
from shound.core.fingerprint import FingerprintResult, Observation, fingerprint
from shound.core.headers_tls import audit_cookies, audit_cors, audit_security_headers, audit_tls
from shound.core.models import Evidence, Finding, Severity, severity_rank
from shound.core.preflight import PreflightResult, run_preflight
from shound.core.redaction import redact
from shound.core.session import TargetSession
from shound.errors import PreflightError
from shound.exitcodes import ExitCode
from shound.options import Mode, ScanRequest
from shound.plugins import select_plugins
from shound.plugins.base import ScanContext

PENDING_TASKS: dict[Mode, str] = {
    "recon": "T-110, T-111",
    "audit": "T-110, T-111",
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


def fingerprint_table(result: FingerprintResult) -> Table:
    table = Table(title="Fingerprint", title_justify="left")
    table.add_column("Teknologi", style="bold")
    table.add_column("Kategori")
    table.add_column("Confidence", justify="right")
    table.add_column("Sinyal")
    levels = {"strong": "green", "likely": "yellow", "weak": "dim"}
    for tech in result.technologies:
        style = levels[tech.level]
        signals = "\n".join(f"{s.check_id} {s.evidence}" for s in tech.signals)
        table.add_row(
            escape(tech.name),
            tech.category,
            f"[{style}]{tech.confidence:.0%}[/{style}]",
            escape(signals),
        )
    if not result.technologies:
        table.add_row("-", "-", "-", "Tidak ada sinyal teknologi yang dikenali.")
    return table


def versions_table(result: FingerprintResult) -> Table:
    table = Table(title="Versi terdeteksi", title_justify="left")
    table.add_column("Komponen", style="bold")
    table.add_column("Versi")
    table.add_column("Sumber")
    table.add_column("Catatan")
    for version in result.versions:
        note = (
            f"Banner menyebut {version.distro}: patch mungkin sudah di-backport"
            if version.backport_risk
            else ""
        )
        table.add_row(
            escape(version.component), escape(version.version), version.source.value, escape(note)
        )
    return table


_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
    Severity.UNKNOWN: "dim",
}


EVIDENCE_PREVIEW = 90


def _evidence_line(evidence: Evidence) -> str:
    """Short terminal preview; the full evidence goes to the report files (T-111)."""
    detail = evidence.snippet or evidence.note
    path = urlsplit(evidence.url).path or "/"
    text = f"{path}: {detail}" if detail else evidence.url
    text = " ".join(text.split())
    return text if len(text) <= EVIDENCE_PREVIEW else text[: EVIDENCE_PREVIEW - 3] + "..."


def findings_table(findings: list[Finding]) -> Table:
    table = Table(title=f"Temuan ({len(findings)})", title_justify="left")
    table.add_column("ID", style="bold", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Judul")
    table.add_column("Bukti")
    for finding in sorted(findings, key=lambda f: (severity_rank(f.severity), f.id)):
        style = _SEVERITY_STYLE[finding.severity]
        evidence = "\n".join(_evidence_line(e) for e in finding.evidence[:3])
        if len(finding.evidence) > 3:
            evidence += f"\n(+{len(finding.evidence) - 3} lainnya)"
        table.add_row(
            finding.id,
            f"[{style}]{finding.severity.value}[/{style}]",
            escape(finding.title),
            escape(evidence),
        )
    if not findings:
        table.add_row("-", "-", "Tidak ada temuan.", "-")
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
        detected = fingerprint(
            [
                Observation(result.response),
                *(Observation(sample.response, not_found=True) for sample in baseline.samples),
            ]
        )
        console.print(fingerprint_table(detected))
        if detected.versions:
            console.print(versions_table(detected))
        responses = [result.response, *(sample.response for sample in baseline.samples)]
        findings: list[Finding] = []
        notes: list[str] = []
        if request.mode in {"recon", "scan"}:
            findings += audit_security_headers(result.response)
            findings += audit_cookies(responses)
            findings += await audit_cors(session, result.final_url)
            tls_audit = await audit_tls(session, result)
            findings += tls_audit.findings
            notes += [f"TLS: {note}" for note in tls_audit.notes]
        if request.mode in {"audit", "scan"}:
            selection = select_plugins(detected, request.framework)
            notes += selection.notes
            context = ScanContext(
                session=session,
                baseline=baseline,
                target=result.final_url,
                fingerprint=detected,
                method_probe=request.method_probe,
                responses=tuple(responses),
            )
            for plugin_class in selection.plugins:
                plugin_result = await plugin_class().run(context)
                findings += plugin_result.findings
                notes += [f"{plugin_class.name}: {note}" for note in plugin_result.notes]
                if plugin_result.versions:
                    console.print(
                        versions_table(FingerprintResult(versions=plugin_result.versions))
                    )
                for lockfile in plugin_result.exposed_lockfiles:
                    notes.append(
                        f"{lockfile.url} terekspos; audit CVE isinya menyusul (BACKLOG T-208)."
                    )
        soft_404 = baseline.soft_404_finding()
        if soft_404 is not None:
            findings.append(soft_404)
        console.print(findings_table(findings))
        for note in notes:
            console.print(f"[dim]Catatan: {escape(note)}[/dim]")
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
