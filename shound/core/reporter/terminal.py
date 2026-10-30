"""Terminal rendering of a ``ScanReport`` (PRD §3.7.1).

Evidence is shown as a short preview; the complete (already redacted) evidence
is in the JSON report.
"""

from urllib.parse import urlsplit

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from shound.core.models import Evidence, Finding, ScanReport, Severity

EVIDENCE_PREVIEW = 90
MAX_EVIDENCE_ROWS = 3

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
    Severity.UNKNOWN: "dim",
}
_GRADE_STYLE = {"A+": "green", "A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}


def evidence_line(evidence: Evidence) -> str:
    detail = evidence.snippet or evidence.note
    path = urlsplit(evidence.url).path or "/"
    text = f"{path}: {detail}" if detail else evidence.url
    text = " ".join(text.split())
    return text if len(text) <= EVIDENCE_PREVIEW else text[: EVIDENCE_PREVIEW - 3] + "..."


def findings_table(findings: list[Finding]) -> Table:
    """Findings in the order given (``build_report`` sorts by severity)."""
    table = Table(title=f"Temuan ({len(findings)})", title_justify="left")
    table.add_column("ID", style="bold", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Judul")
    table.add_column("Bukti")
    for finding in findings:
        style = _SEVERITY_STYLE[finding.severity]
        evidence = "\n".join(evidence_line(e) for e in finding.evidence[:MAX_EVIDENCE_ROWS])
        if len(finding.evidence) > MAX_EVIDENCE_ROWS:
            evidence += f"\n(+{len(finding.evidence) - MAX_EVIDENCE_ROWS} lainnya)"
        table.add_row(
            finding.id,
            f"[{style}]{finding.severity.value}[/{style}]",
            escape(finding.title),
            escape(evidence),
        )
    if not findings:
        table.add_row("-", "-", "Tidak ada temuan.", "-")
    return table


def grade_panel(report: ScanReport) -> Panel:
    style = _GRADE_STYLE[report.grade]
    summary = "  ".join(f"{severity} {count}" for severity, count in report.summary.items())
    lines = [
        f"[bold {style}]Security Grade: {report.grade}[/bold {style}]   skor {report.score}/100",
        summary,
    ]
    lines += [f"[{style}]{escape(cap)}[/{style}]" for cap in report.grade_caps]
    if report.penalties:
        top = ", ".join(f"{p.label} -{p.points:g}" for p in report.penalties[:5])
        lines.append(f"[dim]Pengurang terbesar: {escape(top)}[/dim]")
    return Panel("\n".join(lines), title="Ringkasan", title_align="left", expand=False)


def render_report(report: ScanReport, console: Console) -> None:
    """Findings table, notes, failed checks and the grade summary."""
    console.print(findings_table(report.findings))
    for note in report.notes:
        console.print(f"[dim]Catatan: {escape(note)}[/dim]")
    for error in report.errors:
        console.print(f"[yellow]Gagal diperiksa:[/yellow] {escape(error)}")
    if report.insecure_tls:
        console.print("[yellow]Verifikasi sertifikat TLS dimatikan (--insecure).[/yellow]")
    console.print(grade_panel(report))
