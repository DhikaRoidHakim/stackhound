import io
import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from shound import __version__
from shound.core.fingerprint import DetectedTechnology, FingerprintResult
from shound.core.grading import compute_grade
from shound.core.models import (
    Confidence,
    DetectedVersion,
    Evidence,
    Finding,
    ScanReport,
    Severity,
    VersionSource,
)
from shound.core.redaction import redacted_evidence
from shound.core.reporter.json_report import render_json, write_json
from shound.core.reporter.report import build_report
from shound.core.reporter.terminal import EVIDENCE_PREVIEW, evidence_line, render_report

T0 = datetime(2026, 10, 30, 8, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 10, 30, 8, 1, tzinfo=timezone.utc)


def finding(check_id: str, severity: Severity, evidence: list[Evidence] | None = None) -> Finding:
    return Finding(
        id=check_id,
        title=f"judul {check_id}",
        category="misconfig",
        severity=severity,
        confidence=Confidence.HIGH,
        plugin="test",
        description="d",
        evidence=evidence or [],
        remediation="r",
    )


def version(component: str, value: str, source: VersionSource) -> DetectedVersion:
    return DetectedVersion(component=component, version=value, source=source, evidence="e")


def make_report(findings: list[Finding], **kwargs: object) -> ScanReport:
    defaults: dict[str, object] = {
        "mode": "audit",
        "target": "https://target.test/",
        "started_at": T0,
        "finished_at": T1,
    }
    defaults.update(kwargs)
    return build_report(grade=compute_grade(findings), findings=findings, **defaults)  # type: ignore[arg-type]


class TestBuildReport:
    def test_fields(self) -> None:
        findings = [finding("LOW-1", Severity.LOW), finding("CRIT-1", Severity.CRITICAL)]
        report = make_report(findings, errors=["CORS: timeout"], notes=["n"], insecure_tls=True)
        assert report.tool_version == __version__
        assert report.report_schema == "1.0"
        assert (report.mode, report.target) == ("audit", "https://target.test/")
        assert [f.id for f in report.findings] == ["CRIT-1", "LOW-1"]  # by severity
        assert (report.grade, report.score) == ("F", 57)
        assert report.grade_caps
        assert [(p.label, p.points) for p in report.penalties] == [("CRIT-1", 40.0), ("LOW-1", 3.0)]
        assert report.summary == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "INFO": 0}
        assert report.errors == ["CORS: timeout"]
        assert report.notes == ["n"]
        assert report.insecure_tls is True

    def test_fingerprint_with_plugin_versions_deduplicated(self) -> None:
        detected = FingerprintResult(
            technologies=[
                DetectedTechnology(
                    id="laravel", name="PHP Laravel", category="framework", confidence=1.0
                )
            ],
            versions=[version("php", "8.3.36", VersionSource.HEADER)],
        )
        report = make_report(
            [],
            fingerprint=detected,
            extra_versions=[
                version("php", "8.3.36", VersionSource.HEADER),  # duplicate
                version("laravel", "12.70.1", VersionSource.ERROR_PAGE),
            ],
        )
        assert report.fingerprint is not None
        assert report.fingerprint["technologies"][0]["id"] == "laravel"
        assert [(v["component"], v["source"]) for v in report.fingerprint["versions"]] == [
            ("php", "HEADER"),
            ("laravel", "ERROR_PAGE"),
        ]

    def test_without_fingerprint(self) -> None:
        assert make_report([]).fingerprint is None


class TestJson:
    def test_round_trip(self) -> None:
        report = make_report([finding("X-1", Severity.HIGH, [Evidence(url="https://t/x")])])
        text = render_json(report)
        assert text.endswith("\n")
        assert ScanReport.model_validate_json(text) == report
        data = json.loads(text)
        assert data["findings"][0]["severity"] == "HIGH"
        assert data["started_at"] == "2026-10-30T08:00:00Z"

    def test_write_creates_folders(self, tmp_path: Path) -> None:
        path = tmp_path / "reports" / "nested" / "scan.json"
        write_json(make_report([]), path)
        assert json.loads(path.read_text(encoding="utf-8"))["grade"] == "A+"
        assert not path.with_name("scan.json.tmp").exists()

    def test_redacted_evidence_stays_redacted(self) -> None:
        secret = "AKIAREPORTTESTKEY0001"
        evidence = redacted_evidence(
            "https://user:pw-in-url@t.test/.env", snippet=f"AWS_ACCESS_KEY_ID={secret}"
        )
        text = render_json(make_report([finding("LRV-01", Severity.CRITICAL, [evidence])]))
        assert secret not in text
        assert "pw-in-url" not in text


class TestTerminal:
    @staticmethod
    def render(report: ScanReport) -> str:
        out = io.StringIO()
        render_report(report, Console(file=out, width=200, color_system=None))
        return out.getvalue()

    def test_render(self) -> None:
        report = make_report(
            [finding("SH-01.CSP", Severity.MEDIUM, [Evidence(url="https://t.test/", snippet="x")])],
            notes=["catatan satu"],
            errors=["CORS: timeout"],
            insecure_tls=True,
        )
        text = self.render(report)
        assert "Temuan (1)" in text
        assert "SH-01.CSP" in text
        assert "Catatan: catatan satu" in text
        assert "Gagal diperiksa: CORS: timeout" in text
        assert "--insecure" in text
        assert "Security Grade: A" in text
        assert "skor 92/100" in text

    def test_empty(self) -> None:
        text = self.render(make_report([]))
        assert "Tidak ada temuan." in text
        assert "Security Grade: A+" in text

    def test_markup_in_evidence_is_escaped(self) -> None:
        evidence = Evidence(url="https://t.test/", snippet="[bold red]injected[/bold red]")
        text = self.render(make_report([finding("X-1", Severity.LOW, [evidence])]))
        assert "[bold red]injected" in text

    def test_evidence_line(self) -> None:
        short = Evidence(url="https://t.test/.env", snippet="5 kunci:\n APP_KEY")
        assert evidence_line(short) == "/.env: 5 kunci: APP_KEY"
        assert evidence_line(Evidence(url="https://t.test/a")) == "https://t.test/a"
        long = Evidence(url="https://t.test/", snippet="x" * 500)
        assert len(evidence_line(long)) == EVIDENCE_PREVIEW
        assert evidence_line(long).endswith("...")
