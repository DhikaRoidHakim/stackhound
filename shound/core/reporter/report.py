"""Builds the ``ScanReport`` every reporter renders (PRD §3.7)."""

from datetime import datetime

from shound import __version__
from shound.core.fingerprint import FingerprintResult
from shound.core.grading import GradeResult, severity_counts
from shound.core.models import (
    DetectedVersion,
    Finding,
    ScanReport,
    ScorePenalty,
    UnifiedVulnerability,
    severity_rank,
)


def build_report(
    *,
    mode: str,
    target: str | None,
    started_at: datetime,
    finished_at: datetime,
    grade: GradeResult,
    findings: list[Finding],
    vulnerabilities: list[UnifiedVulnerability] | None = None,
    fingerprint: FingerprintResult | None = None,
    extra_versions: list[DetectedVersion] | None = None,
    errors: list[str] | None = None,
    notes: list[str] | None = None,
    insecure_tls: bool = False,
) -> ScanReport:
    vulnerabilities = vulnerabilities or []
    fingerprint_data = None
    if fingerprint is not None:
        versions = [*fingerprint.versions]
        for version in extra_versions or []:
            if all(
                (v.component, v.version, v.source)
                != (version.component, version.version, version.source)
                for v in versions
            ):
                versions.append(version)
        fingerprint_data = FingerprintResult(
            technologies=fingerprint.technologies, versions=versions
        ).model_dump(mode="json")
    ordered = sorted(findings, key=lambda f: (severity_rank(f.severity), f.id))
    return ScanReport(
        tool_version=__version__,
        mode=mode,
        target=target,
        started_at=started_at,
        finished_at=finished_at,
        fingerprint=fingerprint_data,
        findings=ordered,
        vulnerabilities=vulnerabilities,
        errors=errors or [],
        notes=notes or [],
        insecure_tls=insecure_tls,
        score=grade.score,
        grade=grade.grade,
        grade_caps=grade.caps,
        penalties=[ScorePenalty(label=p.label, points=p.points) for p in grade.penalties],
        summary={
            severity.value: count
            for severity, count in severity_counts([*findings, *vulnerabilities]).items()
        },
    )
