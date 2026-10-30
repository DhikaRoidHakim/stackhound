"""Security Grade and exit code (PRD §3.7.2, §3.7.5, MEMORY D-009, D-010).

Score starts at 100 and loses a penalty per finding and per vulnerable component:

- finding: severity penalty x confidence factor;
- component: penalty of its worst vulnerability x confidence factor, plus 1 per
  further vulnerability (at most +10), halved for dev-only dependencies.

The grade follows the score, then two caps apply: a CRITICAL with HIGH confidence
forces F, a HIGH with HIGH confidence limits the grade to C.
"""

import math
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from shound.core.models import (
    Confidence,
    Finding,
    Severity,
    UnifiedVulnerability,
    severity_rank,
)
from shound.exitcodes import ExitCode

SEVERITY_PENALTY = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 20.0,
    Severity.MEDIUM: 8.0,
    Severity.LOW: 3.0,
    Severity.INFO: 0.0,
}
CONFIDENCE_FACTOR = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.75, Confidence.LOW: 0.25}
EXTRA_VULNERABILITY_PENALTY = 1.0
MAX_EXTRA_VULNERABILITY_PENALTY = 10.0
DEV_DEPENDENCY_FACTOR = 0.5

GRADE_THRESHOLDS = [("A", 90), ("B", 80), ("C", 70), ("D", 60)]
GRADE_ORDER = ["A+", "A", "B", "C", "D", "F"]
A_PLUS_MIN_SCORE = 97

Item = Finding | UnifiedVulnerability


def effective_severity(severity: Severity) -> Severity:
    """A vulnerability without CVSS data is treated as MEDIUM, never as harmless."""
    return Severity.MEDIUM if severity is Severity.UNKNOWN else severity


@dataclass(frozen=True)
class Penalty:
    label: str  # "LRV-01" or "laravel/framework (3 kerentanan)"
    points: float


@dataclass(frozen=True)
class GradeResult:
    score: int
    grade: str
    penalties: list[Penalty] = field(default_factory=list)
    caps: list[str] = field(default_factory=list)  # why the grade was capped


def _finding_penalty(finding: Finding) -> float:
    severity = effective_severity(finding.severity)
    return SEVERITY_PENALTY[severity] * CONFIDENCE_FACTOR[finding.confidence]


def _component_penalties(vulnerabilities: Iterable[UnifiedVulnerability]) -> list[Penalty]:
    groups: dict[tuple[str, str | None], list[UnifiedVulnerability]] = defaultdict(list)
    for vulnerability in vulnerabilities:
        groups[(vulnerability.component_name, vulnerability.ecosystem)].append(vulnerability)

    penalties = []
    for (component, _), items in groups.items():
        worst = max(
            SEVERITY_PENALTY[effective_severity(v.severity)] * CONFIDENCE_FACTOR[v.confidence]
            for v in items
        )
        extra = min(MAX_EXTRA_VULNERABILITY_PENALTY, EXTRA_VULNERABILITY_PENALTY * (len(items) - 1))
        points = worst + extra
        if all(v.is_dev_dependency for v in items):
            points *= DEV_DEPENDENCY_FACTOR
        penalties.append(Penalty(f"{component} ({len(items)} kerentanan)", points))
    return penalties


def _grade_for(score: int) -> str:
    return next((grade for grade, minimum in GRADE_THRESHOLDS if score >= minimum), "F")


def compute_grade(
    findings: Iterable[Finding], vulnerabilities: Iterable[UnifiedVulnerability] = ()
) -> GradeResult:
    findings = list(findings)
    vulnerabilities = list(vulnerabilities)
    items: list[Item] = [*findings, *vulnerabilities]

    penalties = [
        Penalty(f.id, points) for f in findings if (points := _finding_penalty(f)) > 0
    ] + _component_penalties(vulnerabilities)
    penalties.sort(key=lambda p: -p.points)
    score = max(0, math.floor(100 - sum(p.points for p in penalties) + 0.5))

    medium_or_worse = any(
        severity_rank(effective_severity(i.severity)) <= severity_rank(Severity.MEDIUM)
        for i in items
    )
    grade = _grade_for(score)
    if score >= A_PLUS_MIN_SCORE and not medium_or_worse:
        grade = "A+"

    caps: list[str] = []
    confident = [i for i in items if i.confidence is Confidence.HIGH]
    if any(effective_severity(i.severity) is Severity.CRITICAL for i in confident):
        caps.append("Ada temuan CRITICAL dengan confidence HIGH: grade otomatis F.")
        grade = "F"
    elif any(effective_severity(i.severity) is Severity.HIGH for i in confident):
        if GRADE_ORDER.index(grade) < GRADE_ORDER.index("C"):
            caps.append("Ada temuan HIGH dengan confidence HIGH: grade maksimal C.")
            grade = "C"
    return GradeResult(score=score, grade=grade, penalties=penalties, caps=caps)


def exit_code(
    findings: Iterable[Finding],
    vulnerabilities: Iterable[UnifiedVulnerability] = (),
    *,
    fail_on: Severity | None = None,
    partial: bool = False,
) -> ExitCode:
    """1 if anything reaches --fail-on (any confidence), else 4 if partial, else 0."""
    if fail_on is not None:
        threshold = severity_rank(fail_on)
        items: list[Item] = [*findings, *vulnerabilities]
        if any(severity_rank(effective_severity(i.severity)) <= threshold for i in items):
            return ExitCode.FINDINGS
    return ExitCode.PARTIAL if partial else ExitCode.OK


def severity_counts(items: Iterable[Item]) -> dict[Severity, int]:
    counts = {severity: 0 for severity in SEVERITY_PENALTY}
    for item in items:
        counts[effective_severity(item.severity)] += 1
    return counts
