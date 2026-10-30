import pytest

from shound.core.grading import (
    compute_grade,
    effective_severity,
    exit_code,
    severity_counts,
)
from shound.core.models import (
    Confidence,
    Finding,
    Severity,
    UnifiedVulnerability,
    VersionSource,
)
from shound.exitcodes import ExitCode


def finding(
    severity: Severity, confidence: Confidence = Confidence.HIGH, check_id: str = "X-01"
) -> Finding:
    return Finding(
        id=check_id,
        title="t",
        category="misconfig",
        severity=severity,
        confidence=confidence,
        plugin="test",
        description="d",
        remediation="r",
    )


def vuln(
    severity: Severity,
    component: str = "laravel/framework",
    *,
    confidence: Confidence = Confidence.HIGH,
    dev: bool = False,
    vuln_id: str = "CVE-1",
) -> UnifiedVulnerability:
    return UnifiedVulnerability(
        id=vuln_id,
        component_name=component,
        ecosystem="Packagist",
        detected_version="1.0.0",
        version_source=VersionSource.LOCAL_LOCKFILE,
        severity=severity,
        confidence=confidence,
        is_dev_dependency=dev,
        summary="s",
    )


class TestScore:
    def test_clean_is_a_plus(self) -> None:
        result = compute_grade([])
        assert (result.score, result.grade) == (100, "A+")
        assert result.penalties == []

    @pytest.mark.parametrize(
        ("severity", "score"),
        [(Severity.MEDIUM, 92), (Severity.LOW, 97), (Severity.INFO, 100)],
    )
    def test_severity_penalties(self, severity: Severity, score: int) -> None:
        assert compute_grade([finding(severity)]).score == score

    @pytest.mark.parametrize(
        ("confidence", "score"),
        [(Confidence.HIGH, 92), (Confidence.MEDIUM, 94), (Confidence.LOW, 98)],
    )
    def test_confidence_factor(self, confidence: Confidence, score: int) -> None:
        # 8 x 1.0 = 8; 8 x 0.75 = 6; 8 x 0.25 = 2
        assert compute_grade([finding(Severity.MEDIUM, confidence)]).score == score

    def test_score_floors_at_zero(self) -> None:
        assert compute_grade([finding(Severity.CRITICAL)] * 4).score == 0

    def test_penalties_sorted_largest_first(self) -> None:
        result = compute_grade(
            [finding(Severity.LOW, check_id="A"), finding(Severity.MEDIUM, check_id="B")]
        )
        assert [(p.label, p.points) for p in result.penalties] == [("B", 8.0), ("A", 3.0)]


class TestComponents:
    def test_one_component_counts_worst_plus_extras(self) -> None:
        vulns = [vuln(Severity.MEDIUM, vuln_id=f"CVE-{i}") for i in range(3)]
        result = compute_grade([], vulns)
        # worst MEDIUM 8 + 2 further vulnerabilities = 10
        assert result.score == 90
        assert result.penalties[0].label == "laravel/framework (3 kerentanan)"

    def test_extra_penalty_capped(self) -> None:
        vulns = [vuln(Severity.LOW, vuln_id=f"CVE-{i}") for i in range(40)]
        assert compute_grade([], vulns).score == 100 - 3 - 10

    def test_components_scored_separately(self) -> None:
        result = compute_grade([], [vuln(Severity.LOW, "a/a"), vuln(Severity.LOW, "b/b")])
        assert result.score == 94

    def test_dev_dependency_halved(self) -> None:
        assert compute_grade([], [vuln(Severity.MEDIUM, dev=True)]).score == 96

    def test_unknown_severity_counts_as_medium(self) -> None:
        assert effective_severity(Severity.UNKNOWN) is Severity.MEDIUM
        assert compute_grade([], [vuln(Severity.UNKNOWN)]).score == 92


class TestGrade:
    def test_score_boundaries(self) -> None:
        cases = {0: "A+", 1: "A+", 2: "A", 3: "A", 4: "B", 6: "B", 7: "C", 10: "C", 11: "D"}
        for lows, grade in cases.items():
            findings = [finding(Severity.LOW, check_id=f"L{i}") for i in range(lows)]
            assert compute_grade(findings).grade == grade, (lows, compute_grade(findings).score)

    def test_a_plus_requires_no_medium(self) -> None:
        # 100 - 2 (MEDIUM at LOW confidence) = 98, but a MEDIUM exists -> A
        result = compute_grade([finding(Severity.MEDIUM, Confidence.LOW)])
        assert (result.score, result.grade) == (98, "A")

    def test_confident_critical_forces_f(self) -> None:
        result = compute_grade([finding(Severity.CRITICAL)])
        assert (result.score, result.grade) == (60, "F")
        assert "otomatis F" in result.caps[0]

    def test_unconfident_critical_does_not_force_f(self) -> None:
        result = compute_grade([finding(Severity.CRITICAL, Confidence.LOW)])
        assert (result.score, result.grade) == (90, "A")
        assert result.caps == []

    def test_confident_high_caps_at_c(self) -> None:
        result = compute_grade([finding(Severity.HIGH)])
        assert (result.score, result.grade) == (80, "C")
        assert "maksimal C" in result.caps[0]

    def test_high_cap_does_not_raise_a_worse_grade(self) -> None:
        findings = [finding(Severity.HIGH, check_id=f"H{i}") for i in range(3)]
        result = compute_grade(findings)
        assert (result.score, result.grade) == (40, "F")
        assert result.caps == []

    def test_vulnerability_caps_apply_too(self) -> None:
        assert compute_grade([], [vuln(Severity.CRITICAL)]).grade == "F"
        banner_cve = vuln(Severity.CRITICAL, confidence=Confidence.LOW)
        assert compute_grade([], [banner_cve]).grade == "A"


class TestExitCode:
    def test_no_threshold_is_ok_even_with_findings(self) -> None:
        assert exit_code([finding(Severity.CRITICAL)]) is ExitCode.OK

    @pytest.mark.parametrize(
        ("fail_on", "expected"),
        [
            (Severity.CRITICAL, ExitCode.OK),
            (Severity.HIGH, ExitCode.FINDINGS),
            (Severity.MEDIUM, ExitCode.FINDINGS),
            (Severity.LOW, ExitCode.FINDINGS),
        ],
    )
    def test_threshold(self, fail_on: Severity, expected: ExitCode) -> None:
        assert exit_code([finding(Severity.HIGH)], fail_on=fail_on) is expected

    def test_any_confidence_counts(self) -> None:
        low_confidence = finding(Severity.HIGH, Confidence.LOW)
        assert exit_code([low_confidence], fail_on=Severity.HIGH) is ExitCode.FINDINGS

    def test_info_never_fails(self) -> None:
        assert exit_code([finding(Severity.INFO)], fail_on=Severity.LOW) is ExitCode.OK

    def test_unknown_vulnerability_counts_as_medium(self) -> None:
        unknown = [vuln(Severity.UNKNOWN)]
        assert exit_code([], unknown, fail_on=Severity.MEDIUM) is ExitCode.FINDINGS
        assert exit_code([], unknown, fail_on=Severity.HIGH) is ExitCode.OK

    def test_partial(self) -> None:
        assert exit_code([], partial=True) is ExitCode.PARTIAL

    def test_findings_win_over_partial(self) -> None:
        result = exit_code([finding(Severity.HIGH)], fail_on=Severity.HIGH, partial=True)
        assert result is ExitCode.FINDINGS


def test_severity_counts() -> None:
    counts = severity_counts(
        [finding(Severity.HIGH), finding(Severity.HIGH), vuln(Severity.UNKNOWN)]
    )
    assert counts[Severity.HIGH] == 2
    assert counts[Severity.MEDIUM] == 1
    assert Severity.UNKNOWN not in counts
