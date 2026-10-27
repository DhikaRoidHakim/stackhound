import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from shound.core.models import (
    Confidence,
    Evidence,
    Finding,
    ScanReport,
    Severity,
    UnifiedVulnerability,
    VersionSource,
)

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)


def make_finding(**overrides: object) -> Finding:
    data: dict[str, object] = {
        "id": "LRV-01",
        "title": "Environment File Exposure",
        "category": "exposure",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "plugin": "laravel",
        "description": "File .env dapat diakses publik.",
        "remediation": "Arahkan DocumentRoot ke /public.",
    }
    data.update(overrides)
    return Finding.model_validate(data)


def make_vuln(**overrides: object) -> UnifiedVulnerability:
    data: dict[str, object] = {
        "id": "CVE-2021-3129",
        "component_name": "facade/ignition",
        "ecosystem": "Packagist",
        "detected_version": "2.5.1",
        "version_source": VersionSource.LOCAL_LOCKFILE,
        "severity": Severity.CRITICAL,
        "summary": "Remote code execution in Ignition.",
    }
    data.update(overrides)
    return UnifiedVulnerability.model_validate(data)


def make_report(**overrides: object) -> ScanReport:
    data: dict[str, object] = {
        "tool_version": "0.1.0",
        "mode": "scan",
        "started_at": NOW,
        "finished_at": NOW,
        "score": 100,
        "grade": "A+",
    }
    data.update(overrides)
    return ScanReport.model_validate(data)


class TestEvidence:
    def test_defaults(self) -> None:
        ev = Evidence(url="https://example.test/.env")
        assert ev.method == "GET"
        assert ev.status_code is None
        assert ev.snippet is None
        assert ev.note is None


class TestFinding:
    def test_optional_collections_default_empty(self) -> None:
        f = make_finding()
        assert f.evidence == []
        assert f.references == []

    def test_default_lists_are_not_shared(self) -> None:
        a, b = make_finding(), make_finding()
        a.evidence.append(Evidence(url="https://example.test/"))
        assert b.evidence == []

    def test_severity_coerced_from_string(self) -> None:
        assert make_finding(severity="HIGH").severity is Severity.HIGH

    def test_invalid_severity_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make_finding(severity="SEVERE")

    def test_unknown_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make_finding(severty="HIGH")

    def test_missing_required_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Finding.model_validate({"id": "LRV-01"})


class TestUnifiedVulnerability:
    def test_optional_fields_default_to_none(self) -> None:
        v = make_vuln()
        assert v.fixed_version is None
        assert v.cvss_score is None
        assert v.cvss_version is None
        assert v.cvss_vector is None
        assert v.published is None

    def test_defaults(self) -> None:
        v = make_vuln()
        assert v.confidence is Confidence.HIGH
        assert v.is_dev_dependency is False
        assert v.aliases == []
        assert v.cwe_ids == []
        assert v.sources == []
        assert v.reference_urls == []

    @pytest.mark.parametrize("score", [-0.1, 10.1])
    def test_cvss_score_out_of_range_rejected(self, score: float) -> None:
        with pytest.raises(ValidationError):
            make_vuln(cvss_score=score)

    def test_version_source_required(self) -> None:
        data = make_vuln().model_dump()
        del data["version_source"]
        with pytest.raises(ValidationError):
            UnifiedVulnerability.model_validate(data)


class TestScanReport:
    def test_defaults(self) -> None:
        r = make_report()
        assert r.report_schema == "1.0"
        assert r.target is None
        assert r.fingerprint is None
        assert r.findings == []
        assert r.vulnerabilities == []
        assert r.unaudited_components == []
        assert r.errors == []
        assert r.insecure_tls is False

    @pytest.mark.parametrize("score", [-1, 101])
    def test_score_out_of_range_rejected(self, score: int) -> None:
        with pytest.raises(ValidationError):
            make_report(score=score)

    def test_json_round_trip(self) -> None:
        report = make_report(
            target="https://staging.example.test",
            fingerprint={"laravel": 0.95},
            findings=[
                make_finding(
                    evidence=[Evidence(url="https://staging.example.test/.env", status_code=200)]
                )
            ],
            vulnerabilities=[make_vuln(cvss_score=9.8, cvss_version="3.1", sources=["OSV", "NVD"])],
            score=20,
            grade="F",
        )
        restored = ScanReport.model_validate_json(report.model_dump_json())
        assert restored == report

    def test_enums_serialize_as_plain_strings(self) -> None:
        report = make_report(findings=[make_finding()], vulnerabilities=[make_vuln()])
        payload = json.loads(report.model_dump_json())
        assert payload["report_schema"] == "1.0"
        assert payload["findings"][0]["severity"] == "CRITICAL"
        assert payload["findings"][0]["confidence"] == "HIGH"
        assert payload["vulnerabilities"][0]["version_source"] == "LOCAL_LOCKFILE"
