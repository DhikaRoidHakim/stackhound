"""Unified data models shared by every module (PRD §4).

Plugins and audit modules emit ``Finding`` objects; the CVE engine emits
``UnifiedVulnerability`` objects normalized from OSV.dev and NVD. Both end up in a
``ScanReport`` that the reporters render.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    """Rejects unknown fields so typos in internal construction fail loudly."""

    model_config = ConfigDict(extra="forbid")


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class Confidence(str, Enum):
    HIGH = "HIGH"  # verified by content signature / lock file
    MEDIUM = "MEDIUM"  # strong but indirect signal
    LOW = "LOW"  # banner version (possibly backported), heuristics


class VersionSource(str, Enum):
    HEADER = "HEADER"
    ERROR_PAGE = "ERROR_PAGE"
    HTML_META = "HTML_META"  # e.g. <meta name="generator" content="WordPress 6.4">
    EXPOSED_LOCKFILE = "EXPOSED_LOCKFILE"
    ASSET_HEURISTIC = "ASSET_HEURISTIC"
    LOCAL_LOCKFILE = "LOCAL_LOCKFILE"
    MANUAL = "MANUAL"


class DetectedVersion(_StrictModel):
    """A component version seen on the target (FP-05), input for the CVE engine."""

    component: str  # "php", "laravel", "nginx", ...
    version: str
    source: VersionSource
    evidence: str  # already redacted, e.g. "X-Powered-By: PHP/8.3.36"
    distro: str | None = None  # distro token in the banner -> patches may be backported

    @property
    def backport_risk(self) -> bool:
        return self.distro is not None


class Evidence(_StrictModel):
    url: str
    method: str = "GET"
    status_code: int | None = None
    snippet: str | None = None  # MUST already be redacted, max 500 chars
    note: str | None = None


class Finding(_StrictModel):
    id: str  # "LRV-01", "SH-01.HSTS"
    title: str
    category: str  # misconfig|header|cookie|cors|tls|exposure|info
    severity: Severity
    confidence: Confidence
    plugin: str  # "laravel", "core.headers", ...
    description: str
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: str
    references: list[str] = Field(default_factory=list)


class UnifiedVulnerability(_StrictModel):
    id: str  # CVE-2021-3129 or GHSA-xxxx
    aliases: list[str] = Field(default_factory=list)
    component_name: str  # "laravel/framework" or "php"
    ecosystem: str | None = None  # Packagist|PyPI|npm; None for CPE/NVD
    detected_version: str
    version_source: VersionSource
    fixed_version: str | None = None
    severity: Severity
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_version: str | None = None  # "3.1" | "3.0" | "4.0" | "2.0"
    cvss_vector: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    summary: str
    published: datetime | None = None
    sources: list[str] = Field(default_factory=list)  # ["OSV", "NVD"]
    confidence: Confidence = Confidence.HIGH
    is_dev_dependency: bool = False
    reference_urls: list[str] = Field(default_factory=list)


class ScanReport(_StrictModel):
    report_schema: str = "1.0"
    tool_version: str
    mode: str  # recon|audit|cve|deps|scan
    target: str | None = None  # URL or lock file path
    started_at: datetime
    finished_at: datetime
    fingerprint: dict[str, Any] | None = None
    findings: list[Finding] = Field(default_factory=list)
    vulnerabilities: list[UnifiedVulnerability] = Field(default_factory=list)
    unaudited_components: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)  # causes of a partial scan
    insecure_tls: bool = False
    score: int = Field(ge=0, le=100)
    grade: str
