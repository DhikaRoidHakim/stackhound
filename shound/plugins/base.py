"""Plugin contract (PRD §3.4.1, BACKLOG T-108).

Rules every plugin follows (CLAUDE.md rules 1-4):

- all traffic goes through ``ctx.session`` (safe methods, rate limit, identity header);
- every path check is confirmed with ``ctx.baseline.confirm()`` and built with
  ``ctx.baseline.url_for()``;
- every piece of evidence is built with ``redacted_evidence()``.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from shound.core.baseline import Baseline
from shound.core.fingerprint import FingerprintResult
from shound.core.models import DetectedVersion, Finding
from shound.core.session import HttpResponse, TargetSession


@dataclass(frozen=True)
class ScanContext:
    session: TargetSession
    baseline: Baseline
    target: str  # landing URL after the pre-flight (same-host redirects followed)
    fingerprint: FingerprintResult
    method_probe: bool = True
    responses: tuple[HttpResponse, ...] = ()  # already fetched: landing page, baseline probes


@dataclass(frozen=True)
class ExposedLockfile:
    """A dependency lock file served by the target; audited for CVEs later (T-208)."""

    url: str
    ecosystem: str  # "Packagist", "npm", "PyPI"
    content: str


@dataclass
class PluginResult:
    findings: list[Finding] = field(default_factory=list)
    versions: list[DetectedVersion] = field(default_factory=list)
    exposed_lockfiles: list[ExposedLockfile] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class BasePlugin(ABC):
    id: ClassVar[str]  # matches the technology id in data/signatures.json
    name: ClassVar[str]
    ecosystem: ClassVar[str | None] = None
    package: ClassVar[str | None] = None

    @classmethod
    def match(cls, fingerprint: FingerprintResult) -> float:
        """Confidence 0.0-1.0 that this plugin applies to the target."""
        return fingerprint.confidence(cls.id)

    @abstractmethod
    async def run(self, ctx: ScanContext) -> PluginResult:
        """Run the plugin's checks and return what was found."""
