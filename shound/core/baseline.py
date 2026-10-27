"""Soft-404 baseline (PRD §3.2.2, BACKLOG T-104, CLAUDE.md rule 4).

Many servers (SPAs, catch-all routes, WAFs) answer 200 for any path. Before any
path check, two random paths are requested to learn what "does not exist" looks
like on this target. A path check is confirmed only when:

1. the status is 200 (or 206 for ranged requests),
2. the check's own content signature matches, and
3. the body does not resemble the baseline responses.
"""

import difflib
import hashlib
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import unquote, urljoin, urlsplit

from shound.core.models import Confidence, Finding, Severity
from shound.core.redaction import redacted_evidence
from shound.core.session import HttpResponse, TargetRequestError, TargetSession

CONFIRM_STATUSES = frozenset({200, 206})
SIMILARITY_THRESHOLD = 0.9
COMPARE_CHARS = 20_000  # bounds difflib cost on large pages
PROBE_PREFIX = "shound-"

Signature = Callable[[HttpResponse], bool] | re.Pattern[str]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{8,}\b")
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_-]{20,}={0,2}")
_DIGITS_RE = re.compile(r"\d+")
_SPACE_RE = re.compile(r"\s+")


def base_url(target: str) -> str:
    """Directory that relative check paths are resolved against.

    ``https://x.test/app`` and ``https://x.test/app/`` both give ``.../app/``;
    ``https://x.test/app/index.php`` gives ``.../app/``.
    """
    parts = urlsplit(target)
    path = parts.path or "/"
    last = path.rsplit("/", 1)[-1]
    if "." in last:
        path = path[: len(path) - len(last)]
    elif not path.endswith("/"):
        path += "/"
    return f"{parts.scheme}://{parts.netloc}{path}"


def normalize_body(text: str, *, echoes: tuple[str, ...] = ()) -> str:
    """Remove parts that differ between two "not found" pages of the same site:
    the requested path echoed back, ids, tokens, nonces, numbers, whitespace."""
    # Very short echoes ("/", "a") would wipe ordinary characters from the page.
    for echo in sorted((e for e in echoes if len(e) >= 3), key=len, reverse=True):
        text = text.replace(echo, "#P")
    text = _HEX_RE.sub("#H", text)
    text = _TOKEN_RE.sub("#T", text)
    text = _DIGITS_RE.sub("#", text)
    return _SPACE_RE.sub(" ", text).strip()


def _echoes(url: str) -> tuple[str, ...]:
    path = urlsplit(url).path
    decoded = unquote(path)
    return path, decoded, decoded.rsplit("/", 1)[-1]


def _title(text: str) -> str | None:
    match = _TITLE_RE.search(text)
    return _SPACE_RE.sub(" ", match.group(1)).strip() if match else None


@dataclass(frozen=True)
class BaselineSample:
    url: str
    status_code: int
    content_type: str
    length: int
    title: str | None
    normalized: str
    digest: str
    response: HttpResponse  # raw probe response, reused by fingerprinting (FP-04)

    @classmethod
    def from_response(cls, response: HttpResponse) -> "BaselineSample":
        text = response.text
        normalized = normalize_body(text, echoes=_echoes(response.url))[:COMPARE_CHARS]
        return cls(
            url=response.url,
            status_code=response.status_code,
            content_type=response.headers.get("content-type", ""),
            length=len(response.body),
            title=_title(text),
            normalized=normalized,
            digest=hashlib.sha256(normalized.encode()).hexdigest(),
            response=response,
        )


class Baseline:
    def __init__(
        self, base: str, samples: list[BaselineSample], errors: list[str] | None = None
    ) -> None:
        self.base = base
        self.samples = tuple(samples)
        self.errors = tuple(errors or ())

    @classmethod
    async def capture(
        cls,
        session: TargetSession,
        target: str,
        *,
        token: Callable[[], str] = lambda: secrets.token_hex(8),
    ) -> "Baseline":
        base = base_url(target)
        # Fresh random names per scan so caches and WAF rules cannot learn them.
        paths = [f"{PROBE_PREFIX}{token()}", f"{PROBE_PREFIX}{token()}.txt"]
        samples: list[BaselineSample] = []
        errors: list[str] = []
        for path in paths:
            try:
                response = await session.get(urljoin(base, path))
            except TargetRequestError as exc:
                errors.append(str(exc))
                continue
            samples.append(BaselineSample.from_response(response))
        return cls(base, samples, errors)

    @property
    def available(self) -> bool:
        return bool(self.samples)

    @property
    def soft_404(self) -> bool:
        return any(sample.status_code in CONFIRM_STATUSES for sample in self.samples)

    def url_for(self, path: str) -> str:
        return urljoin(self.base, path.lstrip("/"))

    def resembles(self, response: HttpResponse) -> bool:
        normalized = normalize_body(response.text, echoes=_echoes(response.url))[:COMPARE_CHARS]
        digest = hashlib.sha256(normalized.encode()).hexdigest()
        for sample in self.samples:
            if digest == sample.digest:
                return True
            matcher = difflib.SequenceMatcher(None, normalized, sample.normalized)
            if matcher.quick_ratio() >= SIMILARITY_THRESHOLD and (
                matcher.ratio() >= SIMILARITY_THRESHOLD
            ):
                return True
        return False

    def confirm(self, response: HttpResponse, signature: Signature) -> bool:
        if response.status_code not in CONFIRM_STATUSES:
            return False
        if isinstance(signature, re.Pattern):
            matched = signature.search(response.text) is not None
        else:
            matched = signature(response)
        return matched and not self.resembles(response)

    def soft_404_finding(self) -> Finding | None:
        """INFO finding when the target answers 200 for paths that do not exist."""
        hits = [s for s in self.samples if s.status_code in CONFIRM_STATUSES]
        if not hits:
            return None
        return Finding(
            id="FP-06",
            title="Target memakai soft-404",
            category="info",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            plugin="core.baseline",
            description=(
                "Path acak yang tidak ada dijawab dengan status 200. Pemeriksaan eksposur "
                "file tetap divalidasi dengan signature konten dan perbandingan baseline."
            ),
            evidence=[redacted_evidence(s.url, status_code=s.status_code) for s in hits],
            remediation=(
                "Tidak wajib diperbaiki. Bila memungkinkan, kembalikan status 404 untuk path "
                "yang tidak ada agar scanner dan crawler tidak salah tafsir."
            ),
        )
