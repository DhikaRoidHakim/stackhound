"""Tech-stack fingerprinting engine (PRD §3.2, BACKLOG T-105).

Passive: it only inspects responses that were already fetched (the pre-flight
landing page, the baseline probes, later the plugin probes) and sends nothing
itself. Patterns live in ``data/signatures.json``.

Each technology's confidence is the capped sum of the weights of its distinct
matching signals. Signal types map to the PRD check ids:

- FP-01 ``cookie``  - Set-Cookie name and/or value
- FP-02 ``header``  - response header value
- FP-03 ``body``    - HTML/DOM and asset paths on any page
- FP-04 ``body`` with ``on: not_found`` - only on "page not found" responses
- FP-05 a signal whose pattern has a ``(?P<version>...)`` group yields a version
"""

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

from shound.core.models import DetectedVersion, VersionSource
from shound.core.redaction import redact
from shound.core.session import HttpResponse

STRONG = 0.8  # plugin is loaded automatically (PRD §2.3)
LIKELY = 0.4  # plugin is loaded with a note
MAX_EVIDENCE = 120
BODY_SNIPPET = 40

Category = Literal["framework", "language", "server", "library", "cms", "frontend"]
Level = Literal["strong", "likely", "weak"]

_FP_IDS = {"cookie": "FP-01", "header": "FP-02", "body": "FP-03"}


# ------------------------------------------------------------------ signature schema
class _Spec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SignalSpec(_Spec):
    id: str
    type: Literal["cookie", "header", "body"]
    weight: float = Field(ge=0, le=1)
    on: Literal["any", "not_found"] = "any"
    name: str | None = None  # cookie: name regex; header: header name
    value: str | None = None  # cookie: value regex
    pattern: str | None = None  # header: value regex; body: regex
    version_source: VersionSource | None = None

    _name_re: re.Pattern[str] | None = PrivateAttr(default=None)
    _value_re: re.Pattern[str] | None = PrivateAttr(default=None)
    _pattern_re: re.Pattern[str] | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def _check(self) -> "SignalSpec":
        if self.type == "cookie" and not (self.name or self.value):
            raise ValueError(f"{self.id}: cookie signal needs name and/or value")
        if self.type == "header" and not self.name:
            raise ValueError(f"{self.id}: header signal needs a header name")
        if self.type == "body" and not self.pattern:
            raise ValueError(f"{self.id}: body signal needs a pattern")
        if self.on == "not_found" and self.type != "body":
            raise ValueError(f"{self.id}: on=not_found only applies to body signals")
        has_group = bool(self.pattern and "(?P<version>" in self.pattern)
        if has_group != (self.version_source is not None):
            raise ValueError(f"{self.id}: version_source requires a (?P<version>...) group")
        return self

    def model_post_init(self, context: Any, /) -> None:
        if self.type == "cookie":
            self._name_re = re.compile(self.name) if self.name else None
            self._value_re = re.compile(self.value) if self.value else None
        self._pattern_re = re.compile(self.pattern) if self.pattern else None

    @property
    def fp_id(self) -> str:
        return "FP-04" if self.on == "not_found" else _FP_IDS[self.type]


class TechnologySpec(_Spec):
    id: str
    name: str
    category: Category
    implies: list[str] = Field(default_factory=list)
    signals: list[SignalSpec] = Field(default_factory=list)


class SignatureDB(_Spec):
    schema_version: int
    distro_tokens: list[str] = Field(default_factory=list)
    technologies: list[TechnologySpec]

    _distro_re: re.Pattern[str] | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def _check(self) -> "SignatureDB":
        ids = [tech.id for tech in self.technologies]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate technology id")
        signal_ids = [s.id for tech in self.technologies for s in tech.signals]
        if len(signal_ids) != len(set(signal_ids)):
            raise ValueError("duplicate signal id")
        for tech in self.technologies:
            unknown = set(tech.implies) - set(ids)
            if unknown:
                raise ValueError(f"{tech.id}: implies unknown technology {sorted(unknown)}")
        return self

    def model_post_init(self, context: Any, /) -> None:
        if self.distro_tokens:
            alternatives = "|".join(re.escape(t) for t in self.distro_tokens)
            self._distro_re = re.compile(rf"(?<![A-Za-z])(?:{alternatives})")

    def technology(self, tech_id: str) -> TechnologySpec:
        return next(t for t in self.technologies if t.id == tech_id)

    def distro_in(self, text: str) -> str | None:
        match = self._distro_re.search(text) if self._distro_re else None
        return match.group(0) if match else None


def load_signatures(path: Path | None = None) -> SignatureDB:
    if path is None:
        return _default_signatures()
    return SignatureDB.model_validate(json.loads(path.read_text(encoding="utf-8")))


@cache
def _default_signatures() -> SignatureDB:
    raw = files("shound").joinpath("data/signatures.json").read_text(encoding="utf-8")
    return SignatureDB.model_validate(json.loads(raw))


# ------------------------------------------------------------------ results
class _Result(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SignalMatch(_Result):
    signal_id: str
    check_id: str  # FP-01 .. FP-04
    weight: float
    evidence: str


class DetectedTechnology(_Result):
    id: str
    name: str
    category: Category
    confidence: float
    signals: list[SignalMatch] = Field(default_factory=list)

    @property
    def level(self) -> Level:
        if self.confidence >= STRONG:
            return "strong"
        return "likely" if self.confidence >= LIKELY else "weak"


class FingerprintResult(_Result):
    technologies: list[DetectedTechnology] = Field(default_factory=list)
    versions: list[DetectedVersion] = Field(default_factory=list)

    def get(self, tech_id: str) -> DetectedTechnology | None:
        return next((t for t in self.technologies if t.id == tech_id), None)

    def confidence(self, tech_id: str) -> float:
        tech = self.get(tech_id)
        return tech.confidence if tech else 0.0

    def frameworks(self) -> list[DetectedTechnology]:
        return [t for t in self.technologies if t.category == "framework"]

    def versions_of(self, component: str) -> list[DetectedVersion]:
        return [v for v in self.versions if v.component == component]


@dataclass(frozen=True)
class Observation:
    response: HttpResponse
    not_found: bool = False  # response to a path that does not exist (baseline probe)


# ------------------------------------------------------------------ engine
def _cookies(response: HttpResponse) -> list[tuple[str, str]]:
    pairs = []
    for header in response.headers.get_list("set-cookie"):
        name, _, value = header.split(";", 1)[0].partition("=")
        if name.strip():
            pairs.append((name.strip(), value.strip()))
    return pairs


def _evidence(text: str) -> str:
    return redact(text, max_length=MAX_EVIDENCE)


def _match(
    spec: SignalSpec, observation: Observation, text: str
) -> tuple[str, re.Match[str] | None, str] | None:
    """Return (evidence, version match, raw matched header value) or None."""
    response = observation.response
    if spec.on == "not_found" and not observation.not_found:
        return None
    if spec.type == "cookie":
        for name, value in _cookies(response):
            if spec._name_re and not spec._name_re.search(name):
                continue
            value_match = spec._value_re.search(value) if spec._value_re else None
            if spec._value_re and not value_match:
                continue
            # Show only the part of the value the signature matched (e.g. the constant
            # "eyJpdiI6" prefix), never the cookie value itself.
            shown = f" (nilai {value_match.group(0)}...)" if value_match else ""
            return f"cookie {name}{shown}", None, ""
        return None
    if spec.type == "header":
        assert spec.name is not None
        for value in response.headers.get_list(spec.name):
            match = spec._pattern_re.search(value) if spec._pattern_re else None
            if spec._pattern_re is None or match:
                return f"{spec.name}: {value}", match, value
        return None
    assert spec._pattern_re is not None
    match = spec._pattern_re.search(text)
    if not match:
        return None
    snippet = " ".join(match.group(0).split())[:BODY_SNIPPET]
    return f'"{snippet}" di {urlsplit(response.url).path or "/"}', match, ""


def fingerprint(
    observations: Iterable[Observation], db: SignatureDB | None = None
) -> FingerprintResult:
    db = db or load_signatures()
    observed = list(observations)
    texts = [o.response.text for o in observed]
    matches: dict[str, dict[str, SignalMatch]] = {}
    versions: dict[tuple[str, str], DetectedVersion] = {}

    for tech in db.technologies:
        for spec in tech.signals:
            for observation, text in zip(observed, texts, strict=True):
                hit = _match(spec, observation, text)
                if hit is None:
                    continue
                evidence, version_match, header_value = hit
                matches.setdefault(tech.id, {}).setdefault(
                    spec.id,
                    SignalMatch(
                        signal_id=spec.id,
                        check_id=spec.fp_id,
                        weight=spec.weight,
                        evidence=_evidence(evidence),
                    ),
                )
                version = (
                    version_match.group("version")
                    if version_match and spec.version_source
                    else None
                )
                if version and spec.version_source and (tech.id, version) not in versions:
                    versions[(tech.id, version)] = DetectedVersion(
                        component=tech.id,
                        version=version,
                        source=spec.version_source,
                        evidence=_evidence(evidence),
                        # Only the component's own header value counts: "(Debian)" in
                        # the Server header says nothing about a separately built PHP.
                        distro=db.distro_in(header_value) if header_value else None,
                    )

    detected: dict[str, DetectedTechnology] = {}
    for tech_id, signals in matches.items():
        tech_spec = db.technology(tech_id)
        detected[tech_id] = DetectedTechnology(
            id=tech_id,
            name=tech_spec.name,
            category=tech_spec.category,
            confidence=round(min(1.0, sum(s.weight for s in signals.values())), 2),
            signals=list(signals.values()),
        )

    # One level of implication (laravel -> php), only from at least "likely" detections.
    for source in list(detected.values()):
        if source.confidence < LIKELY:
            continue
        for implied_id in db.technology(source.id).implies:
            implied = detected.get(implied_id)
            if implied is not None and implied.confidence >= source.confidence:
                continue
            implied_spec = db.technology(implied_id)
            note = SignalMatch(
                signal_id=f"implied-by:{source.id}",
                check_id="FP-03",
                weight=0.0,
                evidence=f"{source.name} berjalan di atas {implied_spec.name}",
            )
            detected[implied_id] = DetectedTechnology(
                id=implied_id,
                name=implied_spec.name,
                category=implied_spec.category,
                confidence=source.confidence,
                signals=[*(implied.signals if implied else []), note],
            )

    ordered = sorted(detected.values(), key=lambda t: (-t.confidence, t.name))
    return FingerprintResult(technologies=ordered, versions=list(versions.values()))
