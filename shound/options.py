"""Validation of user input shared by the CLI and the interactive menu.

Both front-ends turn raw input into a ``ScanRequest`` through these functions, so
a scan started from the menu behaves exactly like the equivalent command line.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from shound.core.models import Severity

# Re-exported: CLI, menu and tests import these from here.
from shound.errors import PreflightError as PreflightError
from shound.errors import UsageError as UsageError

Mode = Literal["recon", "audit", "cve", "deps", "scan"]

FRAMEWORKS = ("laravel", "django", "fastapi", "express", "codeigniter", "generic")
OUTPUT_FORMATS = {".json": "json", ".md": "markdown", ".html": "html"}
LOCKFILE_NAMES = ("composer.lock", "package-lock.json", "requirements.txt")

_COMPONENT_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*$")
_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.-]+)?)$")


class FailOn(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def severity(self) -> Severity:
        return Severity(self.value.upper())


@dataclass(frozen=True)
class ScanRequest:
    mode: Mode
    interactive: bool
    target: str | None = None  # normalized URL
    path: Path | None = None  # lock file for `deps`
    framework: str | None = None  # forced plugin for `audit`
    versions: dict[str, str] = field(default_factory=dict)  # component -> version
    outputs: tuple[Path, ...] = ()
    fail_on: FailOn | None = None
    insecure: bool = False
    method_probe: bool = True
    use_cache: bool = True
    refresh_cache: bool = False
    verbose: bool = False


def normalize_target_url(raw: str) -> str:
    raw = raw.strip()
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError as exc:
        raise UsageError(f"URL target tidak valid: {raw!r} ({exc}).") from exc
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise UsageError(
            f"URL target tidak valid: {raw!r}. Gunakan format http(s)://host[:port][/path]."
        )
    if parts.username is not None or parts.password is not None:
        raise UsageError("URL target tidak boleh berisi kredensial (user:password@).")
    host = parts.hostname.lower()
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def target_key(url: str) -> str:
    """Identity of a target for authorization: scheme, host and effective port."""
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{parts.scheme}://{parts.hostname}:{port}"


def parse_version(raw: str) -> str:
    match = _VERSION_RE.match(raw.strip())
    if not match:
        raise UsageError(f"Versi tidak valid: {raw!r} (contoh: 9.52.4).")
    return match.group(1)


def parse_component_versions(values: list[str] | None) -> dict[str, str]:
    """Parse repeated ``--version komponen=versi`` options."""
    versions: dict[str, str] = {}
    for item in values or []:
        component, sep, version = item.partition("=")
        component = component.strip().lower()
        if not sep or not _COMPONENT_RE.match(component):
            raise UsageError(
                f"Format --version tidak valid: {item!r}. Gunakan komponen=versi, "
                "misalnya laravel=9.52.4."
            )
        if component in versions:
            raise UsageError(f"Komponen {component!r} diberikan lebih dari sekali di --version.")
        versions[component] = parse_version(version)
    return versions


def parse_component(raw: str) -> str:
    component = raw.strip().lower()
    if not _COMPONENT_RE.match(component):
        raise UsageError(f"Nama komponen tidak valid: {raw!r} (contoh: laravel, php, nginx).")
    return component


def parse_outputs(values: list[Path] | None) -> tuple[Path, ...]:
    outputs: list[Path] = []
    for path in values or []:
        if path.suffix.lower() not in OUTPUT_FORMATS:
            allowed = ", ".join(OUTPUT_FORMATS)
            raise UsageError(f"Format laporan tidak dikenal: {path.name}. Gunakan {allowed}.")
        if path not in outputs:
            outputs.append(path)
    return tuple(outputs)


def parse_framework(raw: str | None) -> str | None:
    if raw is None:
        return None
    framework = raw.strip().lower()
    if framework not in FRAMEWORKS:
        raise UsageError(f"Framework tidak dikenal: {raw!r}. Pilihan: {', '.join(FRAMEWORKS)}.")
    return framework


def resolve_lockfile(raw: Path) -> Path:
    """Accept a lock file or a project folder containing one."""
    if raw.is_dir():
        for name in LOCKFILE_NAMES:
            candidate = raw / name
            if candidate.is_file():
                return candidate
        raise PreflightError(
            f"Tidak ada lock file yang didukung di {raw} ({', '.join(LOCKFILE_NAMES)})."
        )
    if not raw.is_file():
        raise PreflightError(f"File tidak ditemukan: {raw}")
    return raw
