"""PHP Laravel misconfiguration checks LRV-01 .. LRV-06 (PRD §3.4.2, BACKLOG T-109).

Non-intrusive: only GET requests (plus the OPTIONS-guarded PATCH probe of
LRV-02, MEMORY D-006). Nothing is downloaded beyond the single file being
checked: no git objects, no full logs (a 2 KiB Range request is enough).
Paths and markers live in ``data/laravel.json``; real-target findings that
shaped them are MEMORY F-013 .. F-016.
"""

import json
import re
from collections.abc import Callable
from functools import cache
from importlib.resources import files
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict

from shound.core.fingerprint import Observation, fingerprint
from shound.core.models import (
    Confidence,
    DetectedVersion,
    Evidence,
    Finding,
    Severity,
    VersionSource,
)
from shound.core.redaction import redacted_evidence
from shound.core.session import HttpResponse, TargetRequestError
from shound.plugins.base import BasePlugin, ExposedLockfile, PluginResult, ScanContext

PLUGIN_ID = "laravel"
LOG_RANGE = "bytes=0-2047"
MAX_ENV_KEYS = 25
_ENV_KEY = re.compile(r"(?m)^[ \t]*(?:export[ \t]+)?([A-Z_][A-Z0-9_]*)[ \t]*=")
_GIT_REMOTE = re.compile(r"(?m)^[ \t]*url[ \t]*=.*$")
_REFERENCES = ["https://laravel.com/docs/deployment", "https://laravel.com/docs/configuration"]


class _Panel(BaseModel):
    name: str
    path: str
    marker: str
    verified: bool  # marker confirmed against a real install (see tests/targets)


class _DebugPage(BaseModel):
    name: str
    marker: str


class LaravelRules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    env_files: list[str]
    env_line: str
    env_min_lines: int
    log_files: list[str]
    log_line: str
    debug_pages: list[_DebugPage]
    panels: list[_Panel]
    composer_files: list[str]
    git_head: str
    git_config: str


@cache
def load_rules() -> LaravelRules:
    raw = files("shound").joinpath("data/laravel.json").read_text(encoding="utf-8")
    return LaravelRules.model_validate(json.loads(raw))


def _finding(
    check_id: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
    evidence: list[Evidence],
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        id=check_id,
        title=title,
        category="exposure" if check_id != "LRV-02" else "misconfig",
        severity=severity,
        confidence=confidence,
        plugin=PLUGIN_ID,
        description=description,
        evidence=evidence,
        remediation=remediation,
        references=list(_REFERENCES),
    )


class LaravelPlugin(BasePlugin):
    id: ClassVar[str] = PLUGIN_ID
    name: ClassVar[str] = "PHP Laravel"
    ecosystem: ClassVar[str | None] = "Packagist"
    package: ClassVar[str | None] = "laravel/framework"

    def __init__(self) -> None:
        self.rules = load_rules()

    async def run(self, ctx: ScanContext) -> PluginResult:
        result = PluginResult()
        for check in (
            self._env_files,
            self._debug_mode,
            self._log_files,
            self._panels,
            self._composer_files,
            self._git_repository,
        ):
            try:
                await check(ctx, result)
            except TargetRequestError as exc:
                result.notes.append(f"{check.__name__.lstrip('_')}: request gagal ({exc}).")
        return result

    async def _get(self, ctx: ScanContext, path: str, **kwargs: Any) -> HttpResponse:
        return await ctx.session.get(ctx.baseline.url_for(path), **kwargs)

    # LRV-01 ---------------------------------------------------------------
    async def _env_files(self, ctx: ScanContext, result: PluginResult) -> None:
        env_line = re.compile(self.rules.env_line)

        def is_env(response: HttpResponse) -> bool:
            return len(env_line.findall(response.text)) >= self.rules.env_min_lines

        evidence: list[Evidence] = []
        severity = Severity.LOW
        for path in self.rules.env_files:
            response = await self._get(ctx, path)
            if not ctx.baseline.confirm(response, is_env):
                continue
            placeholder = path.endswith(".example") and re.search(
                r"(?m)^APP_KEY=\s*$", response.text
            )
            if not placeholder:
                severity = Severity.CRITICAL
            # Key names only; no value of the file is ever kept (CLAUDE.md rule 3).
            keys = _ENV_KEY.findall(response.text)
            shown = ", ".join(keys[:MAX_ENV_KEYS]) + (" ..." if len(keys) > MAX_ENV_KEYS else "")
            evidence.append(
                redacted_evidence(
                    response.url,
                    status_code=response.status_code,
                    snippet=f"{len(keys)} kunci: {shown}",
                    note="file contoh berisi placeholder" if placeholder else None,
                )
            )
        if evidence:
            result.findings.append(
                _finding(
                    "LRV-01",
                    "File environment (.env) dapat diunduh",
                    severity,
                    "File konfigurasi environment dapat diakses publik. File ini biasanya berisi "
                    "APP_KEY, kredensial database, dan API key layanan pihak ketiga.",
                    "Arahkan DocumentRoot Nginx/Apache ke folder public/, blokir dotfile "
                    "(nginx: location ~ /\\. { deny all; }), lalu rotasi SEMUA secret yang "
                    "sempat terekspos, termasuk APP_KEY.",
                    evidence,
                )
            )

    # LRV-02 ---------------------------------------------------------------
    async def _debug_mode(self, ctx: ScanContext, result: PluginResult) -> None:
        pages = [(page.name, re.compile(page.marker)) for page in self.rules.debug_pages]

        def debug_page(response: HttpResponse) -> str | None:
            return next((name for name, marker in pages if marker.search(response.text)), None)

        # Passive first: a debug page may already have been served.
        candidates: list[tuple[str, HttpResponse]] = [("GET", r) for r in ctx.responses]
        if ctx.method_probe:
            probe = await ctx.session.probe_patch(ctx.target)
            if probe is None:
                result.notes.append(
                    "Probe PATCH LRV-02 dilewati: OPTIONS tidak membuktikan PATCH ditolak."
                )
            else:
                candidates.append(("PATCH", probe))
        else:
            result.notes.append("Probe PATCH LRV-02 dinonaktifkan (--no-method-probe).")

        for method, response in candidates:
            name = debug_page(response)
            if name is None:
                continue
            # Header versions are already known from the pre-flight; keep page-only ones.
            versions = [
                v
                for v in fingerprint([Observation(response)]).versions
                if v.source is VersionSource.ERROR_PAGE
            ]
            result.versions.extend(versions)
            leaked = ", ".join(f"{v.component} {v.version}" for v in versions)
            result.findings.append(
                _finding(
                    "LRV-02",
                    "Debug mode aktif (stack trace terbuka)",
                    Severity.HIGH,
                    f"Halaman error {name} ditampilkan ke publik. Halaman ini membocorkan stack "
                    "trace, path server, query, dan potongan konfigurasi"
                    + (f"; versi yang terbaca: {leaked}." if leaked else "."),
                    "Set APP_DEBUG=false dan APP_ENV=production di .env, lalu jalankan "
                    "php artisan config:cache.",
                    [
                        redacted_evidence(
                            response.url,
                            method=method,
                            status_code=response.status_code,
                            note=f"Halaman {name} terdeteksi" + (f" ({leaked})" if leaked else ""),
                        )
                    ],
                )
            )
            return

    # LRV-03 ---------------------------------------------------------------
    async def _log_files(self, ctx: ScanContext, result: PluginResult) -> None:
        log_line = re.compile(self.rules.log_line)
        evidence: list[Evidence] = []
        for path in self.rules.log_files:
            response = await self._get(ctx, path, headers={"Range": LOG_RANGE})
            if not ctx.baseline.confirm(response, log_line):
                continue
            size = response.headers.get("content-range", "").rpartition("/")[2] or "?"
            # The log content itself is never stored (CLAUDE.md rule 3).
            evidence.append(
                redacted_evidence(
                    response.url,
                    status_code=response.status_code,
                    note=f"File log dapat dibaca (ukuran total {size} byte); isi tidak disimpan.",
                )
            )
        if evidence:
            result.findings.append(
                _finding(
                    "LRV-03",
                    "File log Laravel dapat diunduh",
                    Severity.HIGH,
                    "Log aplikasi dapat dibaca publik. Log sering memuat stack trace, data "
                    "request, token, dan data pribadi pengguna.",
                    "Pastikan folder storage/ berada di luar web root; hanya symlink "
                    "public/storage yang boleh terekspos (php artisan storage:link).",
                    evidence,
                )
            )

    # LRV-04 ---------------------------------------------------------------
    async def _panels(self, ctx: ScanContext, result: PluginResult) -> None:
        evidence: list[Evidence] = []
        all_verified = True
        for panel in self.rules.panels:
            # No redirect following: a 302 to /login means the gate works.
            response = await self._get(ctx, panel.path)
            if not ctx.baseline.confirm(response, re.compile(panel.marker)):
                continue
            all_verified = all_verified and panel.verified
            evidence.append(
                redacted_evidence(
                    response.url,
                    status_code=response.status_code,
                    note=f"Dashboard {panel.name} terbuka tanpa autentikasi",
                )
            )
        if evidence:
            result.findings.append(
                _finding(
                    "LRV-04",
                    "Dashboard internal Laravel terbuka",
                    Severity.HIGH,
                    "Dashboard monitoring internal dapat diakses tanpa login. Telescope, misalnya, "
                    "merekam request, query, job, dan exception lengkap dengan datanya.",
                    "Batasi gate di TelescopeServiceProvider/HorizonServiceProvider "
                    "(viewTelescope, viewHorizon) hanya untuk pengguna tertentu, dan jangan "
                    "pakai APP_ENV=local di server publik.",
                    evidence,
                    Confidence.HIGH if all_verified else Confidence.MEDIUM,
                )
            )

    # LRV-05 ---------------------------------------------------------------
    async def _composer_files(self, ctx: ScanContext, result: PluginResult) -> None:
        def json_with(key: str) -> Callable[[HttpResponse], bool]:
            def check(response: HttpResponse) -> bool:
                try:
                    data = json.loads(response.text)
                except ValueError:
                    return False
                return isinstance(data, dict) and key in data

            return check

        evidence: list[Evidence] = []
        for path in self.rules.composer_files:
            key = "packages" if path.endswith(".lock") else "require"
            response = await self._get(ctx, path)
            if not ctx.baseline.confirm(response, json_with(key)):
                continue
            note = None
            if key == "packages":
                packages = json.loads(response.text).get("packages", [])
                framework = next(
                    (p for p in packages if p.get("name") == "laravel/framework"), None
                )
                note = f"{len(packages)} package"
                if framework and framework.get("version"):
                    version = str(framework["version"]).lstrip("v")
                    note += f", laravel/framework {version}"
                    result.versions.append(
                        DetectedVersion(
                            component=PLUGIN_ID,
                            version=version,
                            source=VersionSource.EXPOSED_LOCKFILE,
                            evidence=f"{response.url} (laravel/framework)",
                        )
                    )
                result.exposed_lockfiles.append(
                    ExposedLockfile(url=response.url, ecosystem="Packagist", content=response.text)
                )
            evidence.append(
                redacted_evidence(response.url, status_code=response.status_code, note=note)
            )
        if evidence:
            result.findings.append(
                _finding(
                    "LRV-05",
                    "File manifest Composer dapat diunduh",
                    Severity.MEDIUM,
                    "composer.json/composer.lock dapat diunduh, sehingga daftar lengkap library "
                    "beserta versinya terlihat dan mudah dicocokkan dengan CVE.",
                    "Pindahkan file manifest ke luar folder public/ atau blokir aksesnya di web "
                    "server.",
                    evidence,
                )
            )

    # LRV-06 ---------------------------------------------------------------
    async def _git_repository(self, ctx: ScanContext, result: PluginResult) -> None:
        evidence: list[Evidence] = []
        checks = [(".git/HEAD", self.rules.git_head), (".git/config", self.rules.git_config)]
        for path, marker in checks:
            response = await self._get(ctx, path)
            if not ctx.baseline.confirm(response, re.compile(marker)):
                continue
            if path.endswith("HEAD"):
                snippet = response.text.strip()[:80]
            else:
                # Only the remote URLs (credentials masked by redaction); the rest of
                # .git/config can hold personal data such as user.email.
                remotes = [line.strip() for line in _GIT_REMOTE.findall(response.text)]
                snippet = "\n".join(remotes) or "[core] ditemukan, tanpa remote"
            evidence.append(
                redacted_evidence(response.url, status_code=response.status_code, snippet=snippet)
            )
        if evidence:
            result.findings.append(
                _finding(
                    "LRV-06",
                    "Folder .git dapat diakses publik",
                    Severity.CRITICAL,
                    "Metadata repository git dapat diakses, sehingga kode sumber dan riwayatnya "
                    "berpotensi dapat direkonstruksi.",
                    "Blokir akses ke .git di web server (nginx: location ~ /\\.git { deny all; }), "
                    "jangan deploy dengan git pull di dalam web root, dan rotasi kredensial yang "
                    "tercantum di remote URL.",
                    evidence,
                )
            )
