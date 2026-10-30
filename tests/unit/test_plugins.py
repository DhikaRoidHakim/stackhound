import itertools
import json
import re
from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
import respx

from shound.config import Settings
from shound.core.baseline import Baseline
from shound.core.fingerprint import DetectedTechnology, FingerprintResult
from shound.core.models import Confidence, Finding, Severity, VersionSource
from shound.core.session import TargetSession
from shound.plugins import PLUGINS, select_plugins
from shound.plugins.base import PluginResult, ScanContext
from shound.plugins.laravel import LaravelPlugin, load_rules

BASE = "https://target.test/"
APP_KEY = "base64:U0VDUkVULUFQUC1LRVktZm9yLXRlc3RzLW9ubHk="
DB_PASSWORD = "unit-test-db-password"
GIT_TOKEN = "unit-test-git-token"
LOG_SECRET = "unit-test-log-token"

ENV_FILE = (
    f"APP_NAME=App\nAPP_ENV=production\nAPP_KEY={APP_KEY}\n"
    f"# DB_PASSWORD=old\nDB_PASSWORD={DB_PASSWORD}\n"
)
ENV_EXAMPLE = "APP_NAME=Laravel\nAPP_ENV=local\nAPP_KEY=\nDB_HOST=127.0.0.1\n"
GIT_CONFIG = (
    "[core]\n\trepositoryformatversion = 0\n[user]\n\temail = dev@example.test\n"
    f'[remote "origin"]\n\turl = https://deploy:{GIT_TOKEN}@git.example.test/app.git\n'
)
LOG = f'[2026-01-01 00:00:00] production.ERROR: boom {{"api_token":"{LOG_SECRET}"}}\n'
COMPOSER_LOCK = json.dumps(
    {"packages": [{"name": "laravel/framework", "version": "v10.48.1"}, {"name": "a/b"}]}
)
RENDERER_PAGE = '"markdown":"# Symfony\\\\...\\nPHP 8.3.36\\nLaravel 12.70.1\\n"'

SECRETS = [APP_KEY, DB_PASSWORD, GIT_TOKEN, LOG_SECRET, "dev@example.test"]


def fingerprint_of(**confidences: float) -> FingerprintResult:
    techs = [
        DetectedTechnology(id=tech, name=tech, category="framework", confidence=conf)
        for tech, conf in confidences.items()
    ]
    return FingerprintResult(technologies=techs)


class TestSelectPlugins:
    def test_registry(self) -> None:
        assert {"laravel": LaravelPlugin} == PLUGINS

    @pytest.mark.parametrize(
        ("confidence", "runs", "noted"), [(1.0, True, False), (0.5, True, True)]
    )
    def test_confident_detection_runs(self, confidence: float, runs: bool, noted: bool) -> None:
        selection = select_plugins(fingerprint_of(laravel=confidence))
        assert (LaravelPlugin in selection.plugins) is runs
        assert any("kemungkinan" in n for n in selection.notes) is noted

    def test_weak_detection_skipped(self) -> None:
        selection = select_plugins(fingerprint_of(laravel=0.2))
        assert selection.plugins == []
        assert "--framework" in selection.notes[0]

    def test_forced(self) -> None:
        selection = select_plugins(fingerprint_of(), forced="laravel")
        assert selection.plugins == [LaravelPlugin]

    def test_forced_unavailable(self) -> None:
        selection = select_plugins(fingerprint_of(laravel=1.0), forced="django")
        assert selection.plugins == []
        assert "belum tersedia" in selection.notes[0]


def test_rules_load_and_compile() -> None:
    rules = load_rules()
    for pattern in [rules.env_line, rules.log_line, rules.git_head, rules.git_config]:
        re.compile(pattern)
    for item in [*rules.panels, *rules.debug_pages]:
        re.compile(item.marker)
    assert [p.name for p in rules.panels if p.verified] == ["Telescope"]


# ------------------------------------------------------------------ Laravel plugin
NOT_FOUND = httpx.Response(404, text="<title>Not Found</title>")


class Site:
    """A fake target: (method, path) -> response; everything else is a real 404."""

    def __init__(self, router: respx.MockRouter) -> None:
        self.pages: dict[tuple[str, str], httpx.Response] = {}
        self.requests: list[httpx.Request] = []
        self.fallback = NOT_FOUND
        router.route(url__startswith=BASE).mock(side_effect=self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        response = self.pages.get((request.method, request.url.path), self.fallback)
        return httpx.Response(
            response.status_code, headers=response.headers, content=response.content
        )

    def serve(self, path: str, status: int = 200, method: str = "GET", **kwargs: object) -> None:
        self.pages[(method, f"/{path}")] = httpx.Response(status, **kwargs)  # type: ignore[arg-type]

    def calls(self, method: str, path: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == method and r.url.path == f"/{path}"]


@pytest.fixture
def site() -> Iterator[Site]:
    with respx.mock(assert_all_called=False) as router:
        yield Site(router)


async def _no_wait(seconds: float) -> None:
    """The rate limiter is covered in test_session.py; here it only slows tests down."""


@pytest.fixture
async def session() -> AsyncIterator[TargetSession]:
    async with TargetSession(Settings(rate_limit=20), sleep=_no_wait) as s:
        yield s


async def run_plugin(session: TargetSession, *, method_probe: bool = True) -> PluginResult:
    counter = itertools.count(1)
    baseline = await Baseline.capture(session, BASE, token=lambda: f"{next(counter):016x}")
    ctx = ScanContext(
        session=session,
        baseline=baseline,
        target=BASE,
        fingerprint=fingerprint_of(laravel=1.0),
        method_probe=method_probe,
    )
    return await LaravelPlugin().run(ctx)


def by_id(result: PluginResult) -> dict[str, Finding]:
    return {f.id: f for f in result.findings}


class TestLaravelPlugin:
    async def test_nothing_exposed(self, site: Site, session: TargetSession) -> None:
        result = await run_plugin(session)
        assert result.findings == []
        assert result.exposed_lockfiles == []

    async def test_soft_404_site_has_no_false_positives(
        self, site: Site, session: TargetSession
    ) -> None:
        shell = "<html><script>APP_KEY=x DB_HOST=y ref: refs/heads/main telescope</script></html>"
        site.fallback = httpx.Response(200, text=shell)
        assert (await run_plugin(session)).findings == []

    async def test_env_exposed(self, site: Site, session: TargetSession) -> None:
        site.serve(".env", text=ENV_FILE)
        finding = by_id(await run_plugin(session))["LRV-01"]
        assert finding.severity is Severity.CRITICAL
        [evidence] = finding.evidence
        assert evidence.snippet == "4 kunci: APP_NAME, APP_ENV, APP_KEY, DB_PASSWORD"

    async def test_env_example_with_placeholders_is_low(
        self, site: Site, session: TargetSession
    ) -> None:
        site.serve(".env.example", text=ENV_EXAMPLE)
        finding = by_id(await run_plugin(session))["LRV-01"]
        assert finding.severity is Severity.LOW
        assert finding.evidence[0].note == "file contoh berisi placeholder"

    async def test_debug_page_via_guarded_probe(self, site: Site, session: TargetSession) -> None:
        site.serve("", 200, method="OPTIONS", headers={"Allow": "GET,HEAD"})
        site.serve("", 405, method="PATCH", text=RENDERER_PAGE)
        result = await run_plugin(session)
        finding = by_id(result)["LRV-02"]
        assert finding.severity is Severity.HIGH
        assert finding.evidence[0].method == "PATCH"
        [patch] = site.calls("PATCH", "")
        assert patch.content == b""
        assert {(v.component, v.version) for v in result.versions} == {
            ("laravel", "12.70.1"),
            ("php", "8.3.36"),
        }
        assert all(v.source is VersionSource.ERROR_PAGE for v in result.versions)

    async def test_probe_skipped_when_patch_allowed(
        self, site: Site, session: TargetSession
    ) -> None:
        site.serve("", 200, method="OPTIONS", headers={"Allow": "GET,HEAD,PATCH"})
        result = await run_plugin(session)
        assert site.calls("PATCH", "") == []
        assert any("Probe PATCH" in n for n in result.notes)

    async def test_probe_disabled(self, site: Site, session: TargetSession) -> None:
        result = await run_plugin(session, method_probe=False)
        assert site.calls("OPTIONS", "") == []
        assert any("--no-method-probe" in n for n in result.notes)

    async def test_log_fetched_with_range_and_not_stored(
        self, site: Site, session: TargetSession
    ) -> None:
        site.serve(
            "storage/logs/laravel.log",
            206,
            text=LOG,
            headers={"Content-Range": "bytes 0-2047/91234"},
        )
        finding = by_id(await run_plugin(session))["LRV-03"]
        [request] = site.calls("GET", "storage/logs/laravel.log")
        assert request.headers["range"] == "bytes=0-2047"
        assert finding.evidence[0].snippet is None
        assert "91234" in (finding.evidence[0].note or "")

    async def test_telescope_open(self, site: Site, session: TargetSession) -> None:
        site.serve(
            "telescope", text="<title>Telescope - Laravel</title><script>window.Telescope = {}"
        )
        assert by_id(await run_plugin(session))["LRV-04"].confidence is Confidence.HIGH

    async def test_unverified_panel_marker_lowers_confidence(
        self, site: Site, session: TargetSession
    ) -> None:
        site.serve("horizon", text="<title>Horizon</title>")
        assert by_id(await run_plugin(session))["LRV-04"].confidence is Confidence.MEDIUM

    async def test_panel_behind_login_is_fine(self, site: Site, session: TargetSession) -> None:
        site.serve("telescope", 302, headers={"Location": f"{BASE}login"})
        site.serve("login", text="<title>Telescope</title>")
        assert "LRV-04" not in by_id(await run_plugin(session))
        assert site.calls("GET", "login") == []  # redirects are not followed

    async def test_composer_lock(self, site: Site, session: TargetSession) -> None:
        site.serve("composer.lock", text=COMPOSER_LOCK)
        result = await run_plugin(session)
        assert by_id(result)["LRV-05"].evidence[0].note == "2 package, laravel/framework 10.48.1"
        assert [lock.url for lock in result.exposed_lockfiles] == [f"{BASE}composer.lock"]
        assert [(v.version, v.source) for v in result.versions] == [
            ("10.48.1", VersionSource.EXPOSED_LOCKFILE)
        ]

    async def test_git_exposed(self, site: Site, session: TargetSession) -> None:
        site.serve(".git/HEAD", text="ref: refs/heads/main\n")
        site.serve(".git/config", text=GIT_CONFIG)
        finding = by_id(await run_plugin(session))["LRV-06"]
        assert finding.severity is Severity.CRITICAL
        assert [e.snippet for e in finding.evidence] == [
            "ref: refs/heads/main",
            "url = https://***@git.example.test/app.git",
        ]
        # Only HEAD and config are read; no git objects are requested.
        assert all(not r.url.path.startswith("/.git/objects") for r in site.requests)

    async def test_no_secret_reaches_any_finding(self, site: Site, session: TargetSession) -> None:
        site.serve(".env", text=ENV_FILE)
        site.serve(".git/HEAD", text="ref: refs/heads/main\n")
        site.serve(".git/config", text=GIT_CONFIG)
        site.serve("storage/logs/laravel.log", text=LOG)
        result = await run_plugin(session)
        assert set(by_id(result)) == {"LRV-01", "LRV-03", "LRV-06"}
        dumped = json.dumps([f.model_dump(mode="json") for f in result.findings])
        for secret in SECRETS:
            assert secret not in dumped, secret

    async def test_only_safe_methods_sent(self, site: Site, session: TargetSession) -> None:
        await run_plugin(session)
        assert {r.method for r in site.requests} <= {"GET", "OPTIONS"}

    async def test_request_failure_becomes_error(self, session: TargetSession) -> None:
        with respx.mock(assert_all_called=False) as router:
            # Registered before the Site catch-all so it takes precedence.
            router.get(f"{BASE}.env").mock(side_effect=httpx.ReadTimeout("timeout"))
            Site(router)
            result = await run_plugin(session)
        assert result.findings == []
        assert any(e.startswith("env_files") for e in result.errors)
