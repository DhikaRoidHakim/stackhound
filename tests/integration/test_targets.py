"""Smoke tests for the Docker targets in tests/targets (BACKLOG T-006).

They prove each target behaves the way later plugin tests rely on, and exercise
TargetSession and redaction against real servers.

    docker compose -f tests/targets/docker-compose.yml up -d --build
    pytest -m targets
"""

import json
import re
import socket
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import pytest
from typer.testing import CliRunner

from shound import cli
from shound.config import Settings
from shound.core.baseline import Baseline, Signature
from shound.core.fingerprint import LIKELY, Observation, fingerprint
from shound.core.headers_tls import audit_cookies, audit_cors, audit_security_headers, audit_tls
from shound.core.models import Finding, Severity, VersionSource
from shound.core.preflight import run_preflight
from shound.core.redaction import redact
from shound.core.session import TargetSession
from shound.plugins.base import PluginResult, ScanContext
from shound.plugins.laravel import LaravelPlugin

pytestmark = pytest.mark.targets

LARAVEL12 = "http://127.0.0.1:8081"
LARAVEL10 = "http://127.0.0.1:8082"
SPA = "http://127.0.0.1:8083"
CLEAN = "http://127.0.0.1:8084"
LARAVEL_TARGETS = [LARAVEL12, LARAVEL10]

# Fake secrets planted by tests/targets/laravel-debug/configure.sh
FAKE_SECRETS = [
    "shound-fake-db-password",
    "shound-fake-mail-password",
    "AKIASHOUNDFAKEKEY000",
    "shound/fake/secret/access/key/0000000000",
    "shound-fake-git-token",
    "shound-fake-log-token",
]

LOG_LINE = re.compile(r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \w+\.[A-Z]+:", re.MULTILINE)


def require(base: str) -> None:
    port = urlsplit(base).port
    assert port is not None
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
    except OSError:
        pytest.skip(
            f"{base} is not running (docker compose -f tests/targets/docker-compose.yml up -d)"
        )


def assert_no_fake_secrets(text: str) -> None:
    for secret in FAKE_SECRETS:
        assert secret not in text, f"fake secret survived redaction: {secret}"


@pytest.fixture
async def session() -> AsyncIterator[TargetSession]:
    async with TargetSession(Settings(rate_limit=20)) as s:
        yield s


@pytest.mark.parametrize("base", LARAVEL_TARGETS)
class TestLaravelTargets:
    async def test_session_cookie(self, session: TargetSession, base: str) -> None:
        require(base)
        response = await session.get(f"{base}/")
        assert response.status_code == 200
        cookies = dict(
            c.split(";", 1)[0].split("=", 1) for c in response.headers.get_list("set-cookie")
        )
        # Laravel <= 10 names it "<app>_session", Laravel >= 11 "<app>-session" (MEMORY F-013)
        assert {"laravel_session", "laravel-session"} & cookies.keys()
        assert "XSRF-TOKEN" in cookies
        # Every encrypted Laravel cookie is base64 JSON starting with {"iv":
        assert all(value.startswith("eyJpdiI6") for value in cookies.values())

    @pytest.mark.parametrize("path", ["/.env", "/.env.backup"])
    async def test_env_exposed_and_redactable(
        self, session: TargetSession, base: str, path: str
    ) -> None:
        require(base)
        response = await session.get(f"{base}{path}")
        assert response.status_code == 200
        assert "APP_KEY=base64:" in response.text
        assert "shound-fake-db-password" in response.text
        redacted = redact(response.text, max_length=None)
        assert_no_fake_secrets(redacted)
        assert "APP_KEY=***" in redacted

    async def test_git_exposed_and_redactable(self, session: TargetSession, base: str) -> None:
        require(base)
        head = await session.get(f"{base}/.git/HEAD")
        assert head.status_code == 200
        assert head.text.startswith("ref: refs/heads/")
        config = await session.get(f"{base}/.git/config")
        assert config.status_code == 200
        assert "[core]" in config.text
        assert_no_fake_secrets(redact(config.text, max_length=None))

    async def test_log_exposed_with_range(self, session: TargetSession, base: str) -> None:
        require(base)
        response = await session.get(
            f"{base}/storage/logs/laravel.log", headers={"Range": "bytes=0-2047"}
        )
        assert response.status_code in {200, 206}
        assert len(response.body) <= 2048
        assert LOG_LINE.search(response.text)

    async def test_composer_files_exposed(self, session: TargetSession, base: str) -> None:
        require(base)
        lock = await session.get(f"{base}/composer.lock")
        assert lock.status_code == 200
        names = {pkg["name"] for pkg in json.loads(lock.text)["packages"]}
        assert {"laravel/framework", "laravel/telescope"} <= names
        manifest = await session.get(f"{base}/composer.json")
        assert "require" in json.loads(manifest.text)

    async def test_telescope_open_without_redirect(self, session: TargetSession, base: str) -> None:
        require(base)
        response = await session.get(f"{base}/telescope")
        assert response.status_code == 200
        # Telescope 5 inlines its assets (no /vendor/telescope/app.js) and the page is
        # bigger than the body cap, so the signature must sit near the top (MEMORY F-014).
        assert response.truncated
        assert "<title>Telescope" in response.text
        assert "window.Telescope =" in response.text

    async def test_unknown_route_is_real_404(self, session: TargetSession, base: str) -> None:
        require(base)
        response = await session.get(f"{base}/shound-missing-0123456789abcdef")
        assert response.status_code == 404

    async def test_guarded_patch_probe_reveals_debug_page(
        self, session: TargetSession, base: str
    ) -> None:
        require(base)
        response = await session.probe_patch(f"{base}/")
        assert response is not None, "OPTIONS / did not prove PATCH is rejected"
        assert response.status_code == 405
        assert "MethodNotAllowedHttpException" in response.text


async def test_laravel10_debug_page_is_ignition_and_leaks_versions(
    session: TargetSession,
) -> None:
    require(LARAVEL10)
    response = await session.probe_patch(f"{LARAVEL10}/")
    assert response is not None
    assert "spatie/laravel-ignition" in response.text
    assert "window.ignite" in response.text
    assert re.search(r'"laravel_version":"10\.\d+\.\d+"', response.text)
    assert re.search(r'"php_version":"8\.\d+\.\d+"', response.text)


async def test_laravel12_debug_page_is_builtin_renderer_and_leaks_versions(
    session: TargetSession,
) -> None:
    # Laravel >= 11 ships its own exception page instead of Ignition (MEMORY F-015).
    require(LARAVEL12)
    response = await session.probe_patch(f"{LARAVEL12}/")
    assert response is not None
    assert "ignition" not in response.text.lower()
    assert "## Stack Trace" in response.text
    # The versions sit in a JSON-escaped markdown blob ("\nLaravel 12.x.y"), so no \b.
    assert re.search(r"Laravel 12\.\d+\.\d+", response.text)
    assert re.search(r"PHP 8\.\d+\.\d+", response.text)


class TestSpaCatchAll:
    @pytest.mark.parametrize(
        "path", ["/.env", "/.git/HEAD", "/telescope", "/storage/logs/laravel.log", "/x-123"]
    )
    async def test_every_path_returns_the_shell(self, session: TargetSession, path: str) -> None:
        require(SPA)
        home = await session.get(f"{SPA}/")
        response = await session.get(f"{SPA}{path}")
        assert response.status_code == 200
        assert response.body == home.body


class TestCleanTarget:
    async def test_security_headers_present(self, session: TargetSession) -> None:
        require(CLEAN)
        response = await session.get(f"{CLEAN}/")
        assert response.status_code == 200
        for header in (
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        ):
            assert header in response.headers, header
        assert response.headers["server"] == "nginx"  # no version disclosed
        cookie = response.headers["set-cookie"]
        assert "HttpOnly" in cookie
        assert "Secure" in cookie
        assert "SameSite=Lax" in cookie

    @pytest.mark.parametrize("path", ["/.env", "/.git/HEAD", "/telescope", "/composer.lock"])
    async def test_sensitive_paths_are_404(self, session: TargetSession, path: str) -> None:
        require(CLEAN)
        response = await session.get(f"{CLEAN}{path}")
        assert response.status_code == 404


# ---------------------------------------------------------------- pre-flight & baseline
ENV_SIGNATURE = re.compile(r"^APP_KEY=", re.MULTILINE)
WEAK_SIGNATURES: dict[str, Signature] = {
    # Deliberately weak: each string also appears inside the SPA shell, so only the
    # baseline comparison can stop a false positive there.
    "/.env": lambda r: "APP_KEY=" in r.text,
    "/.git/HEAD": lambda r: "ref: refs/heads/" in r.text,
    "/telescope": lambda r: "telescope" in r.text.lower(),
}


@pytest.mark.parametrize("base", [*LARAVEL_TARGETS, SPA, CLEAN])
async def test_preflight_on_targets(session: TargetSession, base: str) -> None:
    require(base)
    result = await run_preflight(f"{base}/", session)
    assert result.addresses == ("127.0.0.1",)
    assert result.response.status_code == 200
    assert result.tls is None  # plain HTTP


@pytest.mark.parametrize("base", LARAVEL_TARGETS)
async def test_baseline_confirms_real_exposures_on_laravel(
    session: TargetSession, base: str
) -> None:
    require(base)
    baseline = await Baseline.capture(session, f"{base}/")
    assert baseline.available
    assert not baseline.soft_404
    env = await session.get(baseline.url_for("/.env"))
    assert baseline.confirm(env, ENV_SIGNATURE)
    for path, signature in WEAK_SIGNATURES.items():
        response = await session.get(baseline.url_for(path))
        assert baseline.confirm(response, signature), path


async def test_baseline_rejects_everything_on_spa(session: TargetSession) -> None:
    require(SPA)
    baseline = await Baseline.capture(session, f"{SPA}/")
    assert baseline.soft_404
    assert baseline.soft_404_finding() is not None
    for path, signature in WEAK_SIGNATURES.items():
        response = await session.get(baseline.url_for(path))
        assert response.status_code == 200
        assert signature(response), f"{path}: shell should contain the weak marker"
        assert not baseline.confirm(response, signature), path


async def test_baseline_on_clean_target(session: TargetSession) -> None:
    require(CLEAN)
    baseline = await Baseline.capture(session, f"{CLEAN}/")
    assert not baseline.soft_404
    for path, signature in WEAK_SIGNATURES.items():
        response = await session.get(baseline.url_for(path))
        assert not baseline.confirm(response, signature), path


# ---------------------------------------------------------------- fingerprint
async def observe(session: TargetSession, base: str) -> list[Observation]:
    result = await run_preflight(f"{base}/", session)
    baseline = await Baseline.capture(session, result.final_url)
    return [
        Observation(result.response),
        *(Observation(sample.response, not_found=True) for sample in baseline.samples),
    ]


@pytest.mark.parametrize("base", LARAVEL_TARGETS)
async def test_fingerprint_laravel_targets(session: TargetSession, base: str) -> None:
    require(base)
    result = fingerprint(await observe(session, base))
    laravel = result.get("laravel")
    assert laravel is not None
    assert laravel.level == "strong"
    assert {s.check_id for s in laravel.signals} == {"FP-01", "FP-04"}
    assert result.frameworks()[0].id == "laravel"
    [php] = result.versions_of("php")
    assert php.source is VersionSource.HEADER
    assert php.distro is None  # official PHP image is built from source
    [apache] = result.versions_of("apache")
    assert apache.distro == "Debian"


@pytest.mark.parametrize(("base", "major"), [(LARAVEL12, "12"), (LARAVEL10, "10")])
async def test_fingerprint_reads_framework_version_from_debug_page(
    session: TargetSession, base: str, major: str
) -> None:
    require(base)
    probe = await session.probe_patch(f"{base}/")
    assert probe is not None
    result = fingerprint([Observation(probe)])
    [laravel] = result.versions_of("laravel")
    assert laravel.version.startswith(f"{major}.")
    assert laravel.source is VersionSource.ERROR_PAGE
    assert result.versions_of("php")


async def test_fingerprint_spa_has_no_likely_framework(session: TargetSession) -> None:
    require(SPA)
    result = fingerprint(await observe(session, SPA))
    assert all(t.confidence < LIKELY for t in result.frameworks())
    assert [v.version for v in result.versions_of("nginx")] == ["1.27.5"]


async def test_fingerprint_clean_target(session: TargetSession) -> None:
    require(CLEAN)
    result = fingerprint(await observe(session, CLEAN))
    assert result.frameworks() == []
    assert result.versions == []  # server_tokens off
    assert result.confidence("nginx") == 0.9


# ---------------------------------------------------------------- SH-01/02/03/05
async def audit_target(session: TargetSession, base: str) -> dict[str, Finding]:
    result = await run_preflight(f"{base}/", session)
    findings = [
        *audit_security_headers(result.response),
        *audit_cookies([result.response]),
        *await audit_cors(session, result.final_url),
    ]
    return {f.id: f for f in findings}


@pytest.mark.parametrize("base", LARAVEL_TARGETS)
async def test_header_audit_laravel(session: TargetSession, base: str) -> None:
    require(base)
    found = await audit_target(session, base)
    assert set(found) == {
        "SH-01.CSP",
        "SH-01.XFO",
        "SH-01.XCTO",
        "SH-01.RP",
        "SH-01.PP",
        "SH-05.SERVER",
        "SH-05.POWERED-BY",
    }
    # Laravel's own cookie defaults pass SH-02 over plain HTTP (XSRF-TOKEN is exempt
    # from HttpOnly on purpose), and Laravel sends no CORS headers for "/".


async def test_header_audit_spa_cors(session: TargetSession) -> None:
    require(SPA)
    found = await audit_target(session, SPA)
    assert found["SH-03.REFLECT"].severity is Severity.HIGH
    assert found["SH-03.NULL"].severity is Severity.MEDIUM
    assert "SH-05.SERVER" in found


async def test_header_audit_clean_target_has_no_findings(session: TargetSession) -> None:
    require(CLEAN)
    assert await audit_target(session, CLEAN) == {}


@pytest.mark.parametrize("base", [*LARAVEL_TARGETS, SPA, CLEAN])
async def test_tls_audit_plain_http_targets(session: TargetSession, base: str) -> None:
    require(base)
    result = await run_preflight(f"{base}/", session)
    sent = session.request_count
    audit = await audit_tls(session, result)
    assert [f.id for f in audit.findings] == ["SH-04.HTTP"]
    assert session.request_count == sent  # decided from the pre-flight response alone


# ---------------------------------------------------------------- Laravel plugin
async def run_laravel_plugin(session: TargetSession, base: str) -> PluginResult:
    result = await run_preflight(f"{base}/", session)
    baseline = await Baseline.capture(session, result.final_url)
    observed = [
        Observation(result.response),
        *(Observation(s.response, not_found=True) for s in baseline.samples),
    ]
    ctx = ScanContext(
        session=session,
        baseline=baseline,
        target=result.final_url,
        fingerprint=fingerprint(observed),
        responses=(result.response, *(s.response for s in baseline.samples)),
    )
    return await LaravelPlugin().run(ctx)


@pytest.mark.parametrize("base", LARAVEL_TARGETS)
async def test_laravel_plugin_finds_every_exposure(session: TargetSession, base: str) -> None:
    require(base)
    result = await run_laravel_plugin(session, base)
    found = {f.id: f for f in result.findings}
    assert set(found) == {"LRV-01", "LRV-02", "LRV-03", "LRV-04", "LRV-05", "LRV-06"}
    assert found["LRV-01"].severity is Severity.CRITICAL
    assert found["LRV-06"].severity is Severity.CRITICAL
    assert [lock.url for lock in result.exposed_lockfiles] == [f"{base}/composer.lock"]
    sources = {v.source for v in result.versions if v.component == "laravel"}
    assert sources == {VersionSource.ERROR_PAGE, VersionSource.EXPOSED_LOCKFILE}
    dumped = json.dumps([f.model_dump(mode="json") for f in result.findings])
    assert_no_fake_secrets(dumped)
    assert "fixture@example.test" not in dumped  # git user.email is not evidence


@pytest.mark.parametrize("base", [SPA, CLEAN])
async def test_laravel_plugin_forced_on_non_laravel_has_no_findings(
    session: TargetSession, base: str
) -> None:
    require(base)
    result = await run_laravel_plugin(session, base)
    assert result.findings == []


# ---------------------------------------------------------------- grade & exit code
@pytest.mark.parametrize(
    ("args", "code", "grade"),
    [
        (["audit", LARAVEL12], 0, "F"),
        (["audit", LARAVEL12, "--fail-on", "critical"], 1, "F"),
        (["recon", CLEAN], 0, "A+"),
        (["recon", CLEAN, "--fail-on", "low"], 1, "A+"),
        (["recon", CLEAN, "--fail-on", "medium"], 0, "A+"),
    ],
)
def test_cli_grade_and_exit_code(args: list[str], code: int, grade: str) -> None:
    require(args[1])
    result = CliRunner().invoke(cli.app, [*args, "--authorized"])
    assert result.exit_code == code, result.output
    assert f"Security Grade: {grade} " in " ".join(result.output.split())
