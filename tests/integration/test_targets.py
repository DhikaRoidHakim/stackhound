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

from shound.config import Settings
from shound.core.redaction import redact
from shound.core.session import TargetSession

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
