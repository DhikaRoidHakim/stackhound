import itertools
import re
from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
import respx

from shound.config import Settings
from shound.core.baseline import Baseline, base_url, normalize_body
from shound.core.models import Severity
from shound.core.session import HttpResponse, TargetSession

BASE = "https://target.test/"
NOT_FOUND = (
    "<html><title>404 Not Found</title><body>Halaman {path} tidak ada. id={id}</body></html>"
)
ENV_SIGNATURE = re.compile(r"^APP_KEY=", re.MULTILINE)


@pytest.fixture
def mock() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        yield router


@pytest.fixture
async def session() -> AsyncIterator[TargetSession]:
    async with TargetSession(Settings()) as s:
        yield s


def response(url: str, status: int, text: str) -> HttpResponse:
    return HttpResponse("GET", url, status, httpx.Headers(), text.encode(), False)


async def capture(session: TargetSession, target: str = BASE) -> Baseline:
    counter = itertools.count(1)
    return await Baseline.capture(session, target, token=lambda: f"{next(counter):016x}")


class TestBaseUrl:
    @pytest.mark.parametrize(
        ("target", "expected"),
        [
            ("https://x.test", "https://x.test/"),
            ("https://x.test/", "https://x.test/"),
            ("https://x.test/app", "https://x.test/app/"),
            ("https://x.test/app/", "https://x.test/app/"),
            ("https://x.test/app/index.php?a=1", "https://x.test/app/"),
            ("http://127.0.0.1:8081/", "http://127.0.0.1:8081/"),
        ],
    )
    def test_base_url(self, target: str, expected: str) -> None:
        assert base_url(target) == expected


class TestNormalize:
    def test_volatile_parts_removed(self) -> None:
        a = normalize_body("Request 1234 token=AbCdEfGhIjKlMnOpQrStUvWx nonce deadbeefcafe")
        b = normalize_body("Request 9876 token=ZyXwVuTsRqPoNmLkJiHgFeDc nonce 0123456789ab")
        assert a == b

    def test_echoed_path_removed(self) -> None:
        a = normalize_body("Page /shound-1 not found", echoes=("/shound-1",))
        b = normalize_body("Page /.env not found", echoes=("/.env",))
        assert a == b

    def test_short_echo_ignored(self) -> None:
        assert normalize_body("a/b/c", echoes=("/",)) == "a/b/c"


class TestCapture:
    async def test_real_404_site(self, mock: respx.MockRouter, session: TargetSession) -> None:
        probe = mock.get(url__regex=r"https://target\.test/shound-[0-9a-f]{16}(\.txt)?$")
        probe.respond(404, text="not found")
        baseline = await capture(session)
        assert probe.call_count == 2
        urls = [s.url for s in baseline.samples]
        assert urls == [f"{BASE}shound-0000000000000001", f"{BASE}shound-0000000000000002.txt"]
        assert baseline.available
        assert not baseline.soft_404
        assert baseline.soft_404_finding() is None

    async def test_random_tokens_differ_per_capture(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        mock.get(url__startswith=BASE).respond(404)
        first = await Baseline.capture(session, BASE)
        second = await Baseline.capture(session, BASE)
        assert {s.url for s in first.samples}.isdisjoint(s.url for s in second.samples)

    async def test_probes_relative_to_target_directory(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        mock.get(url__startswith=BASE).respond(404)
        baseline = await capture(session, f"{BASE}app/index.php")
        assert all(s.url.startswith(f"{BASE}app/shound-") for s in baseline.samples)
        assert baseline.url_for("/.env") == f"{BASE}app/.env"

    async def test_soft_404_site(self, mock: respx.MockRouter, session: TargetSession) -> None:
        mock.get(url__startswith=BASE).respond(200, text="<div id=app></div>")
        baseline = await capture(session)
        assert baseline.soft_404
        finding = baseline.soft_404_finding()
        assert finding is not None
        assert finding.id == "FP-06"
        assert finding.severity is Severity.INFO
        assert len(finding.evidence) == 2

    async def test_probe_failure_recorded(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        mock.get(url__startswith=BASE).mock(side_effect=httpx.ReadTimeout("timed out"))
        baseline = await capture(session)
        assert not baseline.available
        assert len(baseline.errors) == 2


class TestConfirm:
    @staticmethod
    def baseline_from(*pages: tuple[str, int, str]) -> Baseline:
        from shound.core.baseline import BaselineSample

        return Baseline(BASE, [BaselineSample.from_response(response(*p)) for p in pages])

    def test_real_file_confirmed_on_404_site(self) -> None:
        baseline = self.baseline_from((f"{BASE}shound-1", 404, "not found"))
        env = response(f"{BASE}.env", 200, "APP_NAME=x\nAPP_KEY=base64:abc\n")
        assert baseline.confirm(env, ENV_SIGNATURE)

    @pytest.mark.parametrize("status", [404, 403, 302, 500])
    def test_non_success_status_never_confirmed(self, status: int) -> None:
        baseline = self.baseline_from((f"{BASE}shound-1", 404, "not found"))
        env = response(f"{BASE}.env", status, "APP_KEY=base64:abc\n")
        assert not baseline.confirm(env, ENV_SIGNATURE)

    def test_partial_content_confirmed(self) -> None:
        baseline = self.baseline_from((f"{BASE}shound-1", 404, "not found"))
        log = response(
            f"{BASE}storage/logs/laravel.log", 206, "[2026-01-01 00:00:00] local.ERROR: x"
        )
        assert baseline.confirm(log, re.compile(r"local\.ERROR"))

    def test_signature_must_match(self) -> None:
        baseline = self.baseline_from((f"{BASE}shound-1", 404, "not found"))
        page = response(f"{BASE}.env", 200, "<html>hello</html>")
        assert not baseline.confirm(page, ENV_SIGNATURE)

    def test_callable_signature(self) -> None:
        baseline = self.baseline_from((f"{BASE}shound-1", 404, "not found"))
        head = response(f"{BASE}.git/HEAD", 200, "ref: refs/heads/main\n")
        assert baseline.confirm(head, lambda r: r.text.startswith("ref: refs/heads/"))

    def test_spa_shell_rejected_even_if_signature_matches(self) -> None:
        shell = '<html><script>window.cfg={env:"APP_KEY=",csrf:"%s"}</script></html>'
        baseline = self.baseline_from(
            (f"{BASE}shound-1", 200, shell % "AAAAAAAAAAAAAAAAAAAAAAAA"),
            (f"{BASE}shound-2.txt", 200, shell % "BBBBBBBBBBBBBBBBBBBBBBBB"),
        )
        page = response(f"{BASE}.env", 200, shell % "CCCCCCCCCCCCCCCCCCCCCCCC")
        assert not baseline.confirm(page, lambda r: "APP_KEY=" in r.text)

    def test_catch_all_page_echoing_path_rejected(self) -> None:
        baseline = self.baseline_from(
            (f"{BASE}shound-1", 200, NOT_FOUND.format(path="/shound-1", id=111)),
        )
        page = response(f"{BASE}.env", 200, NOT_FOUND.format(path="/.env", id=987654))
        assert not baseline.confirm(page, lambda r: True)

    def test_without_baseline_relies_on_signature(self) -> None:
        baseline = Baseline(BASE, [])
        env = response(f"{BASE}.env", 200, "APP_KEY=base64:abc\n")
        assert baseline.confirm(env, ENV_SIGNATURE)
