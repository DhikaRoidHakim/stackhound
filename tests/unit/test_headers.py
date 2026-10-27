from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
import respx

from shound.config import Settings
from shound.core.headers_tls import (
    CORS_PROBE_ORIGIN,
    audit_cookies,
    audit_cors,
    audit_security_headers,
    csp_script_weakness,
    parse_csp,
    parse_set_cookie,
)
from shound.core.models import Finding, Severity
from shound.core.session import HttpResponse, TargetSession

HTTPS = "https://target.test/"
HTTP = "http://target.test/"

SECURE_HEADERS = [
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "geolocation=()"),
]


def resp(headers: list[tuple[str, str]], url: str = HTTPS, status: int = 200) -> HttpResponse:
    return HttpResponse("GET", url, status, httpx.Headers(headers), b"", False)


def by_id(findings: list[Finding]) -> dict[str, Finding]:
    return {f.id: f for f in findings}


def without(name: str) -> list[tuple[str, str]]:
    return [h for h in SECURE_HEADERS if h[0] != name]


class TestSecurityHeaders:
    def test_fully_hardened_response_has_no_findings(self) -> None:
        assert audit_security_headers(resp(SECURE_HEADERS)) == []

    def test_bare_response(self) -> None:
        found = by_id(audit_security_headers(resp([])))
        assert {k: v.severity for k, v in found.items()} == {
            "SH-01.HSTS": Severity.MEDIUM,
            "SH-01.CSP": Severity.MEDIUM,
            "SH-01.XFO": Severity.MEDIUM,
            "SH-01.XCTO": Severity.LOW,
            "SH-01.RP": Severity.LOW,
            "SH-01.PP": Severity.INFO,
        }
        assert all(f.references for f in found.values())
        assert all(f.evidence[0].url == HTTPS for f in found.values())

    def test_hsts_not_evaluated_on_http(self) -> None:
        assert "SH-01.HSTS" not in by_id(audit_security_headers(resp([], url=HTTP)))

    @pytest.mark.parametrize("value", ["max-age=86400", "includeSubDomains", 'max-age="600"'])
    def test_weak_hsts(self, value: str) -> None:
        headers = [*without("Strict-Transport-Security"), ("Strict-Transport-Security", value)]
        finding = by_id(audit_security_headers(resp(headers)))["SH-01.HSTS"]
        assert finding.severity is Severity.LOW

    def test_csp_report_only_counts_as_missing(self) -> None:
        headers = [
            *without("Content-Security-Policy"),
            ("Content-Security-Policy-Report-Only", "default-src 'self'"),
        ]
        finding = by_id(audit_security_headers(resp(headers)))["SH-01.CSP"]
        assert finding.severity is Severity.MEDIUM
        assert "report-only" in finding.description

    def test_weak_csp_is_low(self) -> None:
        headers = [
            *without("Content-Security-Policy"),
            (
                "Content-Security-Policy",
                "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
            ),
        ]
        finding = by_id(audit_security_headers(resp(headers)))["SH-01.CSP"]
        assert finding.severity is Severity.LOW
        assert "unsafe-inline" in finding.description

    def test_any_strict_policy_is_enough(self) -> None:
        headers = [
            *without("Content-Security-Policy"),
            ("Content-Security-Policy", "img-src *; frame-ancestors 'none'"),
            ("Content-Security-Policy", "script-src 'self'"),
        ]
        assert "SH-01.CSP" not in by_id(audit_security_headers(resp(headers)))

    def test_frame_ancestors_replaces_xfo(self) -> None:
        assert "SH-01.XFO" not in by_id(audit_security_headers(resp(without("X-Frame-Options"))))

    @pytest.mark.parametrize("value", ["ALLOW-FROM https://a.test", "allowall", ""])
    def test_bad_xfo_without_frame_ancestors(self, value: str) -> None:
        headers = [
            *[
                h
                for h in SECURE_HEADERS
                if h[0] not in {"X-Frame-Options", "Content-Security-Policy"}
            ],
            ("Content-Security-Policy", "default-src 'self'"),
            ("X-Frame-Options", value),
        ]
        assert "SH-01.XFO" in by_id(audit_security_headers(resp(headers)))

    @pytest.mark.parametrize(
        ("value", "flagged"),
        [
            ("unsafe-url", True),
            ("no-referrer, unsafe-url", True),
            ("unsafe-url, strict-origin-when-cross-origin", False),
            ("no-referrer", False),
        ],
    )
    def test_referrer_policy_last_token_wins(self, value: str, flagged: bool) -> None:
        headers = [*without("Referrer-Policy"), ("Referrer-Policy", value)]
        assert ("SH-01.RP" in by_id(audit_security_headers(resp(headers)))) is flagged

    def test_legacy_feature_policy_accepted(self) -> None:
        headers = [*without("Permissions-Policy"), ("Feature-Policy", "camera 'none'")]
        assert "SH-01.PP" not in by_id(audit_security_headers(resp(headers)))


class TestCsp:
    def test_parse_first_directive_wins(self) -> None:
        policy = parse_csp("default-src 'self'; script-src a.test; script-src *")
        assert policy == {"default-src": ["'self'"], "script-src": ["a.test"]}

    @pytest.mark.parametrize(
        ("policy", "weak"),
        [
            ("img-src *", True),  # no script-src/default-src
            ("default-src *", True),
            ("script-src https:", True),
            ("script-src 'self' 'unsafe-inline'", True),
            ("script-src 'self' 'unsafe-inline' 'nonce-abc'", False),
            ("script-src 'self' 'unsafe-inline' 'sha256-xyz='", False),
            ("default-src 'self'", False),
        ],
    )
    def test_script_weakness(self, policy: str, weak: bool) -> None:
        assert (csp_script_weakness(parse_csp(policy)) is not None) is weak


class TestVersionDisclosure:
    def test_versions_flagged(self) -> None:
        headers = [
            *SECURE_HEADERS,
            ("Server", "Apache/2.4.69 (Debian)"),
            ("X-Powered-By", "PHP/8.3.36"),
            ("X-AspNet-Version", "4.0.30319"),
        ]
        found = by_id(audit_security_headers(resp(headers)))
        assert set(found) == {"SH-05.SERVER", "SH-05.POWERED-BY", "SH-05.FRAMEWORK"}
        assert all(f.severity is Severity.LOW for f in found.values())
        assert found["SH-05.SERVER"].evidence[0].snippet == "Server: Apache/2.4.69 (Debian)"

    @pytest.mark.parametrize("server", ["nginx", "Apache", "cloudflare"])
    def test_no_version_no_finding(self, server: str) -> None:
        headers = [*SECURE_HEADERS, ("Server", server), ("X-Powered-By", "Express")]
        assert audit_security_headers(resp(headers)) == []


def set_cookie(value: str) -> tuple[str, str]:
    return ("Set-Cookie", value)


class TestCookies:
    def test_parse_set_cookie(self) -> None:
        cookie = parse_set_cookie("sid=abc; Path=/; HttpOnly; Secure; SameSite=Strict")
        assert cookie is not None
        assert (cookie.name, cookie.http_only, cookie.secure, cookie.same_site) == (
            "sid",
            True,
            True,
            "strict",
        )
        assert "abc" not in cookie.describe()

    def test_laravel_defaults_on_http_are_fine(self) -> None:
        response = resp(
            [
                set_cookie(
                    "XSRF-TOKEN=eyJpdiI6; expires=Tue, 27 Oct 2099 09:54:20 GMT; "
                    "path=/; samesite=lax"
                ),
                set_cookie("laravel-session=eyJpdiI6; path=/; httponly; samesite=lax"),
            ],
            url=HTTP,
        )
        assert audit_cookies([response]) == []

    def test_insecure_session_cookie_on_https(self) -> None:
        response = resp([set_cookie("PHPSESSID=s3cr3t-value; path=/")])
        found = by_id(audit_cookies([response]))
        assert set(found) == {"SH-02.HTTPONLY", "SH-02.SECURE", "SH-02.SAMESITE"}
        assert found["SH-02.HTTPONLY"].severity is Severity.MEDIUM
        assert found["SH-02.SAMESITE"].severity is Severity.LOW
        assert "s3cr3t-value" not in found["SH-02.HTTPONLY"].model_dump_json()

    def test_csrf_cookie_exempt_from_httponly_only(self) -> None:
        response = resp([set_cookie("XSRF-TOKEN=abc; path=/; samesite=none")])
        found = by_id(audit_cookies([response]))
        assert set(found) == {"SH-02.SECURE", "SH-02.SAMESITE"}

    def test_non_sensitive_cookies_ignored(self) -> None:
        response = resp([set_cookie("_ga=GA1.2.3; path=/"), set_cookie("theme=dark")])
        assert audit_cookies([response]) == []

    def test_deleted_cookies_ignored(self) -> None:
        response = resp(
            [
                set_cookie("session=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT"),
                set_cookie("auth=; Max-Age=0"),
            ]
        )
        assert audit_cookies([response]) == []

    def test_one_finding_per_check_across_cookies_and_responses(self) -> None:
        first = resp([set_cookie("sessionid=a; Secure; SameSite=Lax")])
        second = resp(
            [set_cookie("remember_web_x=b; Secure; SameSite=Lax"), set_cookie("sessionid=c")]
        )
        [finding] = audit_cookies([first, second])
        assert finding.id == "SH-02.HTTPONLY"
        assert len(finding.evidence) == 2  # sessionid counted once, from its first response


@pytest.fixture
def mock() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        yield router


@pytest.fixture
async def session() -> AsyncIterator[TargetSession]:
    async with TargetSession(Settings(rate_limit=20)) as s:
        yield s


def cors_route(mock: respx.MockRouter, allow: dict[str, dict[str, str]]) -> respx.Route:
    """Answer per Origin header with the given CORS headers."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=allow.get(request.headers.get("origin", ""), {}))

    return mock.get(HTTPS).mock(side_effect=handler)


class TestCors:
    async def test_reflection_with_credentials_is_high(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        headers = {
            "Access-Control-Allow-Origin": CORS_PROBE_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        }
        route = cors_route(mock, {CORS_PROBE_ORIGIN: headers})
        found = by_id(await audit_cors(session, HTTPS))
        assert found["SH-03.REFLECT"].severity is Severity.HIGH
        assert [c.request.headers["origin"] for c in route.calls] == [CORS_PROBE_ORIGIN, "null"]
        assert all(c.request.method == "GET" for c in route.calls)

    async def test_reflection_without_credentials_is_medium(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        cors_route(mock, {CORS_PROBE_ORIGIN: {"Access-Control-Allow-Origin": CORS_PROBE_ORIGIN}})
        found = by_id(await audit_cors(session, HTTPS))
        assert found["SH-03.REFLECT"].severity is Severity.MEDIUM

    async def test_wildcard_with_credentials(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        headers = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
        cors_route(mock, {CORS_PROBE_ORIGIN: headers})
        assert set(by_id(await audit_cors(session, HTTPS))) == {"SH-03.WILDCARD"}

    async def test_public_wildcard_is_fine(
        self, mock: respx.MockRouter, session: TargetSession
    ) -> None:
        cors_route(mock, {CORS_PROBE_ORIGIN: {"Access-Control-Allow-Origin": "*"}})
        assert await audit_cors(session, HTTPS) == []

    async def test_null_origin(self, mock: respx.MockRouter, session: TargetSession) -> None:
        cors_route(mock, {"null": {"Access-Control-Allow-Origin": "null"}})
        [finding] = await audit_cors(session, HTTPS)
        assert finding.id == "SH-03.NULL"
        assert finding.severity is Severity.MEDIUM

    async def test_allow_list_is_fine(self, mock: respx.MockRouter, session: TargetSession) -> None:
        cors_route(mock, {"https://app.target.test": {"Access-Control-Allow-Origin": "x"}})
        assert await audit_cors(session, HTTPS) == []
