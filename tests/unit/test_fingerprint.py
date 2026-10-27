import json
import re
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from shound.core.fingerprint import (
    LIKELY,
    STRONG,
    DetectedTechnology,
    Observation,
    SignatureDB,
    fingerprint,
    load_signatures,
)
from shound.core.models import VersionSource
from shound.core.session import HttpResponse

URL = "https://target.test/"
SESSION_VALUE = "eyJpdiI6IlNuL1JQcU5ZdHhpQ2tOS2FHM0RWWHc9PSIsInZhbHVlIjoiU0VDUkVUIn0="


def resp(
    body: str = "",
    *,
    url: str = URL,
    status: int = 200,
    headers: list[tuple[str, str]] | None = None,
) -> HttpResponse:
    return HttpResponse("GET", url, status, httpx.Headers(headers or []), body.encode(), False)


def page(**kwargs: Any) -> Observation:
    return Observation(resp(**kwargs))


def not_found(body: str, **kwargs: Any) -> Observation:
    return Observation(resp(body, url=f"{URL}shound-0001", status=404, **kwargs), not_found=True)


def cookie(name: str, value: str) -> tuple[str, str]:
    return ("Set-Cookie", f"{name}={value}; path=/; httponly; samesite=lax")


class TestSignatureDatabase:
    def test_default_database_loads(self) -> None:
        db = load_signatures()
        ids = {t.id for t in db.technologies}
        assert {"laravel", "django", "fastapi", "express", "codeigniter", "php", "nginx"} <= ids
        # Component ids must line up with the CVE mappings (PRD §5.2, §5.3).
        assert {"php", "nginx", "apache", "openssl", "iis"} <= ids

    def test_every_version_signal_declares_its_source(self) -> None:
        for tech in load_signatures().technologies:
            for signal in tech.signals:
                has_group = "(?P<version>" in (signal.pattern or "")
                assert has_group == (signal.version_source is not None), signal.id

    @pytest.mark.parametrize(
        ("signal", "message"),
        [
            ({"id": "x", "type": "cookie", "weight": 0.1}, "cookie signal needs"),
            ({"id": "x", "type": "header", "weight": 0.1}, "header name"),
            ({"id": "x", "type": "body", "weight": 0.1}, "needs a pattern"),
            (
                {"id": "x", "type": "header", "name": "Server", "on": "not_found", "weight": 0.1},
                "on=not_found",
            ),
            (
                {"id": "x", "type": "body", "pattern": "v(?P<version>\\d)", "weight": 0.1},
                "version_source",
            ),
            ({"id": "x", "type": "body", "pattern": "x", "weight": 1.5}, "less than or equal"),
        ],
    )
    def test_invalid_signal_rejected(self, signal: dict[str, Any], message: str) -> None:
        tech = {"id": "t", "name": "T", "category": "framework", "signals": [signal]}
        raw = {"schema_version": 1, "technologies": [tech]}
        with pytest.raises(ValidationError, match=re.escape(message)):
            SignatureDB.model_validate(raw)

    def test_unknown_implied_technology_rejected(self) -> None:
        tech = {"id": "t", "name": "T", "category": "framework", "implies": ["nope"]}
        raw = {"schema_version": 1, "technologies": [tech]}
        with pytest.raises(ValidationError, match="implies unknown"):
            SignatureDB.model_validate(raw)

    def test_duplicate_ids_rejected(self) -> None:
        tech = {"id": "t", "name": "T", "category": "framework"}
        with pytest.raises(ValidationError, match="duplicate technology"):
            SignatureDB.model_validate({"schema_version": 1, "technologies": [tech, tech]})

    def test_load_from_path(self, tmp_path: Any) -> None:
        path = tmp_path / "sig.json"
        path.write_text(json.dumps({"schema_version": 1, "technologies": []}), encoding="utf-8")
        assert load_signatures(path).technologies == []


class TestLaravel:
    @pytest.mark.parametrize(
        "session_name", ["laravel_session", "laravel-session", "myapp-session"]
    )
    def test_session_cookie_variants(self, session_name: str) -> None:
        result = fingerprint(
            [
                page(
                    headers=[
                        cookie("XSRF-TOKEN", SESSION_VALUE),
                        cookie(session_name, SESSION_VALUE),
                    ]
                )
            ]
        )
        laravel = result.get("laravel")
        assert laravel is not None
        assert laravel.confidence == 1.0  # 0.6 session + 0.15 xsrf + 0.3 encrypted, capped
        assert laravel.level == "strong"

    def test_cookie_value_never_in_evidence(self) -> None:
        result = fingerprint([page(headers=[cookie("laravel_session", SESSION_VALUE)])])
        dumped = result.model_dump_json()
        assert SESSION_VALUE not in dumped
        assert "eyJpdiI6..." in dumped  # only the constant prefix the signature matched

    def test_plain_xsrf_token_is_weak(self) -> None:
        result = fingerprint([page(headers=[cookie("XSRF-TOKEN", "abc123")])])
        assert result.confidence("laravel") == 0.15
        laravel = result.get("laravel")
        assert laravel is not None
        assert laravel.level == "weak"

    def test_implies_php(self) -> None:
        result = fingerprint([page(headers=[cookie("laravel_session", SESSION_VALUE)])])
        php = result.get("php")
        assert php is not None
        assert php.confidence == result.confidence("laravel")
        assert php.signals[-1].signal_id == "implied-by:laravel"

    def test_weak_detection_implies_nothing(self) -> None:
        result = fingerprint([page(body='<meta name="csrf-token" content="x">')])
        assert result.confidence("laravel") == 0.2
        assert result.get("php") is None

    def test_not_found_signal_needs_not_found_response(self) -> None:
        body = (
            '<h1 class="px-4 border-r border-gray-400 tracking-wider">404</h1><div>Not Found</div>'
        )
        assert fingerprint([page(body=body)]).get("laravel") is None
        result = fingerprint([not_found(body)])
        assert result.confidence("laravel") == 0.5
        laravel = result.get("laravel")
        assert laravel is not None
        assert laravel.signals[0].check_id == "FP-04"

    def test_signal_counted_once_across_responses(self) -> None:
        observations = [page(headers=[cookie("XSRF-TOKEN", "a")]) for _ in range(5)]
        assert fingerprint(observations).confidence("laravel") == 0.15

    def test_ignition_debug_page_versions(self) -> None:
        body = (
            '<script src="spatie/laravel-ignition"></script>'
            '{"laravel_version":"10.50.3","php_version":"8.3.36"}'
        )
        result = fingerprint([Observation(resp(body, status=405))])
        assert result.confidence("laravel") == 1.0
        [laravel] = result.versions_of("laravel")
        [php] = result.versions_of("php")
        assert (laravel.version, laravel.source) == ("10.50.3", VersionSource.ERROR_PAGE)
        assert php.version == "8.3.36"

    def test_laravel11_renderer_versions(self) -> None:
        # The version block sits inside JSON-escaped markdown: a literal backslash-n.
        body = (
            r'"markdown":"# Symfony\\Component\\...\n\nPHP 8.3.36\nLaravel 12.70.1\n127.0.0.1:8081"'
        )
        result = fingerprint([Observation(resp(body, status=405))])
        assert [v.version for v in result.versions_of("laravel")] == ["12.70.1"]
        assert [v.version for v in result.versions_of("php")] == ["8.3.36"]

    def test_version_mention_outside_debug_page_ignored(self) -> None:
        result = fingerprint([page(body="<p>Built with Laravel 12.1.0 on PHP 8.3.0</p>")])
        assert result.versions == []


class TestOtherFrameworks:
    def test_express(self) -> None:
        result = fingerprint(
            [
                page(headers=[("X-Powered-By", "Express"), cookie("connect.sid", "s%3Aabc")]),
                not_found("<pre>Cannot GET /shound-0001</pre>"),
            ]
        )
        assert result.confidence("express") == 1.0
        assert result.get("nodejs") is not None

    def test_express_404_text_on_normal_page_ignored(self) -> None:
        result = fingerprint([page(body="Docs: <pre>Cannot GET /foo</pre> means 404")])
        assert result.get("express") is None

    def test_django(self) -> None:
        body = '<form><input type="hidden" name="csrfmiddlewaretoken" value="x"></form>'
        result = fingerprint([page(body=body, headers=[cookie("csrftoken", "x")])])
        assert result.confidence("django") == 0.9
        assert result.get("python") is not None

    def test_django_debug_404(self) -> None:
        result = fingerprint([not_found("Using the URLconf defined in mysite.urls")])
        assert result.confidence("django") == 0.9

    def test_fastapi(self) -> None:
        result = fingerprint(
            [page(headers=[("Server", "uvicorn")]), not_found('{"detail":"Not Found"}')]
        )
        assert result.confidence("fastapi") == 0.8
        assert result.get("fastapi") is not None

    def test_codeigniter(self) -> None:
        result = fingerprint([page(headers=[cookie("ci_session", "abc")])])
        assert result.confidence("codeigniter") == 0.6

    def test_wordpress_meta_generator(self) -> None:
        body = '<meta name="generator" content="WordPress 6.4.2" /><link href="/wp-content/x.css">'
        result = fingerprint([page(body=body)])
        assert result.confidence("wordpress") == 1.0
        [version] = result.versions_of("wordpress")
        assert (version.version, version.source) == ("6.4.2", VersionSource.HTML_META)


class TestServerVersions:
    def test_apache_openssl_with_distro(self) -> None:
        server = "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f"
        result = fingerprint([page(headers=[("Server", server)])])
        versions = {v.component: v for v in result.versions}
        assert versions["apache"].version == "2.4.41"
        assert versions["openssl"].version == "1.1.1f"
        assert versions["apache"].distro == "Ubuntu"
        assert versions["apache"].backport_risk

    def test_php_distro_suffix(self) -> None:
        result = fingerprint([page(headers=[("X-Powered-By", "PHP/7.4.3-4ubuntu2.20")])])
        [php] = result.versions_of("php")
        assert php.version == "7.4.3"
        assert php.distro == "ubuntu"

    def test_php_not_tainted_by_server_distro(self) -> None:
        headers = [("Server", "Apache/2.4.69 (Debian)"), ("X-Powered-By", "PHP/8.3.36")]
        result = fingerprint([page(headers=headers)])
        [php] = result.versions_of("php")
        assert php.distro is None
        [apache] = result.versions_of("apache")
        assert apache.distro == "Debian"

    def test_server_without_version(self) -> None:
        result = fingerprint([page(headers=[("Server", "nginx")])])
        assert result.confidence("nginx") == 0.9
        assert result.versions == []

    def test_aspnet_and_iis(self) -> None:
        headers = [
            ("Server", "Microsoft-IIS/10.0"),
            ("X-AspNet-Version", "4.0.30319"),
            ("X-Powered-By", "ASP.NET"),
        ]
        result = fingerprint([page(headers=headers)])
        assert {v.component: v.version for v in result.versions} == {
            "iis": "10.0",
            "aspnet": "4.0.30319",
        }


class TestResultShape:
    def test_empty(self) -> None:
        result = fingerprint([page(body="hello")])
        assert result.technologies == []
        assert result.versions == []
        assert result.confidence("laravel") == 0.0

    def test_sorted_and_frameworks(self) -> None:
        result = fingerprint(
            [
                page(
                    headers=[
                        ("Server", "nginx"),
                        cookie("csrftoken", "x"),
                        cookie("XSRF-TOKEN", "a"),
                    ]
                )
            ]
        )
        confidences = [t.confidence for t in result.technologies]
        assert confidences == sorted(confidences, reverse=True)
        assert [t.id for t in result.frameworks()] == ["django", "laravel"]

    @pytest.mark.parametrize(
        ("confidence", "level"),
        [(1.0, "strong"), (STRONG, "strong"), (0.79, "likely"), (LIKELY, "likely"), (0.39, "weak")],
    )
    def test_levels(self, confidence: float, level: str) -> None:
        tech = DetectedTechnology(id="x", name="X", category="framework", confidence=confidence)
        assert tech.level == level
