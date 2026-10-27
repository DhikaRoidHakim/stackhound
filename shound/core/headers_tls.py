"""HTTP security headers, cookie flags, CORS and version disclosure
(PRD §3.3, BACKLOG T-106). TLS (SH-04) follows in T-107.

``audit_security_headers`` and ``audit_cookies`` are pure functions over
responses that were already fetched; only ``audit_cors`` sends requests (two
GETs with a crafted ``Origin`` header).
"""

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from functools import cache
from importlib.resources import files
from urllib.parse import urlsplit

from shound.core.models import Confidence, Finding, Severity
from shound.core.redaction import redacted_evidence
from shound.core.session import HttpResponse, TargetSession

PLUGIN = "core.headers"
HSTS_MIN_MAX_AGE = 15_552_000  # 180 days
CORS_PROBE_ORIGIN = "https://shound-origin-check.invalid"

_MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
_OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
_VERSION_RE = re.compile(r"\d+\.\d+")
_MAX_AGE_RE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.IGNORECASE)
_NONCE_OR_HASH = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")


def _finding(
    check_id: str,
    title: str,
    category: str,
    severity: Severity,
    description: str,
    remediation: str,
    response: HttpResponse,
    snippets: Iterable[str],
    references: Iterable[str] = (),
) -> Finding:
    return Finding(
        id=check_id,
        title=title,
        category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        plugin=PLUGIN,
        description=description,
        evidence=[
            redacted_evidence(
                response.url,
                method=response.method,
                status_code=response.status_code,
                snippet=snippet,
            )
            for snippet in snippets
        ],
        remediation=remediation,
        references=list(references),
    )


# ------------------------------------------------------------------ SH-01 headers
def parse_csp(value: str) -> dict[str, list[str]]:
    policy: dict[str, list[str]] = {}
    for directive in value.split(";"):
        parts = directive.split()
        if parts:
            # The first occurrence of a directive wins (CSP spec).
            policy.setdefault(parts[0].lower(), [p.lower() for p in parts[1:]])
    return policy


def csp_script_weakness(policy: dict[str, list[str]]) -> str | None:
    """Why this policy does not restrict scripts, or None if it does."""
    sources = policy.get("script-src", policy.get("default-src"))
    if sources is None:
        return "tidak ada script-src maupun default-src, jadi skrip dari mana pun diizinkan"
    wildcards = [s for s in sources if s in {"*", "http:", "https:"}]
    if wildcards:
        return f"script-src mengizinkan sumber wildcard ({' '.join(wildcards)})"
    has_nonce_or_hash = any(s.startswith(_NONCE_OR_HASH) for s in sources)
    if "'unsafe-inline'" in sources and not has_nonce_or_hash:
        return "script-src memakai 'unsafe-inline' tanpa nonce atau hash"
    return None


def audit_security_headers(response: HttpResponse) -> list[Finding]:
    """SH-01 (security headers) and SH-05 (version disclosure) on one response."""
    headers = response.headers
    findings: list[Finding] = []
    csp_values = headers.get_list("content-security-policy")
    policies = [parse_csp(v) for v in csp_values]

    def missing(
        check_id: str, title: str, severity: Severity, why: str, fix: str, ref: str
    ) -> None:
        findings.append(
            _finding(
                check_id, title, "header", severity, why, fix, response,
                [f"Header {ref} tidak ada"], [f"{_MDN}{ref}", _OWASP_HEADERS],
            )
        )  # fmt: skip

    if urlsplit(response.url).scheme == "https":
        hsts = headers.get("strict-transport-security")
        if hsts is None:
            missing(
                "SH-01.HSTS",
                "Strict-Transport-Security tidak dipasang",
                Severity.MEDIUM,
                "Tanpa HSTS, browser masih mau membuka situs lewat HTTP sehingga pengguna "
                "rentan terhadap serangan downgrade/SSL stripping.",
                'Kirim "Strict-Transport-Security: max-age=31536000; includeSubDomains" '
                "dari web server atau aplikasi.",
                "Strict-Transport-Security",
            )
        else:
            match = _MAX_AGE_RE.search(hsts)
            max_age = int(match.group(1)) if match else None
            if max_age is None or max_age < HSTS_MIN_MAX_AGE:
                findings.append(
                    _finding(
                        "SH-01.HSTS",
                        "Nilai max-age HSTS terlalu pendek",
                        "header",
                        Severity.LOW,
                        f"max-age={max_age if max_age is not None else '?'} di bawah "
                        f"{HSTS_MIN_MAX_AGE} detik (180 hari).",
                        "Naikkan max-age menjadi minimal 15552000, disarankan 31536000.",
                        response,
                        [f"Strict-Transport-Security: {hsts}"],
                        [f"{_MDN}Strict-Transport-Security"],
                    )
                )

    if not policies:
        report_only = headers.get("content-security-policy-report-only") is not None
        missing(
            "SH-01.CSP",
            "Content-Security-Policy tidak dipasang",
            Severity.MEDIUM,
            "Tanpa CSP, serangan XSS dapat memuat dan menjalankan skrip dari mana saja."
            + (
                " Hanya ada CSP mode report-only, yang tidak memblokir apa pun."
                if report_only
                else ""
            ),
            "Pasang Content-Security-Policy, minimal \"default-src 'self'\", lalu longgarkan "
            "per kebutuhan dengan nonce/hash, bukan 'unsafe-inline'.",
            "Content-Security-Policy",
        )
    else:
        weaknesses = [csp_script_weakness(p) for p in policies]
        # Multiple policies are all enforced; scripts are restricted if any one does it.
        if all(weaknesses):
            findings.append(
                _finding(
                    "SH-01.CSP",
                    "Content-Security-Policy tidak membatasi skrip",
                    "header",
                    Severity.LOW,
                    f"CSP ada, tetapi {weaknesses[0]}.",
                    "Batasi script-src ke 'self' dan sumber tepercaya; ganti 'unsafe-inline' "
                    "dengan nonce atau hash.",
                    response,
                    [f"Content-Security-Policy: {v}" for v in csp_values],
                    [f"{_MDN}Content-Security-Policy/script-src"],
                )
            )  # fmt: skip

    xfo = (headers.get("x-frame-options") or "").strip().upper()
    if xfo not in {"DENY", "SAMEORIGIN"} and not any("frame-ancestors" in p for p in policies):
        missing(
            "SH-01.XFO",
            "Perlindungan clickjacking tidak dipasang",
            Severity.MEDIUM,
            "Halaman dapat dimuat di dalam iframe situs lain (clickjacking): tidak ada "
            "X-Frame-Options DENY/SAMEORIGIN maupun CSP frame-ancestors.",
            'Kirim "X-Frame-Options: DENY" (atau SAMEORIGIN), atau CSP "frame-ancestors \'none\'".',
            "X-Frame-Options",
        )

    if (headers.get("x-content-type-options") or "").strip().lower() != "nosniff":
        missing(
            "SH-01.XCTO",
            "X-Content-Type-Options: nosniff tidak dipasang",
            Severity.LOW,
            "Browser boleh menebak tipe konten (MIME sniffing), yang dapat mengubah file "
            "unggahan menjadi skrip yang dieksekusi.",
            'Kirim "X-Content-Type-Options: nosniff" di semua respons.',
            "X-Content-Type-Options",
        )

    referrer = [t.strip().lower() for t in (headers.get("referrer-policy") or "").split(",")]
    referrer = [t for t in referrer if t]
    if not referrer or referrer[-1] == "unsafe-url":
        missing(
            "SH-01.RP",
            "Referrer-Policy tidak aman",
            Severity.LOW,
            "URL lengkap (termasuk path dan query yang mungkin berisi token) dapat bocor "
            "ke situs lain lewat header Referer.",
            'Kirim "Referrer-Policy: strict-origin-when-cross-origin" atau lebih ketat.',
            "Referrer-Policy",
        )

    if headers.get("permissions-policy") is None and headers.get("feature-policy") is None:
        missing(
            "SH-01.PP",
            "Permissions-Policy tidak dipasang",
            Severity.INFO,
            "Fitur browser (kamera, mikrofon, geolokasi, dll.) tidak dibatasi secara eksplisit.",
            'Kirim misalnya "Permissions-Policy: geolocation=(), camera=(), microphone=()".',
            "Permissions-Policy",
        )

    findings.extend(_version_disclosure(response))
    return findings


# ------------------------------------------------------------------ SH-05 disclosure
_DISCLOSURE = [
    (
        "SH-05.SERVER",
        ("Server",),
        "Header Server menampilkan versi",
        "nginx: server_tokens off; Apache: ServerTokens Prod dan ServerSignature Off.",
    ),
    (
        "SH-05.POWERED-BY",
        ("X-Powered-By",),
        "Header X-Powered-By menampilkan versi",
        "PHP: expose_php = Off di php.ini; Express: app.disable('x-powered-by'); "
        "atau hapus header di web server/reverse proxy.",
    ),
    (
        "SH-05.FRAMEWORK",
        ("X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"),
        "Header framework menampilkan versi",
        'ASP.NET: <httpRuntime enableVersionHeader="false" />; hapus header '
        "X-AspNetMvc-Version/X-Generator di aplikasi atau reverse proxy.",
    ),
]


def _version_disclosure(response: HttpResponse) -> list[Finding]:
    findings = []
    for check_id, names, title, fix in _DISCLOSURE:
        shown = [
            f"{name}: {value}"
            for name in names
            for value in response.headers.get_list(name)
            if _VERSION_RE.search(value)
        ]
        if shown:
            findings.append(
                _finding(
                    check_id,
                    title,
                    "info",
                    Severity.LOW,
                    "Versi software yang terlihat dari luar memudahkan penyerang mencocokkan "
                    "CVE. Versi ini juga dipakai StackHound untuk pencarian CVE.",
                    fix,
                    response,
                    shown,
                    [_OWASP_HEADERS],
                )
            )
    return findings


# ------------------------------------------------------------------ SH-02 cookies
@dataclass(frozen=True)
class SetCookie:
    name: str
    attributes: dict[str, str]  # lower-cased names; flags map to ""

    @property
    def http_only(self) -> bool:
        return "httponly" in self.attributes

    @property
    def secure(self) -> bool:
        return "secure" in self.attributes

    @property
    def same_site(self) -> str | None:
        value = self.attributes.get("samesite")
        return value.lower() if value else None

    @property
    def deleted(self) -> bool:
        if self.attributes.get("max-age", "").strip() in {"0", "-1"}:
            return True
        expires = self.attributes.get("expires")
        if not expires:
            return False
        try:
            when = parsedate_to_datetime(expires)
        except (TypeError, ValueError):
            return False
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return when < datetime.now(timezone.utc)

    def describe(self) -> str:
        """Name and attributes only; the cookie value is never shown."""
        attrs = "; ".join(f"{k}={v}" if v else k for k, v in self.attributes.items())
        return f"Set-Cookie: {self.name}=<disembunyikan>" + (f"; {attrs}" if attrs else "")


def parse_set_cookie(header: str) -> SetCookie | None:
    first, *rest = header.split(";")
    name, sep, _ = first.partition("=")
    if not sep or not name.strip():
        return None
    attributes: dict[str, str] = {}
    for part in rest:
        key, _, value = part.strip().partition("=")
        if key:
            attributes[key.strip().lower()] = value.strip()
    return SetCookie(name.strip(), attributes)


@dataclass(frozen=True)
class _CookiePolicy:
    session_patterns: tuple[re.Pattern[str], ...]
    csrf_names: frozenset[str]

    def is_csrf(self, name: str) -> bool:
        return name.lower() in self.csrf_names

    def is_session(self, name: str) -> bool:
        return any(p.search(name) for p in self.session_patterns)


@cache
def _cookie_policy() -> _CookiePolicy:
    raw = json.loads(files("shound").joinpath("data/cookies.json").read_text(encoding="utf-8"))
    return _CookiePolicy(
        session_patterns=tuple(re.compile(p) for p in raw["session_patterns"]),
        csrf_names=frozenset(n.lower() for n in raw["csrf_names"]),
    )


def audit_cookies(responses: Iterable[HttpResponse]) -> list[Finding]:
    """SH-02 over every Set-Cookie seen; one finding per check, one evidence per cookie."""
    policy = _cookie_policy()
    seen: set[str] = set()
    no_httponly: list[tuple[HttpResponse, SetCookie]] = []
    no_secure: list[tuple[HttpResponse, SetCookie]] = []
    weak_samesite: list[tuple[HttpResponse, SetCookie]] = []

    for response in responses:
        https = urlsplit(response.url).scheme == "https"
        for header in response.headers.get_list("set-cookie"):
            cookie = parse_set_cookie(header)
            if cookie is None or cookie.deleted or cookie.name in seen:
                continue
            seen.add(cookie.name)
            csrf = policy.is_csrf(cookie.name)
            session = policy.is_session(cookie.name) and not csrf
            if not (session or csrf):
                continue
            if session and not cookie.http_only:
                no_httponly.append((response, cookie))
            if https and not cookie.secure:
                no_secure.append((response, cookie))
            if cookie.same_site in {None, "none"}:
                weak_samesite.append((response, cookie))

    findings = []
    checks = [
        (
            no_httponly,
            "SH-02.HTTPONLY",
            "Cookie session tanpa atribut HttpOnly",
            Severity.MEDIUM,
            "Cookie session dapat dibaca JavaScript, sehingga XSS dapat mencuri sesi pengguna.",
            "Set HttpOnly pada cookie session (Laravel: 'http_only' => true di config/session.php; "
            "Django: SESSION_COOKIE_HTTPONLY = True; Express: cookie: { httpOnly: true }).",
        ),
        (
            no_secure,
            "SH-02.SECURE",
            "Cookie sensitif tanpa atribut Secure",
            Severity.MEDIUM,
            "Cookie dapat terkirim lewat HTTP biasa dan disadap di jaringan.",
            "Set Secure pada cookie (Laravel: SESSION_SECURE_COOKIE=true; Django: "
            "SESSION_COOKIE_SECURE dan CSRF_COOKIE_SECURE = True; "
            "Express: cookie: { secure: true }).",
        ),
        (
            weak_samesite,
            "SH-02.SAMESITE",
            "Cookie sensitif tanpa SameSite Lax/Strict",
            Severity.LOW,
            "Tanpa SameSite=Lax/Strict, cookie ikut terkirim pada request lintas situs (CSRF).",
            "Set SameSite=Lax (atau Strict) pada cookie session dan CSRF.",
        ),
    ]
    for hits, check_id, title, severity, why, fix in checks:
        if hits:
            findings.append(
                _finding(
                    check_id,
                    title,
                    "cookie",
                    severity,
                    why,
                    fix,
                    hits[0][0],
                    [cookie.describe() for _, cookie in hits],
                    [f"{_MDN}Set-Cookie"],
                )
            )
    return findings


# ------------------------------------------------------------------ SH-03 CORS
async def audit_cors(session: TargetSession, url: str) -> list[Finding]:
    """SH-03: two GETs with a crafted Origin header; nothing else is sent."""
    findings: list[Finding] = []
    ref = [f"{_MDN}Access-Control-Allow-Origin", "https://portswigger.net/web-security/cors"]
    fix = (
        "Gunakan daftar origin yang diizinkan secara eksplisit; jangan memantulkan header "
        "Origin apa adanya dan jangan mengizinkan origin null bersama kredensial."
    )

    response = await session.get(url, headers={"Origin": CORS_PROBE_ORIGIN})
    acao = (response.headers.get("access-control-allow-origin") or "").strip()
    credentials = _allows_credentials(response)
    evidence = (
        f"Origin: {CORS_PROBE_ORIGIN} -> Access-Control-Allow-Origin: {acao or '-'}; "
        f"Access-Control-Allow-Credentials: {'true' if credentials else '-'}"
    )
    if acao == CORS_PROBE_ORIGIN:
        severity = Severity.HIGH if credentials else Severity.MEDIUM
        impact = (
            "Situs mana pun dapat membaca respons atas nama pengguna yang login, "
            "termasuk data sesi."
            if credentials
            else "Situs mana pun dapat membaca respons (tanpa cookie pengguna)."
        )
        findings.append(
            _finding(
                "SH-03.REFLECT",
                "CORS memantulkan Origin sembarang",
                "cors",
                severity,
                f"Origin palsu diterima apa adanya. {impact}",
                fix,
                response,
                [evidence],
                ref,
            )
        )
    elif acao == "*" and credentials:
        findings.append(
            _finding(
                "SH-03.WILDCARD",
                "CORS wildcard bersama Allow-Credentials",
                "cors",
                Severity.MEDIUM,
                "Access-Control-Allow-Origin: * digabung dengan Allow-Credentials: true. "
                "Browser menolak kombinasi ini, tetapi menandakan konfigurasi CORS yang keliru.",
                fix,
                response,
                [evidence],
                ref,
            )
        )

    null_response = await session.get(url, headers={"Origin": "null"})
    if (null_response.headers.get("access-control-allow-origin") or "").strip() == "null":
        null_credentials = _allows_credentials(null_response)
        findings.append(
            _finding(
                "SH-03.NULL",
                "CORS mengizinkan origin null",
                "cors",
                Severity.MEDIUM,
                "Origin null dapat dipalsukan dari iframe sandbox atau file lokal."
                + (" Kredensial juga diizinkan." if null_credentials else ""),
                fix,
                null_response,
                [
                    "Origin: null -> Access-Control-Allow-Origin: null; "
                    f"Access-Control-Allow-Credentials: {'true' if null_credentials else '-'}"
                ],
                ref,
            )
        )
    return findings


def _allows_credentials(response: HttpResponse) -> bool:
    value = response.headers.get("access-control-allow-credentials") or ""
    return value.strip().lower() == "true"
