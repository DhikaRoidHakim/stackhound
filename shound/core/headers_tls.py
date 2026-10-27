"""HTTP security headers, cookie flags, CORS, TLS and version disclosure
(PRD §3.3, BACKLOG T-106/T-107).

``audit_security_headers`` and ``audit_cookies`` are pure functions over
responses that were already fetched. ``audit_cors`` sends two GETs with a crafted
``Origin`` header; ``audit_tls`` opens a few bare TLS handshakes and one plain
HTTP GET.
"""

import json
import re
import ssl
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from functools import cache
from importlib.resources import files
from urllib.parse import urlsplit, urlunsplit

from shound.core.models import Confidence, Finding, Severity
from shound.core.preflight import TLS_EXPIRY_WARNING_DAYS, PreflightResult
from shound.core.redaction import redacted_evidence
from shound.core.session import (
    REDIRECT_STATUSES,
    HttpResponse,
    TargetRequestError,
    TargetSession,
    TlsInfo,
)

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


# ------------------------------------------------------------------ SH-04 TLS
LEGACY_PROTOCOLS = (
    (ssl.TLSVersion.TLSv1, "TLS 1.0"),
    (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
)
_TLS_REFERENCE = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
)


@dataclass(frozen=True)
class TlsAudit:
    findings: list[Finding]
    notes: list[str]  # checks that could not run, shown to the user


async def audit_tls(session: TargetSession, preflight: PreflightResult) -> TlsAudit:
    """SH-04: certificate validity and expiry, legacy protocols, HTTP -> HTTPS."""
    response = preflight.response
    parts = urlsplit(response.url)
    findings: list[Finding] = []
    notes: list[str] = []

    if parts.scheme != "https":
        findings.append(
            _finding(
                "SH-04.HTTP",
                "Situs disajikan lewat HTTP tanpa redirect ke HTTPS",
                "tls",
                Severity.LOW,
                "Lalu lintas termasuk cookie dan kredensial dapat dibaca atau diubah di jaringan.",
                "Pasang sertifikat TLS (misalnya Let's Encrypt) dan arahkan semua request HTTP "
                "ke HTTPS dengan redirect 301.",
                response,
                [f"GET {response.url} -> {response.status_code}"],
                [_TLS_REFERENCE],
            )
        )
        return TlsAudit(findings, notes)

    host = parts.hostname or ""
    port = parts.port or 443
    tls = response.tls
    certificate: TlsInfo | None = tls if tls is not None and tls.verified else None

    if session.uses_proxy:
        notes.append("Cek sertifikat dan protokol TLS lama dilewati karena memakai proxy.")
    else:
        if certificate is None:  # --insecure: the request itself did not verify
            check = await session.tls_handshake(host, port, verify=True)
            if check.accepted:
                certificate = check.info
            elif check.accepted is False:
                findings.append(
                    _finding(
                        "SH-04.CERT",
                        "Sertifikat TLS tidak valid",
                        "tls",
                        Severity.HIGH,
                        f"Sertifikat gagal diverifikasi: {check.error}. Browser menampilkan "
                        "peringatan, dan pengguna yang terbiasa mengabaikannya rentan MITM.",
                        "Gunakan sertifikat dari CA tepercaya yang cocok dengan nama host dan "
                        "masih berlaku, lengkap dengan rantai intermediate-nya.",
                        response,
                        [f"{host}:{port} -> {check.error}"],
                        [_TLS_REFERENCE],
                    )
                )

        accepted: list[str] = []
        for version, label in LEGACY_PROTOCOLS:
            result = await session.tls_handshake(host, port, verify=False, version=version)
            if result.accepted:
                accepted.append(label)
            elif result.accepted is None:
                notes.append(f"{label} tidak dapat diuji: {result.error}.")
        if accepted:
            findings.append(
                _finding(
                    "SH-04.LEGACY",
                    "Server menerima protokol TLS usang",
                    "tls",
                    Severity.MEDIUM,
                    f"Server menyelesaikan handshake {' dan '.join(accepted)}, yang sudah "
                    "dinyatakan usang (RFC 8996) dan rentan terhadap serangan downgrade.",
                    "Batasi ke TLS 1.2 dan 1.3 (nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                    "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3).",
                    response,
                    [f"{host}:{port} menerima {label}" for label in accepted],
                    [_TLS_REFERENCE, "https://www.rfc-editor.org/rfc/rfc8996"],
                )
            )

    not_after = certificate.not_after if certificate is not None else None
    days = certificate.days_remaining() if certificate is not None else None
    if not_after is not None and days is not None and days < TLS_EXPIRY_WARNING_DAYS:
        findings.append(
            _finding(
                "SH-04.EXPIRY",
                "Sertifikat TLS segera kedaluwarsa",
                "tls",
                Severity.MEDIUM,
                f"Sertifikat {(certificate and certificate.subject_cn) or host} berlaku sampai "
                f"{not_after:%Y-%m-%d} ({days} hari lagi).",
                "Perpanjang sertifikat dan pastikan perpanjangan otomatis (certbot/ACME) berjalan.",
                response,
                [f"notAfter {not_after:%Y-%m-%d %H:%M} UTC"],
                [_TLS_REFERENCE],
            )
        )

    findings.extend(await _http_redirect(session, preflight, host, port, notes))
    return TlsAudit(findings, notes)


async def _http_redirect(
    session: TargetSession,
    preflight: PreflightResult,
    host: str,
    port: int,
    notes: list[str],
) -> list[Finding]:
    """Does plain HTTP on port 80 send visitors to HTTPS?"""
    if any(url.startswith("http://") for url, _ in preflight.response.history):
        return []  # the pre-flight already followed an http -> https redirect
    if port != 443:
        notes.append("Cek redirect HTTP -> HTTPS dilewati: HTTPS tidak di port standar 443.")
        return []
    netloc = f"[{host}]" if ":" in host else host
    http_url = urlunsplit(("http", netloc, "/", "", ""))
    try:
        plain = await session.get(http_url)
    except TargetRequestError:
        notes.append("Port 80 tidak merespons; tidak ada layanan HTTP biasa yang perlu diarahkan.")
        return []
    location = plain.headers.get("location", "")
    if plain.status_code in REDIRECT_STATUSES and location.lower().startswith("https://"):
        return []
    return [
        _finding(
            "SH-04.HTTP",
            "HTTP tidak diarahkan ke HTTPS",
            "tls",
            Severity.LOW,
            "Pengunjung yang membuka versi HTTP tetap dilayani tanpa enkripsi.",
            "Arahkan semua request HTTP ke HTTPS dengan redirect 301 dan pasang HSTS.",
            plain,
            [f"GET {http_url} -> {plain.status_code} {location}".rstrip()],
            [_TLS_REFERENCE],
        )
    ]
