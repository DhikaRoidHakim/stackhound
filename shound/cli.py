"""Command line entry point (PRD §2.2, BACKLOG T-101).

Kept thin: every command validates its input through ``shound.options``, passes
the authorization gate, then hands a ``ScanRequest`` to ``shound.runner``.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape

from shound import __version__, runner
from shound import config as cfg
from shound.authorization import AuthorizationGate
from shound.exitcodes import ExitCode
from shound.menu import Menu
from shound.options import (
    FRAMEWORKS,
    FailOn,
    PreflightError,
    ScanRequest,
    UsageError,
    normalize_target_url,
    parse_component,
    parse_component_versions,
    parse_framework,
    parse_outputs,
    parse_version,
    resolve_lockfile,
)
from shound.prompts import QuestionaryPrompts, is_interactive_terminal
from shound.ui import settings_table

app = typer.Typer(
    name="shound",
    help="StackHound - Framework-Based Security Configuration & CVE Auditor.",
    no_args_is_help=False,
    add_completion=False,
)
config_app = typer.Typer(help="Kelola konfigurasi (API key NVD, timeout, proxy, ...).")
cache_app = typer.Typer(help="Kelola cache CVE.")
app.add_typer(config_app, name="config")
app.add_typer(cache_app, name="cache")

console = Console()
err_console = Console(stderr=True)
gate = AuthorizationGate()

# ------------------------------------------------------------------ option types
UrlArg = Annotated[str, typer.Argument(help="URL target, misalnya https://staging.example.com")]
OutputOpt = Annotated[
    list[Path] | None,
    typer.Option("--output", "-o", help="File laporan (.json, .md, .html). Dapat diulang."),
]
FailOnOpt = Annotated[
    FailOn | None,
    typer.Option(
        "--fail-on", case_sensitive=False, help="Exit code 1 jika ada temuan ≥ severity ini."
    ),
]
NonInteractiveOpt = Annotated[
    bool,
    typer.Option("--non-interactive", help="Tanpa prompt (otomatis jika stdin bukan terminal)."),
]
AuthorizedOpt = Annotated[
    bool,
    typer.Option("--authorized", help="Pernyataan memiliki izin audit; wajib tanpa terminal."),
]
VersionsOpt = Annotated[
    list[str] | None,
    typer.Option(
        "--version",
        metavar="KOMPONEN=VERSI",
        help="Versi komponen yang disembunyikan server, misal laravel=9.52.4. Dapat diulang.",
    ),
]
FrameworkOpt = Annotated[
    str | None,
    typer.Option("--framework", help=f"Paksa plugin framework: {', '.join(FRAMEWORKS)}."),
]
RateLimitOpt = Annotated[
    float | None,
    typer.Option("--rate-limit", help="Maks. request/detik ke target (default 5, maks. 20)."),
]
TimeoutOpt = Annotated[
    float | None, typer.Option("--timeout", help="Timeout per request dalam detik.")
]
ProxyOpt = Annotated[str | None, typer.Option("--proxy", help="URL proxy HTTP/SOCKS.")]
InsecureOpt = Annotated[
    bool,
    typer.Option("--insecure", help="Nonaktifkan verifikasi sertifikat TLS (dicatat di laporan)."),
]
UserAgentOpt = Annotated[
    str | None,
    typer.Option("--user-agent", help="User-Agent kustom; header X-Security-Audit tetap dikirim."),
]
NoMethodProbeOpt = Annotated[
    bool, typer.Option("--no-method-probe", help="Matikan probe PATCH untuk deteksi debug mode.")
]
NoCacheOpt = Annotated[bool, typer.Option("--no-cache", help="Jangan baca/tulis cache CVE.")]
RefreshOpt = Annotated[
    bool, typer.Option("--refresh", help="Ambil ulang data CVE lalu perbarui cache.")
]
VerboseOpt = Annotated[
    bool, typer.Option("--verbose", "-v", help="Log detail request (tanpa body).")
]


def _stdin_is_tty() -> bool:
    return is_interactive_terminal()


def _fail(message: str, code: ExitCode) -> NoReturn:
    err_console.print(f"[red]Error:[/red] {escape(message)}")
    raise typer.Exit(int(code))


def _check_cache_flags(no_cache: bool, refresh: bool) -> None:
    if no_cache and refresh:
        raise UsageError("--no-cache dan --refresh tidak bisa dipakai bersamaan.")


def _authorize(target: str, *, authorized: bool, interactive: bool) -> None:
    confirm = QuestionaryPrompts().confirm_authorization
    if gate.ensure(target, authorized_flag=authorized, interactive=interactive, confirm=confirm):
        return
    if interactive:
        raise UsageError("Dibatalkan: izin audit untuk target ini tidak dikonfirmasi.")
    raise UsageError(
        "Mode non-interaktif membutuhkan --authorized untuk memindai target URL "
        "(pernyataan bahwa Anda memiliki izin audit atas target tersebut)."
    )


def _execute(
    build: Callable[[bool], ScanRequest],
    *,
    non_interactive: bool,
    authorized: bool = False,
    overrides: dict[str, Any] | None = None,
) -> NoReturn:
    interactive = not non_interactive and _stdin_is_tty()
    try:
        request = build(interactive)
        settings = cfg.load_settings(overrides)
        if request.target is not None:
            _authorize(request.target, authorized=authorized, interactive=interactive)
        code = runner.execute(request, settings, console)
    except (UsageError, cfg.ConfigError) as exc:
        _fail(str(exc), ExitCode.USAGE)
    except PreflightError as exc:
        _fail(str(exc), ExitCode.PREFLIGHT)
    raise typer.Exit(int(code))


def _network_overrides(
    rate_limit: float | None = None,
    timeout: float | None = None,
    proxy: str | None = None,
    user_agent: str | None = None,
) -> dict[str, Any]:
    return {"rate_limit": rate_limit, "timeout": timeout, "proxy": proxy, "user_agent": user_agent}


# ------------------------------------------------------------------ root
def _print_version(value: bool) -> None:
    if value:
        console.print(f"StackHound {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version", help="Tampilkan versi lalu keluar.", callback=_print_version, is_eager=True
        ),
    ] = False,
) -> None:
    """StackHound - audit konfigurasi keamanan & CVE secara non-intrusive.

    Tanpa subcommand, membuka menu interaktif.
    """
    if ctx.invoked_subcommand is not None:
        return
    if not _stdin_is_tty():
        _fail(
            "Menu interaktif membutuhkan console terminal (PowerShell, cmd, Windows Terminal; "
            "di Git Bash gunakan `winpty shound`). Atau gunakan subcommand; lihat `shound --help`.",
            ExitCode.USAGE,
        )
    raise typer.Exit(int(Menu(QuestionaryPrompts(), console, gate=gate).run()))


# ------------------------------------------------------------------ scan commands
@app.command()
def recon(
    url: UrlArg,
    output: OutputOpt = None,
    fail_on: FailOnOpt = None,
    non_interactive: NonInteractiveOpt = False,
    authorized: AuthorizedOpt = False,
    versions: VersionsOpt = None,
    rate_limit: RateLimitOpt = None,
    timeout: TimeoutOpt = None,
    proxy: ProxyOpt = None,
    insecure: InsecureOpt = False,
    user_agent: UserAgentOpt = None,
    verbose: VerboseOpt = False,
) -> None:
    """[1] Quick recon: fingerprint, security header & TLS."""

    def build(interactive: bool) -> ScanRequest:
        return ScanRequest(
            mode="recon",
            interactive=interactive,
            target=normalize_target_url(url),
            versions=parse_component_versions(versions),
            outputs=parse_outputs(output),
            fail_on=fail_on,
            insecure=insecure,
            verbose=verbose,
        )

    _execute(
        build,
        non_interactive=non_interactive,
        authorized=authorized,
        overrides=_network_overrides(rate_limit, timeout, proxy, user_agent),
    )


@app.command()
def audit(
    url: UrlArg,
    framework: FrameworkOpt = None,
    output: OutputOpt = None,
    fail_on: FailOnOpt = None,
    non_interactive: NonInteractiveOpt = False,
    authorized: AuthorizedOpt = False,
    versions: VersionsOpt = None,
    rate_limit: RateLimitOpt = None,
    timeout: TimeoutOpt = None,
    proxy: ProxyOpt = None,
    insecure: InsecureOpt = False,
    user_agent: UserAgentOpt = None,
    no_method_probe: NoMethodProbeOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """[2] Audit misconfiguration spesifik framework."""

    def build(interactive: bool) -> ScanRequest:
        return ScanRequest(
            mode="audit",
            interactive=interactive,
            target=normalize_target_url(url),
            framework=parse_framework(framework),
            versions=parse_component_versions(versions),
            outputs=parse_outputs(output),
            fail_on=fail_on,
            insecure=insecure,
            method_probe=not no_method_probe,
            verbose=verbose,
        )

    _execute(
        build,
        non_interactive=non_interactive,
        authorized=authorized,
        overrides=_network_overrides(rate_limit, timeout, proxy, user_agent),
    )


@app.command()
def cve(
    url: Annotated[
        str | None, typer.Argument(help="URL target untuk deteksi versi otomatis.")
    ] = None,
    component: Annotated[
        str | None, typer.Option("--component", help="Komponen untuk input manual, misal laravel.")
    ] = None,
    versions: Annotated[
        list[str] | None,
        typer.Option(
            "--version",
            help="Dengan --component: versinya (9.52.4). "
            "Dengan URL: KOMPONEN=VERSI (dapat diulang).",
        ),
    ] = None,
    output: OutputOpt = None,
    fail_on: FailOnOpt = None,
    non_interactive: NonInteractiveOpt = False,
    authorized: AuthorizedOpt = False,
    no_cache: NoCacheOpt = False,
    refresh: RefreshOpt = False,
    rate_limit: RateLimitOpt = None,
    timeout: TimeoutOpt = None,
    proxy: ProxyOpt = None,
    insecure: InsecureOpt = False,
    user_agent: UserAgentOpt = None,
    verbose: VerboseOpt = False,
) -> None:
    """[3] Lookup CVE dari target URL atau dari komponen & versi manual."""

    def build(interactive: bool) -> ScanRequest:
        _check_cache_flags(no_cache, refresh)
        common: dict[str, Any] = {
            "mode": "cve",
            "interactive": interactive,
            "outputs": parse_outputs(output),
            "fail_on": fail_on,
            "insecure": insecure,
            "use_cache": not no_cache,
            "refresh_cache": refresh,
            "verbose": verbose,
        }
        if component is not None:
            if url is not None:
                raise UsageError("Gunakan URL target ATAU --component, tidak keduanya.")
            if not versions or len(versions) != 1:
                raise UsageError(
                    "--component membutuhkan tepat satu --version, misal --version 9.52.4."
                )
            return ScanRequest(
                versions={parse_component(component): parse_version(versions[0])}, **common
            )
        if url is None:
            raise UsageError(
                "Berikan URL target, atau --component dan --version untuk input manual."
            )
        return ScanRequest(
            target=normalize_target_url(url), versions=parse_component_versions(versions), **common
        )

    _execute(
        build,
        non_interactive=non_interactive,
        authorized=authorized,
        overrides=_network_overrides(rate_limit, timeout, proxy, user_agent),
    )


@app.command()
def deps(
    path: Annotated[Path, typer.Argument(help="Lock file atau folder proyek.")],
    output: OutputOpt = None,
    fail_on: FailOnOpt = None,
    non_interactive: NonInteractiveOpt = False,
    no_cache: NoCacheOpt = False,
    refresh: RefreshOpt = False,
    timeout: TimeoutOpt = None,
    proxy: ProxyOpt = None,
    verbose: VerboseOpt = False,
) -> None:
    """[4] Audit dependency lokal (composer.lock, package-lock.json, requirements.txt)."""

    def build(interactive: bool) -> ScanRequest:
        _check_cache_flags(no_cache, refresh)
        return ScanRequest(
            mode="deps",
            interactive=interactive,
            path=resolve_lockfile(path),
            outputs=parse_outputs(output),
            fail_on=fail_on,
            use_cache=not no_cache,
            refresh_cache=refresh,
            verbose=verbose,
        )

    _execute(
        build,
        non_interactive=non_interactive,
        overrides=_network_overrides(timeout=timeout, proxy=proxy),
    )


@app.command()
def scan(
    url: UrlArg,
    framework: FrameworkOpt = None,
    output: OutputOpt = None,
    fail_on: FailOnOpt = None,
    non_interactive: NonInteractiveOpt = False,
    authorized: AuthorizedOpt = False,
    versions: VersionsOpt = None,
    rate_limit: RateLimitOpt = None,
    timeout: TimeoutOpt = None,
    proxy: ProxyOpt = None,
    insecure: InsecureOpt = False,
    user_agent: UserAgentOpt = None,
    no_method_probe: NoMethodProbeOpt = False,
    no_cache: NoCacheOpt = False,
    refresh: RefreshOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """[5] Full scan: recon, audit framework, CVE, lalu laporan."""

    def build(interactive: bool) -> ScanRequest:
        _check_cache_flags(no_cache, refresh)
        return ScanRequest(
            mode="scan",
            interactive=interactive,
            target=normalize_target_url(url),
            framework=parse_framework(framework),
            versions=parse_component_versions(versions),
            outputs=parse_outputs(output),
            fail_on=fail_on,
            insecure=insecure,
            method_probe=not no_method_probe,
            use_cache=not no_cache,
            refresh_cache=refresh,
            verbose=verbose,
        )

    _execute(
        build,
        non_interactive=non_interactive,
        authorized=authorized,
        overrides=_network_overrides(rate_limit, timeout, proxy, user_agent),
    )


# ------------------------------------------------------------------ config & cache
@config_app.command("show")
def config_show() -> None:
    """Tampilkan konfigurasi efektif (API key dimask)."""
    try:
        settings = cfg.load_settings()
    except cfg.ConfigError as exc:
        _fail(str(exc), ExitCode.USAGE)
    console.print(settings_table(settings))
    console.print(f"File konfigurasi: {escape(str(cfg.config_path()))}")


@config_app.command("set")
def config_set(
    key: Annotated[str, typer.Argument(help=f"Salah satu: {', '.join(cfg.CONFIG_KEYS)}.")],
    value: Annotated[str, typer.Argument(help="Nilai baru.")],
) -> None:
    """Simpan satu nilai ke file konfigurasi."""
    try:
        cfg.set_config_value(key, value)
    except cfg.ConfigError as exc:
        _fail(str(exc), ExitCode.USAGE)
    console.print(f"[green]{escape(key)} disimpan.[/green]")


@config_app.command("unset")
def config_unset(
    key: Annotated[str, typer.Argument(help=f"Salah satu: {', '.join(cfg.CONFIG_KEYS)}.")],
) -> None:
    """Hapus nilai dari file konfigurasi (kembali ke default)."""
    try:
        cfg.unset_config_value(key)
    except cfg.ConfigError as exc:
        _fail(str(exc), ExitCode.USAGE)
    console.print(f"[green]{escape(key)} dikembalikan ke default.[/green]")


@cache_app.command("stats")
def cache_stats() -> None:
    """Statistik cache CVE."""
    _fail("Kelola cache belum tersedia (BACKLOG T-201).", ExitCode.USAGE)


@cache_app.command("clear")
def cache_clear() -> None:
    """Kosongkan cache CVE."""
    _fail("Kelola cache belum tersedia (BACKLOG T-201).", ExitCode.USAGE)
