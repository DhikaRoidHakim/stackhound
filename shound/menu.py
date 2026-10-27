"""Interactive menu (PRD §2.1, BACKLOG T-102).

The menu only collects answers; validation and execution go through the same
``options`` / ``authorization`` / ``runner`` functions the CLI uses.
"""

from collections.abc import Callable
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from shound.authorization import AuthorizationGate
from shound.config import ConfigError, Settings, load_settings, set_config_value, unset_config_value
from shound.exitcodes import ExitCode
from shound.options import (
    Mode,
    PreflightError,
    ScanRequest,
    UsageError,
    normalize_target_url,
    parse_component,
    parse_framework,
    parse_version,
    resolve_lockfile,
)
from shound.prompts import MenuChoice, Prompts
from shound.runner import execute as run_request
from shound.ui import print_banner, settings_table

Executor = Callable[[ScanRequest, Settings, Console], ExitCode]


class Menu:
    def __init__(
        self,
        prompts: Prompts,
        console: Console,
        *,
        gate: AuthorizationGate | None = None,
        execute: Executor = run_request,
        config_file: Path | None = None,
    ) -> None:
        self._prompts = prompts
        self._console = console
        self._gate = gate or AuthorizationGate()
        self._execute = execute
        self._config_file = config_file

    def run(self) -> ExitCode:
        print_banner(self._console)
        while True:
            choice = self._prompts.select_mode()
            if choice is None or choice == "exit":
                self._console.print("Sampai jumpa.")
                return ExitCode.OK
            try:
                self._handle(choice)
            except (UsageError, PreflightError, ConfigError) as exc:
                self._console.print(f"[red]Error:[/red] {escape(str(exc))}")
            self._prompts.pause()

    def _handle(self, choice: MenuChoice) -> None:
        if choice == "settings":
            self._settings()
        elif choice == "cache":
            self._console.print("[yellow]Kelola cache belum tersedia[/yellow] (BACKLOG T-201).")
        elif choice == "deps":
            self._deps()
        elif choice == "cve":
            self._cve()
        elif choice == "recon" or choice == "audit" or choice == "scan":
            self._target_scan(choice)

    def _target_scan(self, mode: Mode) -> None:
        raw_url = self._prompts.ask_url()
        if raw_url is None:
            return
        target = normalize_target_url(raw_url)
        framework = None
        if mode == "audit":
            selected = self._prompts.select_framework()
            if selected is None:
                return
            framework = None if selected == "auto" else parse_framework(selected)
        self._run_on_target(
            ScanRequest(mode=mode, interactive=True, target=target, framework=framework)
        )

    def _cve(self) -> None:
        source = self._prompts.select_cve_source()
        if source is None:
            return
        if source == "url":
            raw_url = self._prompts.ask_url()
            if raw_url is not None:
                target = normalize_target_url(raw_url)
                self._run_on_target(ScanRequest(mode="cve", interactive=True, target=target))
            return
        raw_component = self._prompts.ask_component()
        if raw_component is None:
            return
        component = parse_component(raw_component)
        raw_version = self._prompts.ask_version(component)
        if raw_version is None:
            return
        versions = {component: parse_version(raw_version)}
        self._run(ScanRequest(mode="cve", interactive=True, versions=versions))

    def _deps(self) -> None:
        raw_path = self._prompts.ask_lockfile_path()
        if raw_path is None:
            return
        path = resolve_lockfile(Path(raw_path.strip()).expanduser())
        self._run(ScanRequest(mode="deps", interactive=True, path=path))

    def _run_on_target(self, request: ScanRequest) -> None:
        assert request.target is not None
        if not self._gate.ensure(
            request.target,
            authorized_flag=False,
            interactive=True,
            confirm=self._prompts.confirm_authorization,
        ):
            self._console.print("[yellow]Dibatalkan:[/yellow] izin audit tidak dikonfirmasi.")
            return
        self._run(request)

    def _run(self, request: ScanRequest) -> None:
        self._execute(request, load_settings(path=self._config_file), self._console)

    def _settings(self) -> None:
        self._console.print(settings_table(load_settings(path=self._config_file)))
        self._console.print("[dim]Termasuk nilai dari environment variable SHOUND_*.[/dim]")
        action = self._prompts.select_settings_action()
        if action is None:
            return
        key = self._prompts.select_setting_key()
        if key is None:
            return
        if action == "unset":
            unset_config_value(key, path=self._config_file)
            self._console.print(f"[green]{key} dikembalikan ke default.[/green]")
            return
        value = self._prompts.ask_setting_value(key)
        if value is None:
            return
        set_config_value(key, value, path=self._config_file)
        self._console.print(f"[green]{key} disimpan.[/green]")
