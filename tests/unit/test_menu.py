import io
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from shound import __version__
from shound.config import Settings
from shound.exitcodes import ExitCode
from shound.menu import Menu
from shound.options import ScanRequest
from shound.prompts import CveSource, MenuChoice, SettingsAction
from shound.ui import load_banner, print_banner

URL = "http://127.0.0.1:8081"


class ScriptedPrompts:
    """Plays back prepared answers; a missing answer means the user cancelled."""

    def __init__(
        self,
        modes: Iterable[MenuChoice],
        *,
        confirm: bool = True,
        **answers: Iterable[Any],
    ) -> None:
        self.modes = list(modes)
        self.answers = {key: list(values) for key, values in answers.items()}
        self.confirm_answer = confirm
        self.confirmed: list[str] = []
        self.pauses = 0

    def _next(self, key: str) -> Any:
        values = self.answers.get(key, [])
        return values.pop(0) if values else None

    def select_mode(self) -> MenuChoice | None:
        return self.modes.pop(0) if self.modes else None

    def ask_url(self) -> str | None:
        value: str | None = self._next("url")
        return value

    def confirm_authorization(self, target: str) -> bool:
        self.confirmed.append(target)
        return self.confirm_answer

    def select_framework(self) -> str | None:
        value: str | None = self._next("framework")
        return value

    def select_cve_source(self) -> CveSource | None:
        value: CveSource | None = self._next("cve_source")
        return value

    def ask_component(self) -> str | None:
        value: str | None = self._next("component")
        return value

    def ask_version(self, component: str) -> str | None:
        value: str | None = self._next("version")
        return value

    def ask_lockfile_path(self) -> str | None:
        value: str | None = self._next("path")
        return value

    def select_settings_action(self) -> SettingsAction | None:
        value: SettingsAction | None = self._next("action")
        return value

    def select_setting_key(self) -> str | None:
        value: str | None = self._next("key")
        return value

    def ask_setting_value(self, key: str) -> str | None:
        value: str | None = self._next("value")
        return value

    def pause(self) -> None:
        self.pauses += 1


class Harness:
    def __init__(self, tmp_path: Path) -> None:
        self.output = io.StringIO()
        self.console = Console(file=self.output, width=200, color_system=None)
        self.config_file = tmp_path / "config.json"
        self.requests: list[ScanRequest] = []

    def execute(self, request: ScanRequest, settings: Settings, console: Console) -> ExitCode:
        self.requests.append(request)
        return ExitCode.OK

    def run(self, prompts: ScriptedPrompts) -> ExitCode:
        menu = Menu(prompts, self.console, execute=self.execute, config_file=self.config_file)
        return menu.run()

    @property
    def text(self) -> str:
        return self.output.getvalue()


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    monkeypatch.delenv("SHOUND_RATE_LIMIT", raising=False)
    return Harness(tmp_path)


class TestBanner:
    def test_banner_has_running_version(self) -> None:
        banner = load_banner()
        assert f"v{__version__}" in banner
        assert "{version}" not in banner
        assert "Framework-Based Security Configuration & CVE Auditor" in banner

    def test_print_banner_keeps_literal_brackets(self) -> None:
        out = io.StringIO()
        print_banner(Console(file=out, width=200, color_system=None))
        printed = out.getvalue()
        assert "[!] DISCLAIMER" in printed
        assert r"\__ \/ __/ __ `/ ___/" in printed


class TestMenuLoop:
    def test_shows_banner_and_exits(self, harness: Harness) -> None:
        assert harness.run(ScriptedPrompts(["exit"])) == ExitCode.OK
        assert "[!] DISCLAIMER" in harness.text
        assert "Sampai jumpa" in harness.text

    def test_cancel_exits(self, harness: Harness) -> None:
        assert harness.run(ScriptedPrompts([])) == ExitCode.OK

    def test_pause_after_each_action(self, harness: Harness) -> None:
        prompts = ScriptedPrompts(["cache", "cache", "exit"])
        harness.run(prompts)
        assert prompts.pauses == 2
        assert "T-201" in harness.text


class TestTargetModes:
    @pytest.mark.parametrize("mode", ["recon", "scan"])
    def test_runs_after_authorization(self, harness: Harness, mode: MenuChoice) -> None:
        prompts = ScriptedPrompts([mode, "exit"], url=[f"{URL}/app"])
        harness.run(prompts)
        assert prompts.confirmed == ["http://127.0.0.1:8081"]
        [request] = harness.requests
        assert request.mode == mode
        assert request.target == f"{URL}/app"
        assert request.interactive is True

    def test_authorization_asked_once_per_target(self, harness: Harness) -> None:
        prompts = ScriptedPrompts(["recon", "scan", "exit"], url=[URL, f"{URL}/other"])
        harness.run(prompts)
        assert len(prompts.confirmed) == 1
        assert len(harness.requests) == 2

    def test_declined_authorization_sends_nothing(self, harness: Harness) -> None:
        prompts = ScriptedPrompts(["scan", "exit"], url=[URL], confirm=False)
        harness.run(prompts)
        assert harness.requests == []
        assert "Dibatalkan" in harness.text

    def test_invalid_url_shows_error_and_continues(self, harness: Harness) -> None:
        prompts = ScriptedPrompts(["recon", "recon", "exit"], url=["example.com", URL])
        harness.run(prompts)
        assert "tidak valid" in harness.text
        assert len(harness.requests) == 1

    @pytest.mark.parametrize(("selected", "expected"), [("auto", None), ("laravel", "laravel")])
    def test_audit_framework(self, harness: Harness, selected: str, expected: str | None) -> None:
        harness.run(ScriptedPrompts(["audit", "exit"], url=[URL], framework=[selected]))
        assert harness.requests[0].framework == expected

    def test_cancelled_url_does_nothing(self, harness: Harness) -> None:
        prompts = ScriptedPrompts(["scan", "exit"])
        harness.run(prompts)
        assert harness.requests == []
        assert prompts.confirmed == []


class TestCveAndDeps:
    def test_cve_manual(self, harness: Harness) -> None:
        prompts = ScriptedPrompts(
            ["cve", "exit"], cve_source=["manual"], component=["Laravel"], version=["v9.52.4"]
        )
        harness.run(prompts)
        [request] = harness.requests
        assert request.versions == {"laravel": "9.52.4"}
        assert request.target is None
        assert prompts.confirmed == []

    def test_cve_from_url_needs_authorization(self, harness: Harness) -> None:
        prompts = ScriptedPrompts(["cve", "exit"], cve_source=["url"], url=[URL])
        harness.run(prompts)
        assert harness.requests[0].target == f"{URL}/"
        assert len(prompts.confirmed) == 1

    def test_deps_folder(self, harness: Harness, tmp_path: Path) -> None:
        (tmp_path / "composer.lock").write_text("{}", encoding="utf-8")
        harness.run(ScriptedPrompts(["deps", "exit"], path=[str(tmp_path)]))
        assert harness.requests[0].path == tmp_path / "composer.lock"

    def test_deps_missing_file(self, harness: Harness, tmp_path: Path) -> None:
        harness.run(ScriptedPrompts(["deps", "exit"], path=[str(tmp_path / "x.lock")]))
        assert harness.requests == []
        assert "tidak ditemukan" in harness.text


class TestSettings:
    def test_set_then_unset(self, harness: Harness) -> None:
        harness.run(
            ScriptedPrompts(
                ["settings", "settings", "settings", "exit"],
                action=["set", "set", "unset"],
                key=["rate_limit", "proxy", "rate_limit"],
                value=["3", "http://proxy:3128"],
            )
        )
        stored = json.loads(harness.config_file.read_text(encoding="utf-8"))
        assert stored == {"proxy": "http://proxy:3128"}
        assert "Konfigurasi efektif" in harness.text

    def test_invalid_value_shows_error(self, harness: Harness) -> None:
        harness.run(
            ScriptedPrompts(["settings", "exit"], action=["set"], key=["timeout"], value=["abc"])
        )
        assert "tidak valid" in harness.text
        assert not harness.config_file.exists()
