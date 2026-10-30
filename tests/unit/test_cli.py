import json
from pathlib import Path

import httpx
import pytest
import respx
from rich.console import Console
from typer.testing import CliRunner, Result

from shound import __version__, cli, runner
from shound import config as cfg
from shound.authorization import AuthorizationGate
from shound.config import Settings
from shound.exitcodes import ExitCode
from shound.options import FailOn, ScanRequest
from shound.prompts import QuestionaryPrompts

TARGET = "http://127.0.0.1:8081"
NVD_KEY = "11111111-2222-3333-4444-555555555555"


@pytest.fixture(autouse=True)
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cfg, "config_path", lambda: tmp_path / "shound" / "config.json")
    for var in cfg.ENV_VARS.values():
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(cli, "gate", AuthorizationGate())
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: False)


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[ScanRequest, Settings]]:
    recorded: list[tuple[ScanRequest, Settings]] = []

    def fake_execute(request: ScanRequest, settings: Settings, console: Console) -> ExitCode:
        recorded.append((request, settings))
        return ExitCode.OK

    monkeypatch.setattr(runner, "execute", fake_execute)
    return recorded


def invoke(*args: str) -> Result:
    return CliRunner().invoke(cli.app, list(args))


def text(result: Result) -> str:
    """Output with Rich line wrapping collapsed."""
    return " ".join(result.output.split())


class TestRoot:
    def test_help_lists_all_commands(self) -> None:
        result = invoke("--help")
        assert result.exit_code == 0
        for command in ("recon", "audit", "cve", "deps", "scan", "config", "cache"):
            assert command in result.output

    def test_version(self) -> None:
        result = invoke("--version")
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_no_args_without_terminal(self) -> None:
        result = invoke()
        assert result.exit_code == ExitCode.USAGE
        assert "membutuhkan console terminal" in text(result)

    def test_no_args_with_terminal_opens_menu(self, monkeypatch: pytest.MonkeyPatch) -> None:
        opened: list[bool] = []

        class FakeMenu:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def run(self) -> ExitCode:
                opened.append(True)
                return ExitCode.OK

        monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
        monkeypatch.setattr(cli, "Menu", FakeMenu)
        result = invoke()
        assert result.exit_code == 0
        assert opened == [True]


class TestAuthorization:
    @pytest.mark.parametrize("command", ["recon", "audit", "scan", "cve"])
    def test_non_interactive_requires_authorized(
        self, command: str, calls: list[tuple[ScanRequest, Settings]]
    ) -> None:
        result = invoke(command, TARGET)
        assert result.exit_code == ExitCode.USAGE
        assert "--authorized" in text(result)
        assert calls == []

    def test_authorized_flag_passes(self, calls: list[tuple[ScanRequest, Settings]]) -> None:
        result = invoke("recon", TARGET, "--authorized")
        assert result.exit_code == 0
        assert calls[0][0].target == f"{TARGET}/"

    @pytest.mark.parametrize(("answer", "exit_code"), [(True, 0), (False, ExitCode.USAGE)])
    def test_interactive_prompt(
        self,
        monkeypatch: pytest.MonkeyPatch,
        calls: list[tuple[ScanRequest, Settings]],
        answer: bool,
        exit_code: int,
    ) -> None:
        asked: list[str] = []

        def confirm(self: QuestionaryPrompts, target: str) -> bool:
            asked.append(target)
            return answer

        monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
        monkeypatch.setattr(QuestionaryPrompts, "confirm_authorization", confirm)
        result = invoke("scan", TARGET)
        assert result.exit_code == exit_code
        assert asked == ["http://127.0.0.1:8081"]
        assert len(calls) == (1 if answer else 0)

    def test_non_interactive_flag_overrides_terminal(
        self, monkeypatch: pytest.MonkeyPatch, calls: list[tuple[ScanRequest, Settings]]
    ) -> None:
        monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
        result = invoke("scan", TARGET, "--non-interactive")
        assert result.exit_code == ExitCode.USAGE
        assert calls == []

    @pytest.mark.parametrize(
        "args", [["deps", "composer.lock"], ["cve", "--component", "laravel", "--version", "9.0"]]
    )
    def test_local_modes_need_no_authorization(
        self,
        args: list[str],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        calls: list[tuple[ScanRequest, Settings]],
    ) -> None:
        (tmp_path / "composer.lock").write_text("{}", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        result = invoke(*args)
        assert result.exit_code == 0, result.output
        assert calls[0][0].target is None


class TestRequestBuilding:
    def test_scan_options_reach_request_and_settings(
        self, calls: list[tuple[ScanRequest, Settings]]
    ) -> None:
        result = invoke(
            "scan",
            "HTTP://127.0.0.1:8081/app",
            "--authorized",
            "--framework", "Laravel",
            "--version", "laravel=v10.48.1",
            "--version", "php=8.1.2",
            "-o", "report.json",
            "-o", "report.html",
            "--fail-on", "HIGH",
            "--rate-limit", "2",
            "--timeout", "30",
            "--user-agent", "Audit/1.0",
            "--insecure",
            "--no-method-probe",
            "--refresh",
        )  # fmt: skip
        assert result.exit_code == 0, result.output
        request, settings = calls[0]
        assert request.mode == "scan"
        assert request.target == "http://127.0.0.1:8081/app"
        assert request.framework == "laravel"
        assert request.versions == {"laravel": "10.48.1", "php": "8.1.2"}
        assert request.outputs == (Path("report.json"), Path("report.html"))
        assert request.fail_on is FailOn.HIGH
        assert request.insecure is True
        assert request.method_probe is False
        assert request.refresh_cache is True
        assert request.interactive is False
        assert (settings.rate_limit, settings.timeout, settings.user_agent) == (2, 30, "Audit/1.0")

    def test_cve_manual(self, calls: list[tuple[ScanRequest, Settings]]) -> None:
        result = invoke("cve", "--component", "Laravel", "--version", "v9.52.4")
        assert result.exit_code == 0
        assert calls[0][0].versions == {"laravel": "9.52.4"}

    def test_cve_from_url(self, calls: list[tuple[ScanRequest, Settings]]) -> None:
        result = invoke("cve", TARGET, "--authorized", "--version", "laravel=9.52.4")
        assert result.exit_code == 0
        assert calls[0][0].target == f"{TARGET}/"
        assert calls[0][0].versions == {"laravel": "9.52.4"}

    def test_deps_folder(self, tmp_path: Path, calls: list[tuple[ScanRequest, Settings]]) -> None:
        (tmp_path / "requirements.txt").write_text("django==4.2\n", encoding="utf-8")
        result = invoke("deps", str(tmp_path), "--no-cache")
        assert result.exit_code == 0
        assert calls[0][0].path == tmp_path / "requirements.txt"
        assert calls[0][0].use_cache is False

    def test_env_config_used(
        self, monkeypatch: pytest.MonkeyPatch, calls: list[tuple[ScanRequest, Settings]]
    ) -> None:
        monkeypatch.setenv("SHOUND_RATE_LIMIT", "3")
        invoke("recon", TARGET, "--authorized")
        assert calls[0][1].rate_limit == 3


class TestUsageErrors:
    @pytest.mark.parametrize(
        ("args", "message"),
        [
            (["scan", "example.com", "--authorized"], "tidak valid"),
            (["scan", TARGET, "--authorized", "--version", "laravel"], "komponen=versi"),
            (["scan", TARGET, "--authorized", "-o", "r.pdf"], "Format laporan"),
            (["scan", TARGET, "--authorized", "--framework", "rails"], "Framework tidak dikenal"),
            (["scan", TARGET, "--authorized", "--rate-limit", "50"], "tidak valid"),
            (["scan", TARGET, "--authorized", "--no-cache", "--refresh"], "bersamaan"),
            (["cve"], "Berikan URL target"),
            (["cve", TARGET, "--component", "laravel", "--version", "1.0"], "tidak keduanya"),
            (["cve", "--component", "laravel"], "tepat satu --version"),
        ],
    )
    def test_exit_2_with_message(
        self, args: list[str], message: str, calls: list[tuple[ScanRequest, Settings]]
    ) -> None:
        result = invoke(*args)
        assert result.exit_code == ExitCode.USAGE
        assert message in text(result)
        assert calls == []

    def test_missing_lockfile_is_preflight_error(
        self, tmp_path: Path, calls: list[tuple[ScanRequest, Settings]]
    ) -> None:
        result = invoke("deps", str(tmp_path / "composer.lock"))
        assert result.exit_code == ExitCode.PREFLIGHT
        assert "tidak ditemukan" in text(result)

    def test_invalid_fail_on_rejected_by_parser(self) -> None:
        result = invoke("scan", TARGET, "--authorized", "--fail-on", "severe")
        assert result.exit_code == ExitCode.USAGE


class TestRealRunner:
    """CLI -> runner -> pre-flight + baseline, with the target mocked by respx."""

    @staticmethod
    def mock_site(mock: respx.MockRouter) -> tuple[respx.Route, respx.Route]:
        home = mock.get(f"{TARGET}/").respond(200, text="home")
        probes = mock.get(url__regex=rf"{TARGET}/shound-[0-9a-f]+").respond(404)
        return home, probes

    def test_recon_runs_to_a_grade(self) -> None:
        with respx.mock(assert_all_called=False) as mock:
            home, probes = self.mock_site(mock)
            result = invoke("recon", TARGET, "--authorized")
        assert result.exit_code == ExitCode.OK  # findings, but no --fail-on
        out = text(result)
        assert "Pre-flight" in out
        assert "Soft-404 tidak" in out
        assert "SH-01.CSP" in out
        # CSP + XFO (MEDIUM 8 each), XCTO + RP + SH-04.HTTP (LOW 3 each): 100 - 25
        assert "Security Grade: C skor 75/100" in out
        assert "belum" not in out
        # Landing page: pre-flight GET, then the two SH-03 CORS probes.
        origins = [call.request.headers.get("origin") for call in home.calls]
        assert origins == [None, "https://shound-origin-check.invalid", "null"]
        assert probes.call_count == 2

    @pytest.mark.parametrize(("fail_on", "code"), [("medium", 1), ("high", 0)])
    def test_fail_on(self, fail_on: str, code: int) -> None:
        with respx.mock(assert_all_called=False) as mock:
            self.mock_site(mock)
            result = invoke("recon", TARGET, "--authorized", "--fail-on", fail_on)
        assert result.exit_code == code  # worst finding is SH-01.CSP (MEDIUM)

    def test_failed_check_makes_scan_partial(self) -> None:
        def landing(request: httpx.Request) -> httpx.Response:
            if "origin" in request.headers:
                raise httpx.ReadTimeout("timeout")
            return httpx.Response(200, text="home")

        with respx.mock(assert_all_called=False) as mock:
            mock.get(f"{TARGET}/").mock(side_effect=landing)
            mock.get(url__regex=rf"{TARGET}/shound-[0-9a-f]+").respond(404)
            partial = invoke("recon", TARGET, "--authorized")
            failing = invoke("recon", TARGET, "--authorized", "--fail-on", "medium")
        assert partial.exit_code == ExitCode.PARTIAL
        assert "Gagal diperiksa: CORS" in text(partial)
        assert failing.exit_code == ExitCode.FINDINGS  # findings win over partial

    def test_report_output_not_written_yet(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        with respx.mock(assert_all_called=False) as mock:
            self.mock_site(mock)
            result = invoke("recon", TARGET, "--authorized", "-o", "report.json")
        assert result.exit_code == ExitCode.USAGE
        assert "T-111" in text(result)
        assert not (tmp_path / "report.json").exists()

    def test_scan_still_incomplete(self) -> None:
        with respx.mock(assert_all_called=False) as mock:
            self.mock_site(mock)
            result = invoke("scan", TARGET, "--authorized")
        assert result.exit_code == ExitCode.USAGE
        assert "Security Grade" in text(result)
        assert "belum lengkap" in text(result)

    def test_unreachable_target_exits_3(self) -> None:
        with respx.mock(assert_all_called=False) as mock:
            mock.get(url__startswith=TARGET).mock(side_effect=httpx.ConnectError("refused"))
            result = invoke("scan", TARGET, "--authorized")
        assert result.exit_code == ExitCode.PREFLIGHT
        assert "Pre-flight gagal" in text(result)

    def test_local_mode_sends_nothing(self, tmp_path: Path) -> None:
        (tmp_path / "composer.lock").write_text("{}", encoding="utf-8")
        with respx.mock(assert_all_called=False) as mock:
            result = invoke("deps", str(tmp_path))
            assert len(mock.calls) == 0
        assert result.exit_code == ExitCode.USAGE
        assert "belum lengkap" in text(result)


class TestConfigCommands:
    def test_set_show_unset(self, tmp_path: Path) -> None:
        assert invoke("config", "set", "nvd_api_key", NVD_KEY).exit_code == 0
        assert invoke("config", "set", "timeout", "25").exit_code == 0
        stored = json.loads((tmp_path / "shound" / "config.json").read_text(encoding="utf-8"))
        assert stored == {"nvd_api_key": NVD_KEY, "timeout": 25.0}

        shown = invoke("config", "show")
        assert shown.exit_code == 0
        assert "1111…5555" in shown.output
        assert NVD_KEY not in shown.output

        assert invoke("config", "unset", "timeout").exit_code == 0
        stored = json.loads((tmp_path / "shound" / "config.json").read_text(encoding="utf-8"))
        assert stored == {"nvd_api_key": NVD_KEY}

    def test_set_invalid(self) -> None:
        result = invoke("config", "set", "rate_limit", "99")
        assert result.exit_code == ExitCode.USAGE
        assert "tidak valid" in text(result)

    def test_unknown_key(self) -> None:
        result = invoke("config", "unset", "colour")
        assert result.exit_code == ExitCode.USAGE


@pytest.mark.parametrize("sub", ["stats", "clear"])
def test_cache_not_available(sub: str) -> None:
    result = invoke("cache", sub)
    assert result.exit_code == ExitCode.USAGE
    assert "T-201" in result.output
