from pathlib import Path

import pytest

from shound.authorization import AuthorizationGate
from shound.core.models import Severity
from shound.options import (
    FailOn,
    PreflightError,
    UsageError,
    normalize_target_url,
    parse_component,
    parse_component_versions,
    parse_framework,
    parse_outputs,
    parse_version,
    resolve_lockfile,
    target_key,
)


class TestNormalizeTargetUrl:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("https://Staging.Example.com", "https://staging.example.com/"),
            ("  http://127.0.0.1:8081/app?x=1#frag ", "http://127.0.0.1:8081/app?x=1"),
            ("HTTPS://example.com/Path", "https://example.com/Path"),
            ("http://[::1]:8080/", "http://[::1]:8080/"),
        ],
    )
    def test_valid(self, raw: str, expected: str) -> None:
        assert normalize_target_url(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "example.com",
            "ftp://example.com",
            "https://",
            "http://example.com:99999",
            "javascript:x",
        ],
    )
    def test_invalid(self, raw: str) -> None:
        with pytest.raises(UsageError, match="tidak valid"):
            normalize_target_url(raw)

    def test_credentials_rejected(self) -> None:
        with pytest.raises(UsageError, match="kredensial"):
            normalize_target_url("https://admin:secret@example.com/")


class TestTargetKey:
    def test_default_ports(self) -> None:
        assert target_key("https://example.com/a") == "https://example.com:443"
        assert target_key("http://example.com/b") == "http://example.com:80"

    def test_explicit_port(self) -> None:
        assert target_key("http://127.0.0.1:8081/") == "http://127.0.0.1:8081"


class TestVersions:
    def test_parse_component_versions(self) -> None:
        assert parse_component_versions(["Laravel=v9.52.4", "php=8.1.2"]) == {
            "laravel": "9.52.4",
            "php": "8.1.2",
        }

    def test_none_is_empty(self) -> None:
        assert parse_component_versions(None) == {}

    @pytest.mark.parametrize("item", ["laravel", "=9.0", "laravel=", "laravel=latest", "a b=1.0"])
    def test_invalid_items(self, item: str) -> None:
        with pytest.raises(UsageError):
            parse_component_versions([item])

    def test_duplicate_component(self) -> None:
        with pytest.raises(UsageError, match="lebih dari sekali"):
            parse_component_versions(["laravel=9.0", "LARAVEL=10.0"])

    @pytest.mark.parametrize(
        ("raw", "expected"), [("9", "9"), ("v1.2.3", "1.2.3"), ("2.0.0-beta.1", "2.0.0-beta.1")]
    )
    def test_parse_version(self, raw: str, expected: str) -> None:
        assert parse_version(raw) == expected

    def test_parse_component(self) -> None:
        assert parse_component(" Laravel/Framework ") == "laravel/framework"
        with pytest.raises(UsageError):
            parse_component("bad name")


class TestOutputsAndFramework:
    def test_outputs_validated_and_deduplicated(self) -> None:
        paths = [Path("r.json"), Path("r.MD"), Path("r.json"), Path("out/r.html")]
        assert parse_outputs(paths) == (Path("r.json"), Path("r.MD"), Path("out/r.html"))

    def test_unknown_output_format(self) -> None:
        with pytest.raises(UsageError, match="Format laporan"):
            parse_outputs([Path("report.pdf")])

    def test_framework(self) -> None:
        assert parse_framework(None) is None
        assert parse_framework("Laravel") == "laravel"
        with pytest.raises(UsageError, match="Framework tidak dikenal"):
            parse_framework("rails")

    def test_fail_on_maps_to_severity(self) -> None:
        assert FailOn.HIGH.severity is Severity.HIGH


class TestResolveLockfile:
    def test_file(self, tmp_path: Path) -> None:
        lock = tmp_path / "composer.lock"
        lock.write_text("{}", encoding="utf-8")
        assert resolve_lockfile(lock) == lock

    def test_folder_picks_supported_lockfile(self, tmp_path: Path) -> None:
        (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
        assert resolve_lockfile(tmp_path) == tmp_path / "package-lock.json"

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(PreflightError, match="tidak ditemukan"):
            resolve_lockfile(tmp_path / "nope.lock")

    def test_folder_without_lockfile(self, tmp_path: Path) -> None:
        with pytest.raises(PreflightError, match="Tidak ada lock file"):
            resolve_lockfile(tmp_path)


class TestAuthorizationGate:
    URL = "https://example.com/app"

    def test_flag_authorizes_without_prompt(self) -> None:
        gate = AuthorizationGate()
        assert gate.ensure(self.URL, authorized_flag=True, interactive=False, confirm=_never)
        assert gate.is_confirmed(self.URL)

    def test_non_interactive_without_flag_refused(self) -> None:
        gate = AuthorizationGate()
        assert not gate.ensure(self.URL, authorized_flag=False, interactive=False, confirm=_never)

    def test_interactive_confirmation_remembered_per_target(self) -> None:
        gate = AuthorizationGate()
        asked: list[str] = []

        def confirm(key: str) -> bool:
            asked.append(key)
            return True

        assert gate.ensure(self.URL, authorized_flag=False, interactive=True, confirm=confirm)
        same_host = "https://example.com/other?x=1"
        assert gate.ensure(same_host, authorized_flag=False, interactive=True, confirm=confirm)
        other_port = "https://example.com:8443/"
        assert gate.ensure(other_port, authorized_flag=False, interactive=True, confirm=confirm)
        assert asked == ["https://example.com:443", "https://example.com:8443"]

    def test_declined(self) -> None:
        gate = AuthorizationGate()
        assert not gate.ensure(
            self.URL, authorized_flag=False, interactive=True, confirm=lambda _: False
        )
        assert not gate.is_confirmed(self.URL)


def _never(_: str) -> bool:
    raise AssertionError("confirm must not be called")
