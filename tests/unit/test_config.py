import json
import os
import stat
from pathlib import Path

import pytest

from shound import __version__
from shound.config import (
    DEFAULT_USER_AGENT,
    ConfigError,
    config_path,
    load_settings,
    mask_secret,
    set_config_value,
    unset_config_value,
)

NVD_KEY = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    return tmp_path / "shound" / "config.json"


def write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


class TestLoadSettings:
    def test_defaults_without_file_or_env(self, cfg: Path) -> None:
        s = load_settings(path=cfg, env={})
        assert s.nvd_api_key is None
        assert s.timeout == 10.0
        assert s.rate_limit == 5.0
        assert s.proxy is None
        assert s.user_agent == DEFAULT_USER_AGENT
        assert __version__ in DEFAULT_USER_AGENT

    def test_precedence_cli_over_env_over_file(self, cfg: Path) -> None:
        write(cfg, {"timeout": 20, "rate_limit": 2, "proxy": "http://file:8080"})
        env = {"SHOUND_TIMEOUT": "30", "SHOUND_RATE_LIMIT": "3"}
        s = load_settings({"timeout": 40}, path=cfg, env=env)
        assert s.timeout == 40.0  # CLI
        assert s.rate_limit == 3.0  # env
        assert s.proxy == "http://file:8080"  # file

    def test_cli_none_values_are_ignored(self, cfg: Path) -> None:
        s = load_settings({"timeout": None}, path=cfg, env={"SHOUND_TIMEOUT": "15"})
        assert s.timeout == 15.0

    def test_empty_env_values_are_ignored(self, cfg: Path) -> None:
        s = load_settings(path=cfg, env={"SHOUND_PROXY": "", "SHOUND_NVD_API_KEY": ""})
        assert s.proxy is None
        assert s.nvd_api_key is None

    def test_api_key_from_env(self, cfg: Path) -> None:
        s = load_settings(path=cfg, env={"SHOUND_NVD_API_KEY": NVD_KEY})
        assert s.nvd_api_key is not None
        assert s.nvd_api_key.get_secret_value() == NVD_KEY

    def test_api_key_not_exposed_in_repr_or_dump(self, cfg: Path) -> None:
        s = load_settings(path=cfg, env={"SHOUND_NVD_API_KEY": NVD_KEY})
        assert NVD_KEY not in repr(s)
        assert NVD_KEY not in s.model_dump_json()

    @pytest.mark.parametrize(
        "env",
        [
            {"SHOUND_RATE_LIMIT": "21"},
            {"SHOUND_RATE_LIMIT": "0"},
            {"SHOUND_TIMEOUT": "abc"},
        ],
    )
    def test_invalid_values_raise_config_error(self, cfg: Path, env: dict[str, str]) -> None:
        with pytest.raises(ConfigError, match="tidak valid"):
            load_settings(path=cfg, env=env)

    def test_invalid_json_raises_config_error(self, cfg: Path) -> None:
        cfg.parent.mkdir(parents=True)
        cfg.write_text("{not json", encoding="utf-8")
        with pytest.raises(ConfigError, match="tidak dapat dibaca"):
            load_settings(path=cfg, env={})

    def test_non_object_json_raises_config_error(self, cfg: Path) -> None:
        write(cfg, ["timeout", 10])
        with pytest.raises(ConfigError, match="objek JSON"):
            load_settings(path=cfg, env={})

    def test_unknown_key_in_file_raises_config_error(self, cfg: Path) -> None:
        write(cfg, {"timout": 10})
        with pytest.raises(ConfigError, match="timout"):
            load_settings(path=cfg, env={})


class TestSetUnset:
    def test_set_stores_coerced_value(self, cfg: Path) -> None:
        set_config_value("timeout", "25", path=cfg)
        assert json.loads(cfg.read_text(encoding="utf-8")) == {"timeout": 25.0}
        assert load_settings(path=cfg, env={}).timeout == 25.0

    def test_set_api_key_stores_raw_value(self, cfg: Path) -> None:
        set_config_value("nvd_api_key", NVD_KEY, path=cfg)
        assert json.loads(cfg.read_text(encoding="utf-8")) == {"nvd_api_key": NVD_KEY}

    def test_set_keeps_other_keys(self, cfg: Path) -> None:
        set_config_value("timeout", "25", path=cfg)
        set_config_value("proxy", "http://proxy:3128", path=cfg)
        data = json.loads(cfg.read_text(encoding="utf-8"))
        assert data == {"timeout": 25.0, "proxy": "http://proxy:3128"}

    def test_set_invalid_value_leaves_file_untouched(self, cfg: Path) -> None:
        set_config_value("rate_limit", "4", path=cfg)
        with pytest.raises(ConfigError):
            set_config_value("rate_limit", "100", path=cfg)
        assert json.loads(cfg.read_text(encoding="utf-8")) == {"rate_limit": 4.0}

    def test_set_unknown_key_rejected(self, cfg: Path) -> None:
        with pytest.raises(ConfigError, match="tidak dikenal"):
            set_config_value("colour", "red", path=cfg)
        assert not cfg.exists()

    def test_unset_removes_key(self, cfg: Path) -> None:
        set_config_value("timeout", "25", path=cfg)
        set_config_value("proxy", "http://proxy:3128", path=cfg)
        unset_config_value("timeout", path=cfg)
        assert json.loads(cfg.read_text(encoding="utf-8")) == {"proxy": "http://proxy:3128"}

    def test_unset_missing_file_is_noop(self, cfg: Path) -> None:
        unset_config_value("timeout", path=cfg)
        assert not cfg.exists()

    @pytest.mark.skipif(os.name == "nt", reason="POSIX file modes only")
    def test_file_created_private_on_posix(self, cfg: Path) -> None:
        set_config_value("nvd_api_key", NVD_KEY, path=cfg)
        assert stat.S_IMODE(cfg.stat().st_mode) == 0o600


class TestDisplay:
    def test_display_masks_api_key(self, cfg: Path) -> None:
        s = load_settings(path=cfg, env={"SHOUND_NVD_API_KEY": NVD_KEY})
        shown = s.display_values()
        assert shown["nvd_api_key"] == "1111…5555"
        assert NVD_KEY not in str(shown)
        assert shown["proxy"] == "-"
        assert shown["rate_limit"] == "5.0"

    @pytest.mark.parametrize(("value", "masked"), [("short", "****"), ("abcdefghij", "abcd…ghij")])
    def test_mask_secret(self, value: str, masked: str) -> None:
        assert mask_secret(value) == masked


def test_config_path_is_per_user_app_dir() -> None:
    path = config_path()
    assert path.name == "config.json"
    assert path.parent.name == "shound"
