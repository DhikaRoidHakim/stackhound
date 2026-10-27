"""User configuration (PRD §3.8.1).

Value precedence: CLI flag > environment variable > config.json > default.
The config file only stores values the user set explicitly.
"""

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import platformdirs
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from shound import __version__

APP_NAME = "shound"
DEFAULT_USER_AGENT = f"StackHound-SecurityAudit/{__version__}"
MAX_RATE_LIMIT = 20.0

ENV_VARS: dict[str, str] = {
    "nvd_api_key": "SHOUND_NVD_API_KEY",
    "proxy": "SHOUND_PROXY",
    "timeout": "SHOUND_TIMEOUT",
    "rate_limit": "SHOUND_RATE_LIMIT",
    "user_agent": "SHOUND_USER_AGENT",
}


class ConfigError(Exception):
    """Invalid or unreadable configuration; the message is user-facing."""


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nvd_api_key: SecretStr | None = None
    timeout: float = Field(default=10.0, gt=0, le=300)
    rate_limit: float = Field(default=5.0, gt=0, le=MAX_RATE_LIMIT)
    proxy: str | None = None
    user_agent: str = Field(default=DEFAULT_USER_AGENT, min_length=1)

    def display_values(self) -> dict[str, str]:
        """Values for `shound config show`, with secrets masked."""
        shown: dict[str, str] = {}
        for key in type(self).model_fields:
            value = getattr(self, key)
            if value is None:
                shown[key] = "-"
            elif isinstance(value, SecretStr):
                shown[key] = mask_secret(value.get_secret_value())
            else:
                shown[key] = str(value)
        return shown


CONFIG_KEYS: tuple[str, ...] = tuple(Settings.model_fields)


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}…{value[-4:]}"


def config_path() -> Path:
    return Path(platformdirs.user_config_dir(APP_NAME, appauthor=False)) / "config.json"


def read_config_file(path: Path | None = None) -> dict[str, Any]:
    path = path or config_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"File konfigurasi tidak dapat dibaca ({path}): {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"File konfigurasi harus berisi objek JSON ({path}).")
    return data


def env_values(env: Mapping[str, str] | None = None) -> dict[str, str]:
    env = os.environ if env is None else env
    return {key: env[var] for key, var in ENV_VARS.items() if env.get(var)}


def load_settings(
    cli_overrides: Mapping[str, Any] | None = None,
    *,
    path: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> Settings:
    merged: dict[str, Any] = {}
    merged.update(read_config_file(path))
    merged.update(env_values(env))
    if cli_overrides:
        merged.update({k: v for k, v in cli_overrides.items() if v is not None})
    return _validate(merged)


def set_config_value(key: str, value: str, *, path: Path | None = None) -> None:
    _check_key(key)
    path = path or config_path()
    data = read_config_file(path)
    data[key] = value
    stored = getattr(_validate(data), key)
    data[key] = stored.get_secret_value() if isinstance(stored, SecretStr) else stored
    _write_private(path, data)


def unset_config_value(key: str, *, path: Path | None = None) -> None:
    _check_key(key)
    path = path or config_path()
    data = read_config_file(path)
    if data.pop(key, None) is not None:
        _write_private(path, data)


def _check_key(key: str) -> None:
    if key not in CONFIG_KEYS:
        raise ConfigError(
            f"Kunci konfigurasi tidak dikenal: {key}. Pilihan: {', '.join(CONFIG_KEYS)}."
        )


def _validate(values: Mapping[str, Any]) -> Settings:
    try:
        return Settings.model_validate(values)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in err['loc']) or '-'}: {err['msg']}"
            for err in exc.errors()
        )
        raise ConfigError(f"Nilai konfigurasi tidak valid: {problems}") from exc


def _write_private(path: Path, data: Mapping[str, Any]) -> None:
    """Write atomically; on POSIX the file is created with mode 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)
