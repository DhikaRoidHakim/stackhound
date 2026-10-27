"""Interactive prompts behind a small protocol so the menu can be tested with
scripted answers. Every method returns ``None`` (or ``False``) when the user
cancels with Ctrl+C / Esc."""

import sys
from typing import Literal, Protocol

import questionary

from shound.config import CONFIG_KEYS
from shound.options import FRAMEWORKS


def is_interactive_terminal() -> bool:
    """True only when prompts can really be shown.

    ``isatty()`` alone is not enough on Windows: it is also true for the ``NUL``
    device and for mintty (Git Bash), where prompt_toolkit cannot draw prompts.
    There we additionally require a real console handle.
    """
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return False
    if sys.platform == "win32":
        import ctypes
        import msvcrt

        try:
            handle = msvcrt.get_osfhandle(sys.stdin.fileno())
        except OSError:
            return False
        mode = ctypes.c_ulong()
        return bool(ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)))
    return True


MenuChoice = Literal["recon", "audit", "cve", "deps", "scan", "settings", "cache", "exit"]
CveSource = Literal["url", "manual"]
SettingsAction = Literal["set", "unset"]

ARROW_HINT = "(gunakan tombol panah)"

MENU_ITEMS: list[tuple[MenuChoice, str]] = [
    ("recon", "[1] Quick Recon & Fingerprint (Deteksi Framework, Server & Security Headers)"),
    (
        "audit",
        "[2] Framework Misconfiguration Audit (Audit spesifik: Laravel, Django, Express, dll.)",
    ),
    ("cve", "[3] CVE Vulnerability Lookup (Cari CVE via Deteksi Otomatis / Input Versi Manual)"),
    (
        "deps",
        "[4] Local Dependency Scanner (Baca composer.lock / package-lock.json / requirements.txt)",
    ),
    ("scan", "[5] Full Comprehensive Scan (Jalankan Mode 1 + 2 + 3 secara berurutan)"),
    ("settings", "[6] Pengaturan (API Key NVD, Timeout, Proxy, Rate Limit & User-Agent)"),
    ("cache", "[7] Kelola Cache"),
    ("exit", "[0] Keluar"),
]


class Prompts(Protocol):
    def select_mode(self) -> MenuChoice | None: ...
    def ask_url(self) -> str | None: ...
    def confirm_authorization(self, target: str) -> bool: ...
    def select_framework(self) -> str | None: ...
    def select_cve_source(self) -> CveSource | None: ...
    def ask_component(self) -> str | None: ...
    def ask_version(self, component: str) -> str | None: ...
    def ask_lockfile_path(self) -> str | None: ...
    def select_settings_action(self) -> SettingsAction | None: ...
    def select_setting_key(self) -> str | None: ...
    def ask_setting_value(self, key: str) -> str | None: ...
    def pause(self) -> None: ...


class QuestionaryPrompts:
    def select_mode(self) -> MenuChoice | None:
        choices = [questionary.Choice(title=label, value=value) for value, label in MENU_ITEMS]
        answer: MenuChoice | None = questionary.select(
            "Pilih Mode Pemindaian:", choices=choices, instruction=ARROW_HINT
        ).ask()
        return answer

    def ask_url(self) -> str | None:
        answer: str | None = questionary.text(
            "URL target (contoh: https://staging.aplikasiku.com):",
            validate=lambda value: bool(value.strip()) or "URL wajib diisi.",
        ).ask()
        return answer

    def confirm_authorization(self, target: str) -> bool:
        answer: bool | None = questionary.confirm(
            f"Saya memiliki izin untuk mengaudit {target}", default=False
        ).ask()
        return bool(answer)

    def select_framework(self) -> str | None:
        choices = [questionary.Choice(title="Deteksi otomatis", value="auto")] + [
            questionary.Choice(title=name, value=name) for name in FRAMEWORKS
        ]
        answer: str | None = questionary.select(
            "Framework target:", choices=choices, instruction=ARROW_HINT
        ).ask()
        return answer

    def select_cve_source(self) -> CveSource | None:
        answer: CveSource | None = questionary.select(
            "Sumber versi:",
            choices=[
                questionary.Choice(title="Deteksi otomatis dari URL target", value="url"),
                questionary.Choice(title="Input komponen & versi manual", value="manual"),
            ],
            instruction=ARROW_HINT,
        ).ask()
        return answer

    def ask_component(self) -> str | None:
        answer: str | None = questionary.text(
            "Komponen (contoh: laravel, django, php, nginx):"
        ).ask()
        return answer

    def ask_version(self, component: str) -> str | None:
        answer: str | None = questionary.text(f"Versi {component} (contoh: 9.52.4):").ask()
        return answer

    def ask_lockfile_path(self) -> str | None:
        answer: str | None = questionary.path(
            "Path lock file atau folder proyek (composer.lock / package-lock.json / "
            "requirements.txt):"
        ).ask()
        return answer

    def select_settings_action(self) -> SettingsAction | None:
        # Choice(value=None) would fall back to the title, so "back" is explicit.
        answer: SettingsAction | Literal["back"] | None = questionary.select(
            "Aksi:",
            choices=[
                questionary.Choice(title="Ubah nilai", value="set"),
                questionary.Choice(title="Kembalikan ke default", value="unset"),
                questionary.Choice(title="Kembali", value="back"),
            ],
            instruction=ARROW_HINT,
        ).ask()
        return None if answer == "back" else answer

    def select_setting_key(self) -> str | None:
        answer: str | None = questionary.select(
            "Pengaturan:", choices=list(CONFIG_KEYS), instruction=ARROW_HINT
        ).ask()
        return answer

    def ask_setting_value(self, key: str) -> str | None:
        prompt = questionary.password if key == "nvd_api_key" else questionary.text
        answer: str | None = prompt(f"Nilai baru untuk {key}:").ask()
        return answer

    def pause(self) -> None:
        questionary.press_any_key_to_continue(
            "Tekan tombol apa saja untuk kembali ke menu..."
        ).ask()
