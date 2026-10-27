"""Terminal rendering shared by the CLI and the interactive menu."""

from importlib.resources import files

from rich.console import Console
from rich.table import Table
from rich.text import Text

from shound import __version__
from shound.config import Settings

DISCLAIMER_MARKER = "[!] DISCLAIMER"


def load_banner() -> str:
    """Banner from ``shound/data/banner.txt`` with the running version (MEMORY D-021)."""
    text = files("shound").joinpath("data/banner.txt").read_text(encoding="utf-8")
    return text.replace("{version}", __version__)


def print_banner(console: Console) -> None:
    art, marker, disclaimer = load_banner().rstrip("\n").partition(DISCLAIMER_MARKER)
    # Text objects: the banner contains "[!]" and backslashes that Rich would parse as markup.
    console.print(Text(art.rstrip("\n"), style="bold cyan"))
    if marker:
        console.print(Text(marker + disclaimer, style="yellow"))
    console.print()


def settings_table(settings: Settings) -> Table:
    table = Table(title="Konfigurasi efektif", title_justify="left")
    table.add_column("Kunci", style="bold")
    table.add_column("Nilai")
    for key, value in settings.display_values().items():
        table.add_row(key, Text(value))
    return table
