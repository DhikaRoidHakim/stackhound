"""Command line entry point.

Subcommands are added in T-101; the interactive menu in T-102.
"""

import typer
from rich.console import Console

from shound import __version__

app = typer.Typer(
    name="shound",
    help="StackHound - Framework-Based Security Configuration & CVE Auditor.",
    no_args_is_help=False,
    add_completion=False,
)
console = Console()


def _print_version(value: bool) -> None:
    if value:
        console.print(f"StackHound {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        help="Tampilkan versi lalu keluar.",
        callback=_print_version,
        is_eager=True,
    ),
) -> None:
    """StackHound - audit konfigurasi keamanan & CVE secara non-intrusive."""
    if ctx.invoked_subcommand is None:
        console.print(
            "[yellow]Menu interaktif belum tersedia.[/yellow] Gunakan [bold]--help[/bold]."
        )
