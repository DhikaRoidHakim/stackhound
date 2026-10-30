"""JSON export of a ``ScanReport`` (PRD §3.7.3).

The report only contains data that already went through redaction (evidence is
built with ``redacted_evidence``); raw response bodies, exposed lock file
content and secrets are never part of ``ScanReport``.
"""

from pathlib import Path

from shound.core.models import ScanReport


def render_json(report: ScanReport) -> str:
    return report.model_dump_json(indent=2) + "\n"


def write_json(report: ScanReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(render_json(report), encoding="utf-8")
    tmp.replace(path)
