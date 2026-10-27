"""Framework-specific audit plugins and the loader (PRD §2.3 Phase 3)."""

from dataclasses import dataclass

from shound.core.fingerprint import LIKELY, STRONG, FingerprintResult
from shound.plugins.base import BasePlugin
from shound.plugins.laravel import LaravelPlugin

PLUGINS: dict[str, type[BasePlugin]] = {plugin.id: plugin for plugin in (LaravelPlugin,)}


@dataclass(frozen=True)
class PluginSelection:
    plugins: list[type[BasePlugin]]
    notes: list[str]


def select_plugins(fingerprint: FingerprintResult, forced: str | None = None) -> PluginSelection:
    """Pick plugins by fingerprint confidence, or the one forced with --framework.

    >= STRONG runs automatically, >= LIKELY runs with a note, lower is skipped.
    """
    if forced is not None:
        plugin = PLUGINS.get(forced)
        if plugin is None:
            return PluginSelection([], [f"Plugin '{forced}' belum tersedia."])
        return PluginSelection([plugin], [f"Plugin {plugin.name} dipaksa dengan --framework."])

    selected: list[type[BasePlugin]] = []
    notes: list[str] = []
    for plugin in PLUGINS.values():
        confidence = plugin.match(fingerprint)
        if confidence >= STRONG:
            selected.append(plugin)
        elif confidence >= LIKELY:
            selected.append(plugin)
            notes.append(
                f"{plugin.name} kemungkinan dipakai ({confidence:.0%}); plugin tetap dijalankan."
            )
    if not selected:
        notes.append(
            "Tidak ada framework yang terdeteksi cukup kuat untuk plugin yang tersedia. "
            "Gunakan --framework untuk memaksa plugin tertentu."
        )
    return PluginSelection(selected, notes)
