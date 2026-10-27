"""Audit authorization gate (PRD §6.3, MEMORY D-008).

No request may reach a target before this gate says yes: either ``--authorized``
was given, or the user confirmed interactively. A confirmation is remembered per
target (scheme + host + port) for the rest of the process.
"""

from collections.abc import Callable

from shound.options import target_key


class AuthorizationGate:
    def __init__(self) -> None:
        self._confirmed: set[str] = set()

    def is_confirmed(self, target_url: str) -> bool:
        return target_key(target_url) in self._confirmed

    def ensure(
        self,
        target_url: str,
        *,
        authorized_flag: bool,
        interactive: bool,
        confirm: Callable[[str], bool],
    ) -> bool:
        key = target_key(target_url)
        if authorized_flag or key in self._confirmed:
            self._confirmed.add(key)
            return True
        if interactive and confirm(key):
            self._confirmed.add(key)
            return True
        return False
