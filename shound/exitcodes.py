"""Process exit codes (PRD §3.7.5, MEMORY D-009)."""

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    FINDINGS = 1  # at least one finding >= --fail-on
    USAGE = 2  # invalid arguments, missing authorization, feature not available yet
    PREFLIGHT = 3  # target unreachable / lock file not found
    PARTIAL = 4  # some sources failed, no finding >= --fail-on
