"""User-facing errors that map to process exit codes."""


class UsageError(Exception):
    """Invalid user input; the message is shown to the user (exit code 2)."""


class PreflightError(Exception):
    """A precondition failed: lock file missing, target unreachable (exit code 3)."""
