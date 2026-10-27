"""Evidence redaction (PRD §3.7.4, CLAUDE.md rule 3).

Every snippet, URL and note taken from a target passes through ``redact`` before it
is stored in a ``Finding``. Patterns live in code rather than ``data/*.json`` on
purpose: they are a safety control, not detection signatures, and must not be
weakened by editing a data file.
"""

import re

from shound.core.models import Evidence

MASK = "***"
MAX_SNIPPET_LENGTH = 500

_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
# scheme://user:pass@host -> scheme://***@host. Greedy up to the last "@" of the
# authority so an unencoded "@" inside the password is masked as well.
_URL_CREDENTIALS = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/?#\s\"'<>]+@")
# .env style line: KEY=value, optionally prefixed with `export`. Commented-out lines
# ("# DB_PASSWORD=old") are masked too: people park old secrets there.
_ENV_LINE = re.compile(
    r"(?m)^([ \t]*(?:#[ \t]*)?(?:export[ \t]+)?[A-Z_][A-Z0-9_]*[ \t]*=[ \t]*)(\S.*?)[ \t]*$"
)
# key/value pair whose key name looks sensitive: JSON, YAML, query strings, ini files
_SENSITIVE_PAIR = re.compile(
    r"(?i)([\"']?[\w.-]*(?:passw(?:or)?d|pwd|secret|token|api[_-]?key|access[_-]?key"
    r"|private[_-]?key|app[_-]?key|credential|auth)[\w.-]*[\"']?[ \t]*[:=][ \t]*)"
    # skip "Bearer ***" already handled by _AUTH_SCHEME so the scheme stays readable
    r"(?!(?:bearer|basic|token)[ \t]+\*\*\*)"
    r"(\"[^\"\n]*\"|'[^'\n]*'|[^\s,;&\"'<>]+)"
)
_AUTH_SCHEME = re.compile(r"(?i)\b(bearer|basic|token)[ \t]+[A-Za-z0-9\-._~+/]{8,}=*")
_STANDALONE_TOKENS = [
    re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),  # JWT
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),  # GitHub token
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),  # Slack token
    re.compile(r"\b[rs]k_live_[0-9A-Za-z]{16,}\b"),  # Stripe live key
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),  # Google API key
]
_LARAVEL_BASE64_KEY = re.compile(r"\bbase64:[A-Za-z0-9+/]{16,}={0,2}")


def _mask_value(match: re.Match[str]) -> str:
    value = match.group(2)
    if value[:1] in {'"', "'"} and value[-1:] == value[:1]:
        return f"{match.group(1)}{value[0]}{MASK}{value[0]}"
    return f"{match.group(1)}{MASK}"


def redact(text: str, *, max_length: int | None = MAX_SNIPPET_LENGTH) -> str:
    """Mask secrets in ``text``, then truncate to ``max_length`` characters.

    Redaction runs before truncation so a cut can never leave a partial secret
    that no longer matches a pattern.
    """
    text = _PRIVATE_KEY_BLOCK.sub(f"[PRIVATE KEY {MASK}]", text)
    text = _URL_CREDENTIALS.sub(rf"\1{MASK}@", text)
    text = _ENV_LINE.sub(rf"\1{MASK}", text)
    text = _AUTH_SCHEME.sub(rf"\1 {MASK}", text)
    text = _SENSITIVE_PAIR.sub(_mask_value, text)
    text = _LARAVEL_BASE64_KEY.sub(f"base64:{MASK}", text)
    for pattern in _STANDALONE_TOKENS:
        text = pattern.sub(MASK, text)
    if max_length is not None and len(text) > max_length:
        text = text[: max_length - 1] + "…"
    return text


def redacted_evidence(
    url: str,
    *,
    method: str = "GET",
    status_code: int | None = None,
    snippet: str | None = None,
    note: str | None = None,
) -> Evidence:
    """The one way plugins should build ``Evidence`` from target data."""
    return Evidence(
        url=redact(url, max_length=None),
        method=method,
        status_code=status_code,
        snippet=redact(snippet) if snippet is not None else None,
        note=redact(note) if note is not None else None,
    )
