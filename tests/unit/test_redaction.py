import pytest

from shound.core.redaction import MASK, MAX_SNIPPET_LENGTH, redact, redacted_evidence

# Every value in this list is a fake secret that must never survive redaction.
SECRETS = [
    "base64:Q2hhbmdlTWVQbGVhc2VDaGFuZ2VNZVBsZWFzZTEyMzQ=",
    "S3cr3t-DB-P@ss",
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "mailpass123",
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl",
    "deploytoken:glpat-abcdefgh12345678",
    "redispass",
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC",
]

ENV_FILE = f"""APP_NAME=Laravel
APP_ENV=production
APP_KEY={SECRETS[0]}
APP_DEBUG=false

# Database
DB_HOST=10.0.0.5
DB_PASSWORD="{SECRETS[1]}"
export AWS_ACCESS_KEY_ID={SECRETS[2]}
AWS_SECRET_ACCESS_KEY={SECRETS[3]}
MAIL_PASSWORD='{SECRETS[4]}'
REDIS_URL=redis://:{SECRETS[8]}@cache:6379
EMPTY_VALUE=
"""

GIT_CONFIG = f"""[core]
\trepositoryformatversion = 0
[remote "origin"]
\turl = https://{SECRETS[7]}@gitlab.example.test/team/app.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
"""


def assert_no_secrets(text: str) -> None:
    for secret in SECRETS:
        assert secret not in text, f"secret leaked: {secret!r}"


class TestEnvFiles:
    def test_env_values_masked_keys_kept(self) -> None:
        out = redact(ENV_FILE, max_length=None)
        assert_no_secrets(out)
        for key in ("APP_KEY", "DB_HOST", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "REDIS_URL"):
            assert f"{key}={MASK}" in out
        assert f"export AWS_ACCESS_KEY_ID={MASK}" in out

    def test_comments_and_empty_values_kept(self) -> None:
        out = redact(ENV_FILE, max_length=None)
        assert "# Database" in out
        assert "EMPTY_VALUE=" in out

    def test_non_secret_values_are_masked_too(self) -> None:
        # .env values are masked wholesale; host names can be sensitive as well.
        assert "10.0.0.5" not in redact(ENV_FILE, max_length=None)

    @pytest.mark.parametrize(
        "line",
        ["# DB_PASSWORD=old-secret-pw", "#DB_HOST=10.9.9.9", "  #  export API_KEY=old-secret-pw"],
    )
    def test_commented_out_values_masked(self, line: str) -> None:
        out = redact(line)
        assert "old-secret-pw" not in out
        assert "10.9.9.9" not in out
        assert out.endswith(f"={MASK}")


class TestPatterns:
    def test_git_config_remote_credentials(self) -> None:
        out = redact(GIT_CONFIG, max_length=None)
        assert_no_secrets(out)
        assert f"https://{MASK}@gitlab.example.test/team/app.git" in out
        assert "[core]" in out

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("mysql://root:hunter2@db:3306/app", f"mysql://{MASK}@db:3306/app"),
            ('{"password": "hunter2"}', f'{{"password": "{MASK}"}}'),
            ("db_password: hunter2", f"db_password: {MASK}"),
            ("/callback?token=hunter2&page=1", f"/callback?token={MASK}&page=1"),
            ("Authorization: Bearer abcdefghijklmnop", f"Authorization: Bearer {MASK}"),
            ("APP_KEY base64:Q2hhbmdlTWVQbGVhc2U=", f"APP_KEY base64:{MASK}"),
        ],
    )
    def test_pattern(self, text: str, expected: str) -> None:
        assert redact(text) == expected

    def test_standalone_tokens(self) -> None:
        text = f"leaked {SECRETS[5]} and {SECRETS[6]} and {SECRETS[2]}"
        out = redact(text)
        assert_no_secrets(out)
        assert out == f"leaked {MASK} and {MASK} and {MASK}"

    def test_private_key_block(self) -> None:
        block = f"-----BEGIN RSA PRIVATE KEY-----\n{SECRETS[9]}\n-----END RSA PRIVATE KEY-----"
        out = redact(f"before\n{block}\nafter")
        assert_no_secrets(out)
        assert out.startswith("before\n")
        assert out.endswith("\nafter")

    def test_truncated_private_key_block(self) -> None:
        out = redact(f"-----BEGIN PRIVATE KEY-----\n{SECRETS[9]}")
        assert_no_secrets(out)

    def test_plain_html_untouched(self) -> None:
        html = '<meta name="csrf-token" content="abc"><title>Welcome</title>'
        assert redact(html) == html

    def test_idempotent(self) -> None:
        once = redact(ENV_FILE + GIT_CONFIG, max_length=None)
        assert redact(once, max_length=None) == once


class TestTruncation:
    def test_truncates_to_max_length(self) -> None:
        out = redact("a" * 2000)
        assert len(out) == MAX_SNIPPET_LENGTH
        assert out.endswith("…")

    def test_short_text_unchanged(self) -> None:
        assert redact("hello") == "hello"

    def test_redacts_before_truncating(self) -> None:
        # The secret straddles the cut point; it must still be masked, not cut in half.
        text = "x" * 480 + f"APP_KEY={SECRETS[0]}"
        out = redact(text)
        assert SECRETS[0][:12] not in out


class TestRedactedEvidence:
    def test_all_text_fields_redacted(self) -> None:
        ev = redacted_evidence(
            f"https://user:{SECRETS[1]}@target.test/.env?token={SECRETS[4]}",
            status_code=200,
            snippet=ENV_FILE,
            note=f"remote url https://{SECRETS[7]}@gitlab.example.test",
        )
        dumped = ev.model_dump_json()
        assert_no_secrets(dumped)
        assert ev.url == f"https://{MASK}@target.test/.env?token={MASK}"
        assert ev.status_code == 200
        assert ev.snippet is not None
        assert len(ev.snippet) <= MAX_SNIPPET_LENGTH

    def test_optional_fields_stay_none(self) -> None:
        ev = redacted_evidence("https://target.test/")
        assert ev.snippet is None
        assert ev.note is None
