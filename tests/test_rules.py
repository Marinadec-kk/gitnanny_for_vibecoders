from __future__ import annotations

from gitnanny.diff import parse_added_lines
from gitnanny.models import DiffResult, Severity
from gitnanny.rules import run_local_checks


def scan(*lines: str) -> list:
    body = "\n".join(f"+{ln}" for ln in lines)
    sample = f"diff --git a/f.py b/f.py\n+++ b/f.py\n@@ -1,1 +1,{len(lines)} @@\n{body}\n"
    diff_file = parse_added_lines(sample)[0]
    diff = DiffResult(raw=sample, files=(diff_file,))
    return run_local_checks(diff)


def ids(findings):
    return [f.rule_id for f in findings]


def test_aws_key_detected():
    assert "aws-access-key" in ids(scan('k = "AKIAIOSFODNN7EXAMPLE"'))


def test_github_tokens_detected():
    assert "github-token" in ids(scan('a = "ghp_' + "A" * 36 + '"'))
    assert "github-token" in ids(scan('a = "github_pat_' + "B" * 30 + '"'))


def test_provider_keys_detected():
    assert "anthropic-key" in ids(scan('k = "sk-ant-api03-' + "c" * 40 + '"'))
    assert "openai-key" in ids(scan('k = "sk-proj-' + "d" * 40 + '"'))
    assert "google-api-key" in ids(scan('k = "AIza' + "e" * 35 + '"'))
    assert "slack-token" in ids(scan('k = "xoxb-' + "f" * 20 + '"'))


def test_private_key_and_jwt_detected():
    assert "private-key" in ids(scan("-----BEGIN RSA PRIVATE KEY-----"))
    jwt = "eyJhbGciOiJIUzI1Ni9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4"
    assert "jwt" in ids(scan(f"auth = '{jwt}'"))


def test_uri_password_detected():
    assert "uri-password" in ids(scan('db = "postgres://admin:hunter2@db.example.com/x"'))


def test_generic_secret_with_placeholders_suppressed():
    flagged = scan(
        'password = "hunter2hunter2"',
        'api_key = "<your-key-here>"',
        'secret = "XXXXXXXXXX"',
        'token = "${GITHUB_TOKEN}"',
        "password = os.environ['DB_PASSWORD']",
    )
    secrets = [f for f in flagged if f.rule_id == "generic-secret"]
    assert len(secrets) == 1
    assert secrets[0].line == 1


def test_commented_code_and_debug_leftovers():
    findings = scan(
        "# return compute_total(order, tax_rate)",
        "breakpoint()",
        "# just a prose comment about nothing",
    )
    assert "commented-code" in ids(findings)
    assert "debug-leftover" in ids(findings)
    assert ids(findings).count("commented-code") == 1


def test_clean_code_has_no_findings():
    assert scan("x = max(items)", "def total(xs): return sum(xs)") == []


def test_findings_sorted_by_severity():
    findings = scan(
        "# return compute_total(order, tax_rate)",   # info
        'password = "hunter2hunter2"',               # critical
        "breakpoint()",                              # warning
    )
    assert [f.severity for f in findings] == [
        Severity.CRITICAL,
        Severity.WARNING,
        Severity.INFO,
    ]
