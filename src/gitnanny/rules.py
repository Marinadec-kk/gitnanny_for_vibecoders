from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from .models import AddedLine, DiffResult, Finding, Severity

_PLACEHOLDER_VALUE = re.compile(
    r"""^(?:
        x{3,} | \*{3,} |
        <[^>]{1,40}> | \$\{[^}]{1,40}\} | \{\{[^}]{1,40}\}\} |
        (?i: changeme | change -? me | placeholder | redacted |
             example.* | your[-_].* | dummy.* | test .{0,8} | sample.* )
    )$""",
    re.VERBOSE | re.IGNORECASE,
)

_ENV_LOOKUP = re.compile(
    r"os\.environ|os\.getenv|process\.env|getenv\s*\(|environ\[", re.IGNORECASE
)

_QUOTED_VALUE = re.compile(r"([\"'])(?P<value>[^\"']{8,})\1\s*$")


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_VALUE.match(value.strip()))


def _generic_secret_is_benign(match_text: str) -> bool:
    m = _QUOTED_VALUE.search(match_text)
    value = m.group("value") if m else match_text
    return _is_placeholder(value) or bool(_ENV_LOOKUP.search(match_text))


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str
    is_benign: Callable[[str], bool] | None = None

    def check(self, path: str, line: AddedLine) -> Finding | None:
        m = self.pattern.search(line.text)
        if m is None:
            return None
        snippet = m.group(0)
        if self.is_benign and self.is_benign(snippet):
            return None
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            file=path,
            line=line.lineno,
            message=self.message,
            snippet=snippet,
            source="local",
        )


PATTERN_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        rule_id="aws-access-key",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        message="AWS access key ID — rotate it and purge from history",
    ),
    PatternRule(
        rule_id="github-token",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
        message="GitHub token — revoke immediately",
    ),
    PatternRule(
        rule_id="google-api-key",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        message="Google API key — revoke in Google Cloud console",
    ),
    PatternRule(
        rule_id="slack-token",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        message="Slack token — revoke in Slack app settings",
    ),
    PatternRule(
        rule_id="anthropic-key",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
        message="Anthropic API key — revoke in console",
    ),
    PatternRule(
        rule_id="openai-key",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_-]{20,}"),
        message="OpenAI-style API key — revoke and rotate",
    ),
    PatternRule(
        rule_id="private-key",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
        message="Private key material committed",
    ),
    PatternRule(
        rule_id="jwt",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
        message="Hardcoded JWT — treat as leaked",
    ),
    PatternRule(
        rule_id="uri-password",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@"),
        message="Connection string with embedded password",
    ),
    PatternRule(
        rule_id="generic-secret",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"""(?ix)\b(?: password | passwd | secret | ap[i]?[_-]?key | token )
                \s*[=:]\s*["'][^"']{8,}["']""",
        ),
        message="Hardcoded credential — use an environment variable instead",
        is_benign=_generic_secret_is_benign,
    ),
)

_COMMENT_PREFIXES = ("#", "//", ";")

_CODE_LIKE = re.compile(
    r"""(?x)
    ^\s*(?: return | if | for | while | def | class | import | from
          | const | let | var | function | print | console | await )
    | [={};()]\s*$ | \)\s*[;{]?
    """
)

_DEBUG_LEFTOVERS = re.compile(
    r"breakpoint\s*\(|pdb\.set_trace\s*\(|debugger\s*[;\n]|console\.log\s*\("
)


def _check_commented_code(path: str, line: AddedLine) -> Finding | None:
    stripped = line.text.strip()
    if len(stripped) < 12 or not stripped.startswith(_COMMENT_PREFIXES):
        return None
    code_part = stripped.lstrip("#/; ").strip()
    if not _CODE_LIKE.search(code_part):
        return None
    return Finding(
        rule_id="commented-code",
        severity=Severity.INFO,
        file=path,
        line=line.lineno,
        message="Commented-out code left behind — delete it, git remembers",
        snippet=stripped,
        source="local",
    )


def _check_debug_leftovers(path: str, line: AddedLine) -> Finding | None:
    m = _DEBUG_LEFTOVERS.search(line.text)
    if m is None:
        return None
    return Finding(
        rule_id="debug-leftover",
        severity=Severity.WARNING,
        file=path,
        line=line.lineno,
        message="Debug leftover — remove before pushing",
        snippet=m.group(0),
        source="local",
    )


HEURISTIC_CHECKS: tuple[Callable[[str, AddedLine], Finding | None], ...] = (
    _check_commented_code,
    _check_debug_leftovers,
)


def run_local_checks(diff: DiffResult) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()

    for diff_file in diff.files:
        for added in diff_file.added_lines:
            if not added.text.strip():
                continue
            candidates = [r.check(diff_file.path, added) for r in PATTERN_RULES]
            candidates += [c(diff_file.path, added) for c in HEURISTIC_CHECKS]
            for f in candidates:
                if f is None:
                    continue
                key = (f.rule_id, f.file, f.line)
                if key not in seen:
                    seen.add(key)
                    findings.append(f)

    order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    findings.sort(key=lambda f: (order[f.severity], f.file, f.line))
    return findings
