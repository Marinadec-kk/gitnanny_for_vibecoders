from __future__ import annotations

import json
import os
import re
from typing import NamedTuple

from .models import DiffResult, Finding, Severity

DEFAULT_MODEL = "claude-sonnet-4-5"
API_KEY_VARS = ("GITNANNY_API_KEY", "ANTHROPIC_API_KEY")
BASE_URL_VARS = ("GITNANNY_BASE_URL", "ANTHROPIC_BASE_URL")
MODEL_VAR = "GITNANNY_MODEL"

# thinking models burn tokens before the answer; 4096 keeps JSON intact
_MAX_TOKENS = 4096
_TIMEOUT_SECONDS = 120

SYSTEM_PROMPT = """\
You are GitNanny, a meticulous but kind code nanny reviewing a git diff \
before it is pushed to the remote.

Look only at ADDED lines (+). Report:
- likely bugs: logic errors, None-deref risks, off-by-one, wrong operator,
  unhandled exceptions on new code paths;
- security issues: injection (SQL/command), unsafe deserialization, weak
  crypto, SSRF, path traversal — but NOT literal secrets (a separate
  deterministic scanner already covers those);
- maintainability smells worth fixing now: dead code, duplicated blocks,
  misleading names.

Severity rules:
- "critical": would break production or is exploitable;
- "warning": likely a bug or security risk;
- "info": nits and smells.

Be conservative: report only issues you are confident about; do not pad.
At most 15 findings. Line numbers refer to the NEW file version.

Answer with ONLY a JSON array (no prose, no code fences), each element:
{"rule_id": "short-kebab-id", "severity": "critical"|"warning"|"info",
 "file": "<path from the diff>", "line": <int>, "message": "<one sentence>"}

If the diff is clean, answer exactly: []
"""

_USER_TEMPLATE = """\
Review this git diff:

```
{diff}
```
"""

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$")

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "warning": Severity.WARNING,
    "info": Severity.INFO,
}


class AnalyzerError(RuntimeError):
    pass


class LLMResult(NamedTuple):
    findings: tuple[Finding, ...] = ()
    note: str = ""


def get_api_key() -> str | None:
    for var in API_KEY_VARS:
        if os.environ.get(var):
            return os.environ[var]
    return None


def get_base_url() -> str | None:
    for var in BASE_URL_VARS:
        if os.environ.get(var):
            return os.environ[var]
    return None


def parse_llm_json(text: str, diff: DiffResult) -> list[Finding]:
    cleaned = _FENCE_RE.sub("", text.strip())
    start, end = cleaned.find("["), cleaned.rfind("]")
    if start == -1 or end <= start:
        raise AnalyzerError("model did not return a JSON array")
    try:
        items = json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError as exc:
        raise AnalyzerError(f"model returned invalid JSON: {exc}") from exc

    known_files = {f.path for f in diff.files}
    findings: list[Finding] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        file = str(item.get("file", "")).strip()
        if file and known_files and file not in known_files:
            continue
        message = str(item.get("message", "")).strip()
        if not message:
            continue
        severity = _SEVERITY_MAP.get(
            str(item.get("severity", "")).strip().lower(), Severity.WARNING
        )
        try:
            line = max(int(item.get("line", 0)), 0)
        except (TypeError, ValueError):
            line = 0
        findings.append(
            Finding(
                rule_id=str(item.get("rule_id", "llm-review"))[:60] or "llm-review",
                severity=severity,
                file=file,
                line=line,
                message=message,
                source="llm",
            )
        )
    return findings


def analyze_with_llm(
    diff: DiffResult,
    *,
    model: str = DEFAULT_MODEL,
    api_key: str | None = None,
) -> LLMResult:
    # never raises: failures come back as `note` so local rules still run
    if diff.is_empty:
        return LLMResult()
    key = api_key or get_api_key()
    if not key:
        return LLMResult(note="no API key — deep review skipped (set ANTHROPIC_API_KEY)")

    try:
        import anthropic

        client = anthropic.Anthropic(
            api_key=key,
            base_url=get_base_url(),
            timeout=_TIMEOUT_SECONDS,
        )
        response = client.messages.create(
            model=model,
            max_tokens=_MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": _USER_TEMPLATE.format(diff=diff.raw)}],
        )
        text = "".join(b.text for b in response.content if b.type == "text")
        return LLMResult(findings=tuple(parse_llm_json(text, diff)))
    except Exception as exc:
        return LLMResult(note=f"deep review failed: {exc}")
