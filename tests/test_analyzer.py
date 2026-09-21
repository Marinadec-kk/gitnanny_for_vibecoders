from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import pytest

from gitnanny.analyzer import AnalyzerError, analyze_with_llm, parse_llm_json
from gitnanny.diff import parse_added_lines
from gitnanny.models import DiffResult, Severity


def make_diff():
    sample = (
        "diff --git a/app.py b/app.py\n+++ b/app.py\n"
        "@@ -1,1 +1,2 @@\n import os\n+x = 1\n"
    )
    return DiffResult(raw=sample, files=parse_added_lines(sample))


def test_parse_plain_json():
    text = '[{"rule_id": "bug-risk", "severity": "warning", "file": "app.py", "line": 2, "message": "off-by-one"}]'
    findings = parse_llm_json(text, make_diff())
    assert len(findings) == 1
    assert findings[0].severity is Severity.WARNING
    assert findings[0].source == "llm"


def test_parse_fenced_json():
    text = '```json\n[{"rule_id": "r", "severity": "info", "file": "app.py", "line": 2, "message": "nit"}]\n```'
    assert parse_llm_json(text, make_diff())[0].severity is Severity.INFO


def test_parse_prose_wrapped_json():
    text = 'Sure! Here is my review:\n[{"rule_id": "r", "severity": "info", "file": "app.py", "line": 2, "message": "nit"}]\nHope this helps.'
    assert len(parse_llm_json(text, make_diff())) == 1


def test_hallucinated_files_dropped():
    text = '[{"rule_id": "r", "severity": "critical", "file": "not-in-diff.py", "line": 1, "message": "ghost"}]'
    assert parse_llm_json(text, make_diff()) == []


def test_bad_severity_becomes_warning_and_blank_message_skipped():
    text = '[{"rule_id": "r", "severity": "yolo", "file": "app.py", "line": 2, "message": "kept"}, {"rule_id": "r", "severity": "info", "file": "app.py", "line": 2, "message": ""}]'
    findings = parse_llm_json(text, make_diff())
    assert len(findings) == 1
    assert findings[0].severity is Severity.WARNING


@pytest.mark.parametrize("text", ["no json here", "[broken json"])
def test_invalid_payload_raises(text):
    with pytest.raises(AnalyzerError):
        parse_llm_json(text, make_diff())


def test_no_api_key_returns_note(monkeypatch):
    monkeypatch.delenv("GITNANNY_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = analyze_with_llm(make_diff())
    assert result.findings == ()
    assert "ANTHROPIC_API_KEY" in result.note


def test_empty_diff_skips_everything():
    assert analyze_with_llm(DiffResult(raw="", files=()), api_key="k") == ((), "")


def test_analyze_via_stubbed_sdk(monkeypatch):
    payload = '[{"rule_id": "bug-risk", "severity": "critical", "file": "app.py", "line": 2, "message": "div by zero"}]'

    fake = types.ModuleType("anthropic")

    class Messages:
        def create(self, **kwargs):
            assert kwargs["model"] == "test-model"
            return SimpleNamespace(content=[SimpleNamespace(type="text", text=payload)])

    class Anthropic:
        def __init__(self, **kwargs):
            self.messages = Messages()

    fake.Anthropic = Anthropic
    monkeypatch.setitem(sys.modules, "anthropic", fake)

    result = analyze_with_llm(make_diff(), model="test-model", api_key="test")
    assert result.note == ""
    assert result.findings[0].rule_id == "bug-risk"


def test_sdk_failure_degrades_to_note(monkeypatch):
    fake = types.ModuleType("anthropic")

    class Anthropic:
        def __init__(self, **kwargs):
            raise RuntimeError("boom")

    fake.Anthropic = Anthropic
    monkeypatch.setitem(sys.modules, "anthropic", fake)

    result = analyze_with_llm(make_diff(), api_key="test")
    assert result.findings == ()
    assert "boom" in result.note
