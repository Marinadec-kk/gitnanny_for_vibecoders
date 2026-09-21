from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class AddedLine:
    lineno: int
    text: str


@dataclass(frozen=True)
class DiffFile:
    path: str
    added_lines: tuple[AddedLine, ...]


@dataclass(frozen=True)
class DiffResult:
    raw: str
    files: tuple[DiffFile, ...]
    truncated: bool = False

    @property
    def is_empty(self) -> bool:
        return not self.files


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    file: str
    line: int
    message: str
    snippet: str = ""
    source: str = "local"
