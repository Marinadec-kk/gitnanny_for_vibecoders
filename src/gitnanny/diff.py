from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .models import AddedLine, DiffFile, DiffResult

MAX_DIFF_CHARS = 150_000

TARGET_STAGED = "staged"
TARGET_LAST = "last"
TARGET_UNPUSHED = "unpushed"
TARGETS = (TARGET_STAGED, TARGET_LAST, TARGET_UNPUSHED)

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

# hash of git's empty tree: lets us diff the very first commit
_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


class GitError(RuntimeError):
    pass


def run_git(*args: str, cwd: Path | None = None) -> str:
    cmd = ("git", *args)
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=30, check=False
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed") from exc
    if proc.returncode != 0:
        stderr = proc.stderr.strip() or f"exit code {proc.returncode}"
        raise GitError(f"`{' '.join(cmd)}` failed: {stderr}")
    return proc.stdout


def has_unpushed_commits(cwd: Path | None = None) -> bool:
    try:
        ahead = run_git("rev-list", "--count", "@{upstream}..HEAD", cwd=cwd).strip()
    except GitError:
        return False
    return ahead not in ("", "0")


def resolve_base(sha: str) -> str:
    # all-zero sha (branch creation) means: diff against the empty tree
    return _EMPTY_TREE if not sha.strip("0") else sha


def collect_raw_diff(
    target: str = TARGET_UNPUSHED, *, base: str | None = None, cwd: Path | None = None
) -> str:
    if base is not None:
        return run_git("diff", resolve_base(base), "HEAD", "--no-color", cwd=cwd)
    if target == TARGET_STAGED:
        return run_git("diff", "--cached", "--no-color", cwd=cwd)
    if target == TARGET_LAST:
        try:
            return run_git("diff", "HEAD~1", "HEAD", "--no-color", cwd=cwd)
        except GitError:
            return run_git("diff", _EMPTY_TREE, "HEAD", "--no-color", cwd=cwd)
    if target == TARGET_UNPUSHED:
        if not has_unpushed_commits(cwd=cwd):
            return ""
        return run_git("diff", "@{upstream}..HEAD", "--no-color", cwd=cwd)
    raise ValueError(f"unknown target {target!r}; expected one of {TARGETS}")


def parse_added_lines(raw_diff: str) -> tuple[DiffFile, ...]:
    files: list[DiffFile] = []
    path: str | None = None
    lines: list[AddedLine] | None = None
    next_lineno = 0

    def flush() -> None:
        nonlocal path, lines
        if path is not None and lines is not None:
            files.append(DiffFile(path, tuple(lines)))
        path, lines = None, None

    for line in raw_diff.splitlines():
        if line.startswith("+++ b/"):
            flush()
            path, lines = line[len("+++ b/"):], []
        elif line.startswith("@@"):
            m = _HUNK_RE.match(line)
            next_lineno = int(m.group(1)) if m else 1
        elif lines is None:
            continue
        elif line.startswith("+"):
            lines.append(AddedLine(next_lineno, line[1:]))
            next_lineno += 1
        elif not line.startswith("-"):
            next_lineno += 1
    flush()
    return tuple(files)


def get_diff(
    target: str = TARGET_UNPUSHED, *, base: str | None = None, cwd: Path | None = None
) -> DiffResult:
    raw = collect_raw_diff(target=target, base=base, cwd=cwd)
    truncated = len(raw) > MAX_DIFF_CHARS
    if truncated:
        cut = raw.rfind("\n", 0, MAX_DIFF_CHARS)
        raw = raw[: cut if cut > 0 else MAX_DIFF_CHARS]
    return DiffResult(raw=raw, files=parse_added_lines(raw), truncated=truncated)
