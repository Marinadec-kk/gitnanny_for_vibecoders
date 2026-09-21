from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from . import __version__
from .analyzer import DEFAULT_MODEL, MODEL_VAR, analyze_with_llm
from .diff import GitError, get_diff, has_unpushed_commits, run_git, TARGETS
from .models import DiffResult, Finding, Severity
from .rules import run_local_checks

app = typer.Typer(
    name="gitnanny",
    help="👵 AI-powered nanny that reviews your git diff before you push.",
    no_args_is_help=True,
    add_completion=False,
)
hook_app = typer.Typer(no_args_is_help=True)
app.add_typer(hook_app, name="hook")

console = Console()

HOOK_MARKER = "# installed by gitnanny"
HOOK_SCRIPT = f"""#!/bin/sh
{HOOK_MARKER}
while read local_ref local_sha remote_ref remote_sha; do
  gitnanny check --base "$remote_sha" --quiet || exit 1
done
exit 0
"""

_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
_TARGET_LABELS = {
    "staged": "staged changes",
    "last": "last commit",
    "unpushed": "unpushed commits",
}
_SEVERITY_STYLE = {
    Severity.CRITICAL: ("bold red", "🚨"),
    Severity.WARNING: ("yellow", "⚠️ "),
    Severity.INFO: ("dim blue", "🧹"),
}


def _load_dotenv(path: Path = Path(".env")) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


def _fail(message: str, code: int = 2) -> None:
    console.print(f"[bold red]✗ {message}[/bold red]")
    raise typer.Exit(code)


def _resolve_target(target: str) -> str:
    if target != "auto":
        return target
    return "unpushed" if has_unpushed_commits() else "staged"


def _run_check(
    target: str, base: str | None, use_llm: bool, model: str
) -> tuple[DiffResult, list[Finding], list[str]]:
    diff = get_diff(target=target, base=base)
    if diff.is_empty:
        return diff, [], []
    findings = run_local_checks(diff)
    notes: list[str] = []
    if use_llm:
        llm = analyze_with_llm(diff, model=model)
        findings.extend(llm.findings)
        if llm.note:
            notes.append(llm.note)
    findings.sort(
        key=lambda f: (
            _SEVERITY_ORDER[f.severity],
            f.source != "local",
            f.file,
            f.line,
        )
    )
    return diff, findings, notes


def _finding_text(f: Finding) -> Text:
    style, _ = _SEVERITY_STYLE[f.severity]
    location = f"{f.file}:{f.line}" if f.line else f.file
    text = Text()
    text.append(f"  {location}", style="bold cyan")
    text.append("  ")
    text.append(f.message, style=style if f.severity is Severity.CRITICAL else "")
    if f.snippet:
        text.append("\n    ")
        text.append(f.snippet, style="dim italic")
    text.append("\n    ")
    text.append(f"[{f.rule_id} · {f.source}]", style="dim")
    return text


def _print_outcome(
    diff: DiffResult, findings: list[Finding], notes: list[str], label: str
) -> None:
    title = f"👵 GitNanny checked your {label}"

    if diff.is_empty:
        console.print(Panel(Text("Nothing to nag about — no changes here.", style="green"), title=title))
        return
    if not findings:
        console.print(Panel(Text("✅ Nothing to nag about — push away!", style="bold green"), title=title))
    else:
        console.print()
        console.rule(title)
        console.print()
        for severity in (Severity.CRITICAL, Severity.WARNING, Severity.INFO):
            group = [f for f in findings if f.severity is severity]
            if not group:
                continue
            _, emoji = _SEVERITY_STYLE[severity]
            header = {
                Severity.CRITICAL: "CRITICAL — push blocked",
                Severity.WARNING: "Warnings",
                Severity.INFO: "Nits",
            }[severity]
            console.print(f"{emoji} [bold]{header} ({len(group)})[/bold]")
            console.print()
            for f in group:
                console.print(_finding_text(f))
                console.print()
        console.rule()
        counts = {s: sum(1 for f in findings if f.severity is s) for s in _SEVERITY_ORDER}
        summary = f"{counts[Severity.CRITICAL]} critical · {counts[Severity.WARNING]} warnings · {counts[Severity.INFO]} nits"
        if any(f.severity is Severity.CRITICAL for f in findings):
            console.print(f"[bold red]👵 Nanny says NO:[/bold red] fix the critical items before pushing [dim]({summary})[/dim]")
        else:
            console.print(f"[yellow]👵 Nanny grumbles:[/yellow] nothing fatal, but see above [dim]({summary})[/dim]")

    for note in notes:
        console.print(f"[dim]ℹ️  {note}[/dim]")
    if diff.truncated:
        console.print("[dim]ℹ️  diff was very large and got truncated[/dim]")


def _hook_path() -> Path:
    git_dir = Path(run_git("rev-parse", "--git-dir").strip() or ".git")
    return git_dir.joinpath("hooks", "pre-push").resolve()


@app.command()
def check(
    target: Annotated[
        str,
        typer.Option("--target", "-t", help="What to review: auto (default), staged, last, unpushed."),
    ] = "auto",
    base: Annotated[
        Optional[str],
        typer.Option("--base", help="Diff <sha>..HEAD; used by the pre-push hook."),
    ] = None,
    no_llm: Annotated[
        bool, typer.Option("--no-llm", help="Local rules only, skip the AI deep review.")
    ] = False,
    model: Annotated[
        Optional[str],
        typer.Option("--model", help=f"Model for the deep review ({MODEL_VAR} or claude-sonnet-4-5)."),
    ] = None,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Stay silent when everything is fine.")
    ] = False,
) -> None:
    """Review the diff before it embarrasses you."""
    if target != "auto" and target not in TARGETS:
        _fail(f"unknown target {target!r}, expected one of: auto, {', '.join(TARGETS)}")
    if base and target != "auto":
        _fail("--base and --target are mutually exclusive")
    try:
        model = model or os.environ.get(MODEL_VAR) or DEFAULT_MODEL
        if base:
            label = "new branch" if not base.strip("0") else f"{base[:7]}..HEAD"
        else:
            label = _TARGET_LABELS[_resolve_target(target)]
        diff, findings, notes = _run_check(target, base, not no_llm, model)
    except GitError as exc:
        _fail(f"git problem: {exc}")
        return  # unreachable; keeps type-checkers happy

    if findings or not quiet:
        _print_outcome(diff, findings, notes, label)
    raise typer.Exit(1 if any(f.severity is Severity.CRITICAL for f in findings) else 0)


@hook_app.command("install")
def hook_install(
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Overwrite a foreign pre-push hook.")
    ] = False,
) -> None:
    """Install the pre-push hook into the current repo."""
    try:
        path = _hook_path()
        if path.exists():
            content = path.read_text(encoding="utf-8")
            if HOOK_MARKER not in content and not force:
                raise FileExistsError(f"{path} already exists and is not ours — use --force")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(HOOK_SCRIPT, encoding="utf-8")
        path.chmod(0o755)
    except (FileExistsError, GitError) as exc:
        _fail(str(exc))
    console.print(f"[green]✓[/green] pre-push hook installed: [cyan]{path}[/cyan]")


@hook_app.command("uninstall")
def hook_uninstall() -> None:
    """Remove the gitnanny pre-push hook."""
    try:
        path = _hook_path()
        if path.exists():
            if HOOK_MARKER not in path.read_text(encoding="utf-8"):
                raise PermissionError(f"{path} is not ours — remove it manually")
            path.unlink()
            console.print("[green]✓[/green] pre-push hook removed")
        else:
            console.print("[dim]no gitnanny hook was installed[/dim]")
    except (PermissionError, GitError) as exc:
        _fail(str(exc))


def main() -> None:
    _load_dotenv()
    if len(sys.argv) > 1 and sys.argv[1] in ("--version", "-V"):
        console.print(f"gitnanny {__version__}")
        raise SystemExit(0)
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
