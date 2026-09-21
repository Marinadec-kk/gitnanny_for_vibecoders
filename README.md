# GitNanny 👵

[![CI](https://github.com/Marinadec-kk/gitnanny_for_vibecoders/actions/workflows/ci.yml/badge.svg)](https://github.com/Marinadec-kk/gitnanny_for_vibecoders/actions/workflows/ci.yml)

AI-powered nanny that reviews your git diff **before you push** — and blocks the push if you're about to leak a key or ship an obvious bug.

```
─────────────────── 👵 GitNanny checked your staged changes ────────────────────

🚨 CRITICAL — push blocked (1)

  db.py:2  user_id is interpolated directly into the SQL string via f-string,
           allowing SQL injection; use a parameterized query instead.
    [sql-injection-fstring · llm]

⚠️  Warnings (2)
  ...
👵 Nanny says NO: fix the critical items before pushing
```

## How it works

Two layers, zero ceremony:

1. **Local rules** — fast offline regex checks (no API key needed): AWS keys,
   GitHub tokens, Google/Slack/OpenAI/Anthropic keys, private keys, JWTs,
   connection strings with passwords, hardcoded credentials, debug leftovers,
   commented-out code. Placeholders (`<your-key>`, `${VAR}`, `XXXX`) are
   recognized and skipped.
2. **AI deep review** — the diff goes to an LLM which reports likely bugs and
   security issues as structured findings. Works with any Anthropic-compatible
   endpoint; degrades gracefully to local-only rules when no key is set.

Exit code `1` when there are critical findings — that's what the pre-push hook
uses to block the push.

## Quick start

```bash
git clone git@github.com:Marinadec-kk/gitnanny_for_vibecoders.git
cd gitnanny_for_vibecoders

uv sync                      # creates .venv from uv.lock
cp .env.example .env         # point the nanny at your model endpoint

uv run gitnanny hook install # arm the nanny for this repo
git push                     # 🚨 blocked if the diff smells
```

The hook must find `gitnanny` on `PATH` — for global use:

```bash
uv tool install .
```

## Commands

| Command | Effect |
|---|---|
| `gitnanny check` | Review what you're about to push (`--target auto\|staged\|last\|unpushed`, `--no-llm`, `--model X`) |
| `gitnanny hook install` | Install the pre-push hook (`--force` overwrites a foreign hook) |
| `gitnanny hook uninstall` | Remove it |
| `gitnanny --version` | … |

## Configuration

Env vars or a `.env` file in the repo root (see `.env.example`):

| Variable | Meaning | Default |
|---|---|---|
| `GITNANNY_API_KEY` | API key for the deep review (`ANTHROPIC_API_KEY` also works) | — (local rules only) |
| `GITNANNY_BASE_URL` | Anthropic-compatible endpoint (`ANTHROPIC_BASE_URL` also works) | `api.anthropic.com` |
| `GITNANNY_MODEL` | Model for the deep review | `claude-sonnet-4-5` |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | clean (or only non-critical findings) |
| 1 | critical findings — push blocked |
| 2 | operational error (not a git repo, bad flag, …) |

## CI

`.github/workflows/ci.yml` runs pytest on Python 3.10–3.13 via uv, plus a
self-check step: GitNanny must block a diff with a leaked AWS key — the tool
dogfoods itself on every push.

## Project layout

```
src/gitnanny/
├── models.py     # data structures shared by every module
├── diff.py       # git plumbing: collect and parse diffs
├── rules.py      # fast offline secret/junk detection
├── analyzer.py   # LLM deep review (Anthropic-compatible APIs)
└── cli.py        # commands, rendering, pre-push hook
tests/            # 27 tests, fully offline
```

## License

AGPL-3.0 — see [LICENSE](LICENSE).
