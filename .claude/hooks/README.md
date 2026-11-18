# Gekko Claude Code hooks

These hooks load from `.claude/settings.json` when Claude Code starts in this
repository. Codex does not run Claude's configuration; its changes remain subject
to `CLAUDE.md`/`AGENTS.md`, the git guards and normal review. There is no Codex
hook guard.

## Protections

- `protect-files.sh` blocks `Edit`/`Write` on `.env*`, lockfiles, `migrations/`,
  `src/legacy/`, `.git/`, `node_modules/`, `vendor/`, `dist/`, `build/` and `.next/`.
- The block exits with code `2`, so Claude receives the reason as feedback and can
  change strategy.
- The hook does not inspect or modify evidence under `engagements/`; that folder is
  protected by `.githooks/pre-commit` and the scope rules.

## Quality

- `format-after-edit.sh` formats JS/TS/CSS/JSON with Prettier when present, Python
  with Ruff and shell with shfmt. They are optional dependencies: if missing, the
  hook does not block the work.
- The `Stop` hook (final completeness review) is a crutch for open-weight models
  that stop halfway; with Claude it is redundant and noisy, so it is **off by
  default**. Toggle it with: `./.claude/hooks/toggle-stop-hook.sh on|off|status`.

These are file-protection and formatting aids, not a security broker.

To validate manually:

```bash
printf '%s\n' '{"tool_input":{"file_path":"'$PWD'/src/legacy/x.js"}}' \
  | .claude/hooks/protect-files.sh; test $? -eq 2
bash -n .claude/hooks/*.sh
python3 -m json.tool .claude/settings.json >/dev/null
```
