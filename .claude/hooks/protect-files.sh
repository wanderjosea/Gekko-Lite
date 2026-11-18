#!/usr/bin/env bash
# Claude Code PreToolUse guard for Edit/Write.
# Reads the hook JSON from stdin and blocks files whose mutation requires an
# explicit human migration/release decision. Exit 2 is intentional: Claude
# receives stderr as corrective feedback and can choose another path.
set -euo pipefail

project_dir="${CLAUDE_PROJECT_DIR:-$(pwd)}"
file_path="$(jq -r '.tool_input.file_path // .tool_input.path // empty' 2>/dev/null || true)"

# Some Claude tool variants do not carry a file path. Do not break unrelated
# tools; the matcher is already restricted to Edit|Write.
[ -n "$file_path" ] || exit 0

case "$file_path" in
  /*) absolute="$file_path" ;;
  *)  absolute="$project_dir/$file_path" ;;
esac

# Normalize only the path text; no filesystem access is needed to decide.
relative="${absolute#"$project_dir"/}"

case "$relative" in
  .git/*|node_modules/*|vendor/*|dist/*|build/*|.next/*|src/legacy/*|*/src/legacy/*|migrations/*|*/migrations/*)
    echo "Gekko protection: editing generated, vendored, legacy, or migration path is blocked: $relative" >&2
    exit 2
    ;;
  .env|.env.*|*/.env|*/.env.*|package-lock.json|pnpm-lock.yaml|yarn.lock|bun.lockb|Cargo.lock|poetry.lock|composer.lock|*/package-lock.json|*/pnpm-lock.yaml|*/yarn.lock|*/bun.lockb|*/Cargo.lock|*/poetry.lock|*/composer.lock)
    echo "Gekko protection: $relative is protected. Use the documented migration/configuration process and obtain explicit operator approval." >&2
    exit 2
    ;;
esac

exit 0
