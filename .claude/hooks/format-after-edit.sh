#!/usr/bin/env bash
# Claude Code PostToolUse formatter. Best-effort by design: a missing optional
# formatter must not turn an otherwise valid edit into a failed task.
set -u

project_dir="${CLAUDE_PROJECT_DIR:-$(pwd)}"
file_path="$(jq -r '.tool_input.file_path // .tool_input.path // empty' 2>/dev/null || true)"
[ -n "$file_path" ] || exit 0

case "$file_path" in
  /*) absolute="$file_path" ;;
  *)  absolute="$project_dir/$file_path" ;;
esac
[ -f "$absolute" ] || exit 0

case "$absolute" in
  *.js|*.jsx|*.ts|*.tsx|*.json|*.css|*.scss)
    prettier=""
    if [ -x "$project_dir/frontend/node_modules/.bin/prettier" ]; then
      prettier="$project_dir/frontend/node_modules/.bin/prettier"
    elif [ -x "$project_dir/node_modules/.bin/prettier" ]; then
      prettier="$project_dir/node_modules/.bin/prettier"
    elif command -v prettier >/dev/null 2>&1; then
      prettier="$(command -v prettier)"
    fi
    if [ -n "$prettier" ]; then
      "$prettier" --write "$absolute" >/dev/null 2>&1 || {
        echo "Gekko formatter: prettier failed for $absolute; inspect the edit." >&2
        exit 2
      }
      echo "Gekko formatter: formatted ${absolute#"$project_dir"/}" >&2
    fi
    ;;
  *.py)
    if command -v ruff >/dev/null 2>&1; then
      ruff format "$absolute" >/dev/null 2>&1 || {
        echo "Gekko formatter: ruff format failed for $absolute; inspect the edit." >&2
        exit 2
      }
    fi
    ;;
  *.sh)
    if command -v shfmt >/dev/null 2>&1; then
      shfmt -w "$absolute" >/dev/null 2>&1 || {
        echo "Gekko formatter: shfmt failed for $absolute; inspect the edit." >&2
        exit 2
      }
    fi
    ;;
esac

exit 0
