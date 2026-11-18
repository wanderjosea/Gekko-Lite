#!/usr/bin/env bash
# Enable/disable the Stop completion-check hook in .claude/settings.json.
# It is a model crutch: useful for weak open-weight models that stop mid-task,
# redundant (and noisy) with Claude. Off by default; flip it on for open models.
#   ./.claude/hooks/toggle-stop-hook.sh on      # activate for open-source models
#   ./.claude/hooks/toggle-stop-hook.sh off     # deactivate (default, for Claude)
#   ./.claude/hooks/toggle-stop-hook.sh status
set -euo pipefail

project_dir="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
settings="$project_dir/.claude/settings.json"

stop_block='[{"hooks":[{"type":"prompt","prompt":"Before allowing this session to stop, review the user'"'"'s latest request and the work performed in this session. Return {\"ok\":true} only if the requested outcome is actually complete and verified. Return {\"ok\":false,\"reason\":\"...\"} if a concrete required step, test, or handoff remains. Do not invent extra scope and do not block merely because optional improvements exist."}]}]'

case "${1:-status}" in
  on)  jq --argjson b "$stop_block" '.hooks.Stop = $b' "$settings" > "$settings.tmp" && mv "$settings.tmp" "$settings"
       echo "Stop hook ON (open-model mode)." ;;
  off) jq 'del(.hooks.Stop)' "$settings" > "$settings.tmp" && mv "$settings.tmp" "$settings"
       echo "Stop hook OFF (Claude mode)." ;;
  status) if jq -e '.hooks.Stop' "$settings" >/dev/null 2>&1; then echo "Stop hook: ON"; else echo "Stop hook: OFF"; fi ;;
  *) echo "usage: $0 on|off|status" >&2; exit 1 ;;
esac
