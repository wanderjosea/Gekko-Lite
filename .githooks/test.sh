#!/usr/bin/env bash
# PenA hook self-test — proves the leak/attribution guards actually block.
# Drives the REAL hooks in this dir against throwaway repos under a temp dir.
# No framework: plain asserts. Run:  .githooks/test.sh   (exit 0 = all green)
#
# Note: secret-shaped decoys are built at runtime so this file itself carries no
# literal token — otherwise committing the test would trip pre-commit's scanner.
set -uo pipefail

HOOKS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
zero='0000000000000000000000000000000000000000'
pass=0 fail=0

# check <desc> <block|allow> <cmd...>  — runs cmd, compares block/allow to its exit
check() {
  local desc="$1" want="$2"; shift 2
  local got=allow
  "$@" >/dev/null 2>&1 || got=block
  if [ "$got" = "$want" ]; then pass=$((pass+1)); printf '  \033[32m✓\033[0m %s\n' "$desc"
  else fail=$((fail+1)); printf '  \033[31m✗\033[0m %s (wanted %s, got %s)\n' "$desc" "$want" "$got"; fi
}

echo "commit-msg (AI attribution):"
m="$TMP/msg"
printf 'Clean subject\n\nnormal body\n'                              >"$m"; check "clean message passes"      allow "$HOOKS/commit-msg" "$m"
printf 'x\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n'       >"$m"; check "Co-Authored-By blocked"     block "$HOOKS/commit-msg" "$m"
printf 'x\n\nGenerated with Claude Code\n'                           >"$m"; check "generated-with blocked"     block "$HOOKS/commit-msg" "$m"

echo "pre-commit (scope + secrets):"
pc="$TMP/pc"; git init -q "$pc"; git -C "$pc" config user.email t@t; git -C "$pc" config user.name t
tok="ghp_$(printf 'A%.0s' $(seq 36))"   # matches gh-token regex; no literal in source
pc_case() { # <desc> <block|allow> <relpath> <content>
  local desc="$1" want="$2" f="$3" content="$4"
  ( cd "$pc" && git reset -q && git clean -fdq && mkdir -p "$(dirname "$f")" \
      && printf '%s' "$content" >"$f" && git add -A ) >/dev/null 2>&1
  check "$desc" "$want" bash -c "cd '$pc' && '$HOOKS/pre-commit'"
}
pc_case "engagements/ staged blocked" block "engagements/loot.txt" "secret loot"
pc_case "*.ovpn staged blocked"       block "client.ovpn"          "remote vpn 1194"
pc_case "gh token staged blocked"     block "config.env"           "TOKEN=$tok"
pc_case "clean file passes"           allow "notes.md"             "just some notes"

echo "pre-push (AI attribution in commits):"
pp="$TMP/pp"; git init -q "$pp"; git -C "$pp" config user.email t@t; git -C "$pp" config user.name t
( cd "$pp"
  echo a >a && git add a && git commit -q -m "clean one"
  git rev-parse HEAD >"$TMP/clean"
  echo b >b && git add b && printf 'bad\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n' | git commit -q -F -
  git rev-parse HEAD >"$TMP/bad"
) >/dev/null 2>&1
push() { echo "refs/heads/main $1 refs/heads/main $zero" | ( cd "$pp" && "$HOOKS/pre-push" ); }
check "push carrying AI-attributed commit blocked" block push "$(cat "$TMP/bad")"
check "push of clean commits passes"                allow push "$(cat "$TMP/clean")"

echo
if [ "$fail" -eq 0 ]; then printf '\033[32mALL GREEN\033[0m — %d checks\n' "$pass"; exit 0
else printf '\033[31mFAILED\033[0m — %d passed, %d failed\n' "$pass" "$fail"; exit 1; fi
