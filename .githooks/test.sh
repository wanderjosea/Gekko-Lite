#!/usr/bin/env bash
# Gekko hook self-test — proves the leak/attribution guards actually block.
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
unset GEKKO_SPEC_UNCHANGED   # the override must not leak in from the caller

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
pc_case "path embedding IPv4 blocked" block "nmap_10.1.2.3"        "nmap scan output"
pc_case "recon capture blocked"       block "scan.nmap"            "host up"
pc_case "root-level html blocked"     block "up1.html"             "<html>capture</html>"
pc_case "nested html passes"          allow "kb/_graph/kb-graph.html" "<html>kb</html>"
# frontera de confianza ↔ spec viva (pc_case stagea 1 archivo; aquí se stagean varios)
pc_multi() { # <desc> <block|allow> <files...>   (env GEKKO_SPEC_UNCHANGED se hereda)
  local desc="$1" want="$2"; shift 2
  ( cd "$pc" && git reset -q && git clean -fdq && for f in "$@"; do mkdir -p "$(dirname "$f")"; echo x >"$f"; done && git add -A ) >/dev/null 2>&1
  check "$desc" "$want" bash -c "cd '$pc' && '$HOOKS/pre-commit'"
}
pc_multi "boundary file alone blocked"            block "toolbox/gekko-guard.ts"
pc_multi "boundary + spec allowed"                allow "toolbox/gekko-guard.ts" "specs/SECURITY-GUARDRAILS-SPEC.md"
GEKKO_SPEC_UNCHANGED=1 pc_multi "boundary alone + GEKKO_SPEC_UNCHANGED allowed" allow "toolbox/gekko-guard.ts"
pc_multi "non-boundary file allowed"              allow "toolbox/other.ts"
# Cases that need history (delete/rename/copy): fresh repo per case, <base> files committed
# with --no-verify, then <change> (shell snippet) is run inside it and everything is staged.
pc_hist() { # <desc> <block|allow> <base files, space-separated> <change snippet>
  local desc="$1" want="$2" base="$3" change="$4" r; r="$(mktemp -d -p "$TMP")"
  ( cd "$r" && git init -q && git config user.email t@t && git config user.name t \
    && for f in $base; do mkdir -p "$(dirname "$f")"; seq 1 40 >"$f"; done \
    && git add -A && git commit -q --no-verify -m base && eval "$change" && git add -A ) >/dev/null 2>&1
  check "$desc" "$want" bash -c "cd '$r' && '$HOOKS/pre-commit'"
}
S=specs/SECURITY-GUARDRAILS-SPEC.md
pc_case "non-ASCII engagements/ path blocked"      block "engagements/cliénte/ñ.txt" "loot"
pc_case "non-ASCII *.ovpn path blocked"            block "ñ/cliente.ovpn"            "remote"
pc_hist "engagements/ deletion allowed"            allow "engagements/a.txt" 'git rm -q engagements/a.txt'
pc_hist "boundary delete without spec blocked"     block "toolbox/gekko-guard.ts" 'git rm -q toolbox/gekko-guard.ts'
pc_hist "boundary rename-out without spec blocked" block "toolbox/gekko-guard.ts" 'git mv toolbox/gekko-guard.ts toolbox/other.ts'
pc_hist "rename into boundary without spec blocked" block "toolbox/other.ts"      'git mv toolbox/other.ts toolbox/gekko-panel.ts'
pc_hist "boundary copy without spec blocked"       block "toolbox/other.ts"       'cp toolbox/other.ts toolbox/shell-session.ts'
pc_hist "boundary type change without spec blocked" block "setup.sh"              'rm setup.sh && ln -s /x setup.sh'
pc_hist "spec delete blocked"                      block "$S"                     "git rm -q $S"
GEKKO_SPEC_UNCHANGED=1 pc_hist "spec delete blocked even with override" block "$S" "git rm -q $S"
GEKKO_SPEC_UNCHANGED=1 pc_hist "spec rename blocked even with override" block "$S" "git mv $S specs/x.md"
pc_hist "rename adding a token blocked"            block "notes.md"               "git mv notes.md n2.md && echo \"T=$tok\" >>n2.md"
GEKKO_SPEC_UNCHANGED=0 pc_multi "override=0 blocked"   block "toolbox/gekko-guard.ts"
GEKKO_SPEC_UNCHANGED=yes pc_multi "override=yes blocked" block "toolbox/gekko-guard.ts"
for b in toolbox/gekko-panel-selftest.ts \
         .claude/tools/findings_web.py tools/report-test.sh tools/toolbox-test.sh; do
  pc_multi "boundary $b alone blocked" block "$b"
done

# tools/report-test.sh de mentira: escribe una marca y sale con el código pedido (nunca el real).
# pc_rt <desc> <block|allow> <exit code|none> <marker: yes|no> <files...>
pc_rt() {
  local desc="$1" want="$2" code="$3" marker="$4" r; shift 4; r="$(mktemp -d -p "$TMP")"
  ( cd "$r" && git init -q && git config user.email t@t && git config user.name t \
    && for f in "$@"; do mkdir -p "$(dirname "$f")"; echo x >"$f"; done \
    && if [ "$code" != none ]; then mkdir -p tools && printf 'touch "%s/ran"\nexit %s\n' "$r" "$code" >tools/report-test.sh; fi \
    && git add -A "$@" ) >/dev/null 2>&1
  check "$desc" "$want" bash -c "cd '$r' && '$HOOKS/pre-commit'"
  if [ "$marker" = yes ]; then check "$desc: el stub corrió" allow test -e "$r/ran"
  else check "$desc: el stub no corrió" block test -e "$r/ran"; fi
}
echo "pre-commit (tools/report-test.sh al tocar ledger/módulo):"
pc_rt "ledger + spec, stub ok allowed"        allow 0    yes .claude/tools/findings.py "$S"
pc_rt "ledger + spec, stub falla blocked"     block 1    yes .claude/tools/findings.py "$S"
pc_rt "módulo + spec, stub falla blocked"     block 1    yes .claude/tools/findings_web.py "$S"
pc_rt "saneador + spec, stub falla blocked"   block 1    yes .claude/tools/sanitize_target_content.py "$S"
pc_rt "ledger + spec, sin stub blocked"       block none no  .claude/tools/findings.py "$S"
pc_rt "archivo ajeno, stub que falla allowed" allow 1    no  notes.md
pc_rt "plantilla sola, stub falla blocked"    block 1    yes .claude/tools/report-templates/x.json
pc_rt "plantilla sola, stub ok allowed"       allow 0    yes .claude/tools/report-templates/x.json
pc_rt "logo solo, stub falla blocked"          block 1    yes .claude/tools/report-templates/marcas/x.png
pc_rt "logo solo, stub ok allowed"             allow 0    yes .claude/tools/report-templates/marcas/x.png

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
