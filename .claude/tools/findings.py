#!/usr/bin/env python3
"""PenA findings ledger — the auditable spine linking every finding to its evidence.

One JSONL per engagement (engagements/<eng>/findings.jsonl, which is gitignored —
live loot never leaves the repo). Each line is one finding:

  id        auto   F-0001
  title     str    one line
  severity  info | low | medium | high | critical
  status    hypothesis | confirmed | refuted   (the verifier flips it)
  target    str    the authorized in-scope asset this is about
  evidence  {command, artifact, output}        how it was proven; artifact is a
                                                PATH, not inlined secrets
  repro     [str]  ordered steps
  kb        [str]  related .claude/kb slugs
  created / updated  ISO-8601 UTC

The report is a *projection* of this file (`render`), not a hand-assembled doc —
that is what makes "every finding traceable to a command/artifact" mechanical
instead of a promise. finding-analyzer/exploit-developer `add` hypotheses;
finding-verifier's verdict drives `set`; report-writer `render`s the confirmed.

# ponytail: `set` rewrites a line in place instead of event-sourcing status
# changes — status history isn't worth an append log. Upgrade to an event model
# only if an engagement ever needs a full audit trail of who flipped what, when.
"""
from __future__ import annotations
import argparse, json, sys
from datetime import datetime, timezone
from pathlib import Path

SEVERITIES = ["info", "low", "medium", "high", "critical"]
STATUSES = ["hypothesis", "confirmed", "refuted"]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load(ledger: Path) -> list[dict]:
    if not ledger.exists():
        return []
    rows = []
    for i, line in enumerate(ledger.read_text().splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as e:
            sys.exit(f"corrupt ledger {ledger} at line {i}: {e}")
    return rows


def _save(ledger: Path, rows: list[dict]) -> None:
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))


def _next_id(rows: list[dict]) -> str:
    n = 1 + max((int(r["id"].split("-")[1]) for r in rows
                 if str(r.get("id", "")).startswith("F-")), default=0)
    return f"F-{n:04d}"


def cmd_add(a) -> None:
    ledger = Path(a.ledger)
    rows = _load(ledger)
    row = {
        "id": _next_id(rows),
        "title": a.title,
        "severity": a.severity,
        "status": a.status,
        "target": a.target,
        "evidence": {"command": a.command, "artifact": a.artifact, "output": a.output},
        "repro": a.repro or [],
        "kb": a.kb or [],
        "created": _now(),
        "updated": _now(),
    }
    rows.append(row)
    _save(ledger, rows)
    print(row["id"])


def cmd_set(a) -> None:
    ledger = Path(a.ledger)
    rows = _load(ledger)
    for r in rows:
        if r.get("id") == a.id:
            if a.status:
                r["status"] = a.status
            if a.artifact is not None:
                r.setdefault("evidence", {})["artifact"] = a.artifact
            r["updated"] = _now()
            _save(ledger, rows)
            print(f"{a.id} -> {r['status']}")
            return
    sys.exit(f"no finding {a.id} in {ledger}")


def cmd_list(a) -> None:
    rows = _load(Path(a.ledger))
    if a.status:
        rows = [r for r in rows if r.get("status") == a.status]
    for r in rows:
        print(f"{r['id']}  [{r['severity']:>8}]  {r['status']:<10}  {r['title']}")


def cmd_render(a) -> None:
    rows = _load(Path(a.ledger))
    if not a.all:
        rows = [r for r in rows if r.get("status") == "confirmed"]
    rank = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    rows.sort(key=lambda r: rank.get(r.get("severity"), 99))
    print("# Findings\n")
    if not rows:
        print("_No confirmed findings._")
        return
    for r in rows:
        ev = r.get("evidence", {})
        print(f"## {r['id']} — {r['title']}")
        print(f"- **Severity:** {r['severity']} · **Status:** {r['status']} · "
              f"**Target:** {r['target']}")
        if ev.get("command"):
            print(f"- **Command:** `{ev['command']}`")
        if ev.get("artifact"):
            print(f"- **Artifact:** `{ev['artifact']}`")
        if ev.get("output"):
            print("- **Evidence:**\n\n  ```\n  " +
                  ev["output"].replace("\n", "\n  ") + "\n  ```")
        if r.get("repro"):
            print("- **Repro:**")
            for step in r["repro"]:
                print(f"  1. {step}")
        if r.get("kb"):
            print(f"- **KB:** {', '.join(r['kb'])}")
        print()


def cmd_selftest(_a) -> None:
    import tempfile, types, io, contextlib
    led = Path(tempfile.mkdtemp()) / "findings.jsonl"
    ns = lambda **k: types.SimpleNamespace(**k)

    cmd_add(ns(ledger=str(led), title="SQLi in login", severity="high",
               status="hypothesis", target="10.0.0.5",
               command="sqlmap -u http://10.0.0.5/login", artifact="", output="",
               repro=["POST id=1'"], kb=["web-app-attacks"]))
    cmd_add(ns(ledger=str(led), title="Verbose error", severity="low",
               status="hypothesis", target="10.0.0.5",
               command="", artifact="", output="", repro=[], kb=[]))
    assert [r["id"] for r in _load(led)] == ["F-0001", "F-0002"]

    cmd_set(ns(ledger=str(led), id="F-0001", status="confirmed",
               artifact="evidence/dump.txt"))
    r0 = _load(led)[0]
    assert r0["status"] == "confirmed"
    assert r0["evidence"]["artifact"] == "evidence/dump.txt"
    assert r0["updated"] >= r0["created"]

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmd_render(ns(ledger=str(led), all=False))
    out = buf.getvalue()
    assert "F-0001" in out and "F-0002" not in out, out  # render = confirmed only

    led.write_text('{"id":"F-0001"}\nnot-json\n')
    try:
        _load(led)
        raise AssertionError("corrupt line should have exited")
    except SystemExit:
        pass
    print("selftest OK")


def main() -> None:
    p = argparse.ArgumentParser(prog="findings.py", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(required=True)

    a = sub.add_parser("add", help="append a finding")
    a.set_defaults(fn=cmd_add)
    a.add_argument("--ledger", required=True)
    a.add_argument("--title", required=True)
    a.add_argument("--severity", required=True, choices=SEVERITIES)
    a.add_argument("--status", default="hypothesis", choices=STATUSES)
    a.add_argument("--target", required=True)
    a.add_argument("--command", default="")
    a.add_argument("--artifact", default="", help="PATH to evidence, never inline secrets")
    a.add_argument("--output", default="", help="short proof excerpt")
    a.add_argument("--repro", action="append", help="repeatable; one step per flag")
    a.add_argument("--kb", action="append", help="repeatable; related kb slug")

    s = sub.add_parser("set", help="update status/artifact of a finding")
    s.set_defaults(fn=cmd_set)
    s.add_argument("--ledger", required=True)
    s.add_argument("--id", required=True)
    s.add_argument("--status", choices=STATUSES)
    s.add_argument("--artifact")

    l = sub.add_parser("list", help="one line per finding")
    l.set_defaults(fn=cmd_list)
    l.add_argument("--ledger", required=True)
    l.add_argument("--status", choices=STATUSES)

    r = sub.add_parser("render", help="markdown projection (confirmed only unless --all)")
    r.set_defaults(fn=cmd_render)
    r.add_argument("--ledger", required=True)
    r.add_argument("--all", action="store_true")

    sub.add_parser("selftest", help="run built-in asserts").set_defaults(fn=cmd_selftest)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
