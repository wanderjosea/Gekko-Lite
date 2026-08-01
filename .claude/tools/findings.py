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
import argparse, json, re, sys
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
    data = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
    tmp = ledger.with_suffix(ledger.suffix + ".tmp")
    tmp.write_text(data)
    tmp.replace(ledger)  # atomic rename on same fs — never a half-written ledger on crash


def _next_id(rows: list[dict]) -> str:
    nums = [int(m.group(1)) for r in rows
            if (m := re.fullmatch(r"F-(\d+)", str(r.get("id", ""))))]
    return f"F-{max(nums, default=0) + 1:04d}"


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
    hits = [r for r in rows if r.get("id") == a.id]
    if len(hits) != 1:
        sys.exit(f"expected exactly one finding {a.id} in {ledger}, found {len(hits)}")
    r = hits[0]
    if a.status:
        r["status"] = a.status
    if a.artifact is not None:
        r.setdefault("evidence", {})["artifact"] = a.artifact
    r["updated"] = _now()
    _save(ledger, rows)
    print(f"{a.id} -> {r.get('status')}")


def cmd_list(a) -> None:
    rows = _load(Path(a.ledger))
    if a.status:
        rows = [r for r in rows if r.get("status") == a.status]
    for r in rows:
        print(f"{r.get('id','?'):<8}  [{r.get('severity','?'):>8}]  "
              f"{r.get('status','?'):<10}  {r.get('title','(no title)')}")


def _fence(text: str) -> str:
    """A backtick fence longer than any run inside `text`, so an evidence payload
    (which may be untrusted target output) cannot break out of its code block."""
    longest = run = 0
    for ch in text:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    return "`" * max(3, longest + 1)


def _field(label: str, value: str) -> None:
    # inline code normally; if the value carries backticks/newlines, fence it wide
    if "`" in value or "\n" in value:
        f = _fence(value)
        print(f"- **{label}:**\n\n{f}\n{value}\n{f}")
    else:
        print(f"- **{label}:** `{value}`")


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
        ev = r.get("evidence", {}) or {}
        print(f"## {r.get('id','?')} — {r.get('title','(no title)')}")
        print(f"- **Severity:** {r.get('severity','?')} · "
              f"**Status:** {r.get('status','?')} · **Target:** {r.get('target','?')}")
        if ev.get("command"):
            _field("Command", ev["command"])
        if ev.get("artifact"):
            _field("Artifact", ev["artifact"])
        if ev.get("output"):
            f = _fence(ev["output"])
            print(f"- **Evidence:**\n\n{f}\n{ev['output']}\n{f}")
        if r.get("repro"):
            print("- **Repro:**")
            for i, step in enumerate(r["repro"], 1):
                print(f"  {i}. {step}")
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

    # resilience: partial / hand-edited rows must not crash list or render
    _save(led, [{"id": "F-0001", "title": "x", "severity": "high",
                 "status": "confirmed", "target": "t", "evidence": {}},
                {"id": "F-0099"}])
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_list(ns(ledger=str(led), status=None))
        cmd_render(ns(ledger=str(led), all=True))

    # a duplicate id must make `set` refuse rather than flip the wrong finding
    _save(led, [{"id": "F-0001", "status": "hypothesis"},
                {"id": "F-0001", "status": "hypothesis"}])
    try:
        cmd_set(ns(ledger=str(led), id="F-0001", status="confirmed", artifact=None))
        raise AssertionError("duplicate-id set should have exited")
    except SystemExit:
        pass

    # id minting survives non-numeric F- ids in the ledger
    assert _next_id([{"id": "F-"}, {"id": "F-x"}, {"id": "F-0007"}]) == "F-0008"

    # untrusted output with a triple-backtick can't break out of the fence
    _save(led, [{"id": "F-0001", "title": "t", "severity": "high",
                 "status": "confirmed", "target": "t",
                 "evidence": {"output": "```\n# not a heading\n```"}}])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmd_render(ns(ledger=str(led), all=False))
    assert "````" in buf.getvalue()  # fence widened past the payload's backticks

    # atomic save leaves no stray temp file behind
    assert not led.with_suffix(led.suffix + ".tmp").exists()

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
    a.add_argument("--command", default="", help="reproducible command; use placeholders/env vars, never a live secret")
    a.add_argument("--artifact", default="", help="PATH to evidence, never inline secrets")
    a.add_argument("--output", default="", help="short proof excerpt, redacted of secrets/PII")
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
