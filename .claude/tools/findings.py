#!/usr/bin/env python3
"""Gekko findings ledger — the auditable spine linking every finding to its evidence.

One JSONL per engagement (engagements/<eng>/findings.jsonl, which is gitignored —
live loot never leaves the repo). Optional cvss_vector (CVSS:3.1 base; derives cvss)
and cvss_justification live on the row; operator comments live apart, in .gekko-web/ beside it. Each line is one finding:

  id        auto   F-0001
  title     str    one line
  severity  info | low | medium | high | critical
  status    hypothesis | triaged | confirmed | needs_validation | refuted | remediated   (verifier flips; triage gate runs before confirm;
            remediated = fixed and re-tested: only from confirmed, with a retest note)
  retest    str    only on remediated: what was re-tested after the fix and with what result
  blocker   str    only on needs_validation: the exact fact the operator must
                   observe to resolve it (sandbox/paste-back reality)
  target    str    the authorized in-scope asset this is about
  evidence  {command, artifact, output}        how it was proven; artifact is a
                                                PATH, not inlined secrets
  summary / impact / remediation   str   optional, free text
  cvss      number optional, 0.0-10.0
  cwe       str    optional, CWE-<digits>
  cve       str    optional, CVE-<4 digits>-<4+ digits>
  repro     [str]  ordered steps
  kb        [str]  related kb slugs
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
import argparse, base64, errno, fcntl, hashlib, json, math, os, re, secrets, stat, struct, sys, unicodedata, zlib
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

SEVERITIES = ["info", "low", "medium", "high", "critical"]
STATUSES = ["hypothesis", "triaged", "confirmed", "needs_validation", "refuted", "remediated"]
LEDGER_MAX_BYTES = 64 * 2**20  # every read takes the whole ledger; evidence.output is target-derived


class Refusal(SystemExit):
    def __init__(self, kind: str, message: str):
        self.kind = kind
        super().__init__(message)


def fingerprint(row: dict) -> str:
    encoded = json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _reject_constant(name: str) -> None:
    raise ValueError(f"non-standard JSON constant {name}")


def _finite_float(literal: str) -> float:
    number = float(literal)
    if not math.isfinite(number):  # 1e400 parses to inf, which a rewrite would save as `Infinity`
        raise ValueError(f"JSON number out of float range: {literal[:20]}")
    return number


def _scan_bytes(data: bytes) -> tuple[list[tuple[int, dict]], list[tuple[int, str]]]:
    """Parse every non-blank JSONL line from bytes."""
    rows, bad = [], []
    # split on b"\n" only: bytes.splitlines would also cut at \r, \x0b, \x0c, \x1c-\x1e, which the panel does not
    for n, raw in enumerate(data.split(b"\n"), 1):
        raw = raw.removesuffix(b"\r")
        if not raw.strip():
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            bad.append((n, raw.decode("utf-8", errors="replace")))
            continue
        try:
            obj = json.loads(text, parse_constant=_reject_constant, parse_float=_finite_float)
        except (ValueError, RecursionError):  # JSONDecodeError, int over the digit limit, NaN/Infinity, absurd nesting
            bad.append((n, text))
            continue
        (rows if isinstance(obj, dict) else bad).append((n, obj if isinstance(obj, dict) else text))
    return rows, bad


def _read_regular(ledger: Path | str, max_bytes: int, dir_fd: int | None = None) -> tuple[bytes, os.stat_result]:
    """The ledger's bytes and stat, never through a symlink, never blocking on a FIFO, never over max_bytes."""
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
        fd = os.open(ledger, flags, dir_fd=dir_fd) if dir_fd is not None else os.open(ledger, flags)
    except OSError as error:
        if error.errno not in (errno.ELOOP, errno.ENXIO):  # ENXIO: a Unix socket swapped in
            raise
        raise Refusal("not_regular", f"{ledger} is not a regular file") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Refusal("not_regular", f"{ledger} is not a regular file")
        if info.st_size > max_bytes:
            raise Refusal("too_large", f"{ledger} is larger than {max_bytes} bytes")
        chunks, wanted = [], max_bytes + 1  # one byte over the cap catches a file that grew after fstat
        while wanted > 0 and (chunk := os.read(fd, min(wanted, 1 << 20))):
            chunks.append(chunk)
            wanted -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise Refusal("too_large", f"{ledger} is larger than {max_bytes} bytes")
    return data, info


def _scan(ledger: Path, max_bytes: int | None = None) -> tuple[list[tuple[int, dict]], list[tuple[int, str]]]:
    """Every non-blank line as (line_number, dict) or, if invalid, (line_number, text).

    Every read goes through _read_regular: max_bytes from the web module, LEDGER_MAX_BYTES for the CLI."""
    try:
        return _scan_bytes(_read_regular(ledger, LEDGER_MAX_BYTES if max_bytes is None else max_bytes)[0])
    except FileNotFoundError:
        return [], []


def _load(ledger: Path, max_bytes: int | None = None) -> list[dict]:
    rows, bad = _scan(ledger, max_bytes)
    if bad:
        n, text = bad[0]
        raise Refusal("corrupt", f"corrupt ledger {ledger} at line {n}: not a JSON object: {text[:60]!r}")
    return [r for _, r in rows]


@contextmanager
def _locked(ledger: Path):
    # lock the directory, not the file: _save replaces the file by rename, so a file lock
    # would not protect the next process
    ledger.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(ledger.parent, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _default_acl(directory: Path) -> bool:
    """A default ACL marks the toolbox workspace shared with the container (gekko-workspace.ts setfacl)."""
    try:
        return bool(os.getxattr(directory, "system.posix_acl_default"))
    except OSError:
        return False


def _save(ledger: Path, rows: list[dict]) -> None:
    ledger.parent.mkdir(parents=True, exist_ok=True)
    data = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
    tmp = ledger.with_suffix(ledger.suffix + ".tmp")
    tmp.unlink(missing_ok=True)  # a planted symlink is removed, never followed
    try:
        mode = ledger.stat().st_mode & 0o7777
    except FileNotFoundError:
        mode = 0o660 if _default_acl(ledger.parent) else 0o600  # REQ-LED-006: 0600 would zero a toolbox ACL mask
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    # backslashreplace turns a lone surrogate into a \udXXX JSON escape that reads back identical
    with os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace") as f:
        os.fchmod(fd, mode)  # the replacement never widens (or narrows) the ledger's permissions
        f.write(data)
    tmp.replace(ledger)  # atomic rename on same fs — never a half-written ledger on crash


def _blank(value) -> bool:
    """No visible text: control (Cc) and format (Cf: zero-width, bidi) characters count as nothing."""
    return not isinstance(value, str) or not "".join(
        c for c in value if unicodedata.category(c) not in ("Cc", "Cf")).strip()


def _t(value) -> str:
    """A ledger value as text: hand-written rows can hold any JSON type."""
    return "" if value is None else value if isinstance(value, str) else str(value)


_LINE_BREAKS = re.compile("[\r\n\x0b\x0c\x85\u2028\u2029]")


def _oneline(value) -> str:
    return _LINE_BREAKS.sub(" ", _t(value))


def _items(value) -> list[str]:
    return [_t(i) for i in value] if isinstance(value, list) else ([_t(value)] if _t(value) else [])


def _next_id(rows: list[dict]) -> str:
    nums = [int(m.group(1)) for r in rows
            if (m := re.fullmatch(r"F-(\d+)", str(r.get("id", ""))))]
    return f"F-{max(nums, default=0) + 1:04d}"


CVSS_PREFIX = "CVSS:3.1/"
CVSS_VECTOR_MAX = 100
# metric -> its allowed values, in canonical order
CVSS_METRICS = {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "HLN", "I": "HLN", "A": "HLN"}
_CVSS_WEIGHTS = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
                 "PR": {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.5)},  # (scope unchanged, changed)
                 "UI": {"N": 0.85, "R": 0.62}, "CIA": {"H": 0.56, "L": 0.22, "N": 0.0}}
_CVSS_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))


def roundup(x: float) -> float:
    """CVSS v3.1 appendix A: the smallest tenth >= x, immune to float noise like 4.000002."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss31(vector) -> tuple[str, float, str]:
    """(canonical vector, base score, ledger severity of its band) for a CVSS v3.1 base vector, else Refusal("invalid")."""
    def invalid(reason: str) -> Refusal:
        return Refusal("invalid", f"valor inválido para `cvss_vector`: {reason}")

    if not isinstance(vector, str) or len(vector) > CVSS_VECTOR_MAX:
        raise invalid(f"se esperaba texto de hasta {CVSS_VECTOR_MAX} caracteres")
    if not vector.startswith(CVSS_PREFIX):
        raise invalid(f"debe empezar por {CVSS_PREFIX} (sólo v3.1)")
    chosen: dict[str, str] = {}
    for part in vector[len(CVSS_PREFIX):].split("/"):
        metric, _, value = part.partition(":")
        if metric not in CVSS_METRICS or value not in tuple(CVSS_METRICS[metric]) or metric in chosen:
            raise invalid(f"`{part}` no es una métrica base v3.1 válida o está repetida")
        chosen[metric] = value
    if len(chosen) != len(CVSS_METRICS):
        raise invalid(f"faltan métricas base: {', '.join(m for m in CVSS_METRICS if m not in chosen)}")
    weights, changed = _CVSS_WEIGHTS, chosen["S"] == "C"
    iss = 1 - (1 - weights["CIA"][chosen["C"]]) * (1 - weights["CIA"][chosen["I"]]) * (1 - weights["CIA"][chosen["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = (8.22 * weights["AV"][chosen["AV"]] * weights["AC"][chosen["AC"]]
                      * weights["PR"][chosen["PR"]][changed] * weights["UI"][chosen["UI"]])
    score = 0.0 if impact <= 0 else roundup(min((1.08 if changed else 1.0) * (impact + exploitability), 10.0))
    band = next((name for floor, name in _CVSS_BANDS if score >= floor), "info")
    return CVSS_PREFIX + "/".join(f"{m}:{chosen[m]}" for m in CVSS_METRICS), score, band


TEXT_FIELDS = ("summary", "impact", "remediation")
FORMAT_FIELDS = {"cwe": re.compile(r"CWE-[0-9]+"), "cve": re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")}
DROPPABLE_FIELDS = (*TEXT_FIELDS, *FORMAT_FIELDS)  # the only keys set_row(drop=) may remove (REQ-LED-007)
NARRATIVE_FIELDS = (*DROPPABLE_FIELDS, "cvss_vector", "cvss_justification")
EDIT_FIELDS = frozenset(NARRATIVE_FIELDS)  # what the web edit form may write (spec 019)


def validate_field(name: str, value: str) -> str:
    """The one rule for a narrative field, shared by the CLI and the web; returns the value to store
    (unchanged, except a CVSS vector, which comes back canonical)."""
    if name == "cvss_vector":
        return cvss31(value)[0]
    if name in (*TEXT_FIELDS, "cvss_justification"):
        if _blank(value):
            raise Refusal("invalid", f"valor inválido para `{name}`: debe tener algún carácter visible")
    elif name in FORMAT_FIELDS:
        if not isinstance(value, str) or not FORMAT_FIELDS[name].fullmatch(value):
            raise Refusal("invalid", f"valor inválido para `{name}` {value!r}: se esperaba {FORMAT_FIELDS[name].pattern}")
    else:
        raise Refusal("invalid", f"`{name}` no es un campo de redacción")
    return value


def _optional_fields(a) -> dict:
    """The optional fields the caller passed, validated; exits naming the bad field."""
    out = {}
    for name in TEXT_FIELDS:
        if getattr(a, name, None) is not None:
            out[name] = validate_field(name, getattr(a, name))
    cvss = getattr(a, "cvss", None)
    if cvss is not None:
        try:
            score = float(cvss)
        except ValueError:
            score = float("nan")
        if not 0.0 <= score <= 10.0:  # also false for nan
            sys.exit(f"invalid cvss {cvss!r}: expected a number from 0.0 to 10.0")
        out["cvss"] = score
    for name in FORMAT_FIELDS:
        if getattr(a, name, None) is not None:
            out[name] = validate_field(name, getattr(a, name))
    if getattr(a, "cvss_vector", None) is not None:
        out["cvss_vector"] = validate_field("cvss_vector", a.cvss_vector)
        derived = cvss31(out["cvss_vector"])[1]
        if "cvss" in out and out["cvss"] != derived:
            sys.exit(f"invalid cvss {cvss!r}: the vector {out['cvss_vector']} scores {derived}")
        out["cvss"] = derived
    if getattr(a, "cvss_justification", None) is not None:
        out["cvss_justification"] = validate_field("cvss_justification", a.cvss_justification)
    return out


def cvss_check(changes: dict):
    """The check for set_row: a new vector whose band is not the row's severity needs a visible justification
    (in the change or already on the row). The severity itself is never written (spec 019 D5)."""
    def check(row: dict) -> None:
        if "cvss_vector" not in changes:
            stored = row.get("cvss_vector")
            if "cvss" in changes and isinstance(stored, str):
                try:
                    derived = cvss31(stored)[1]
                except Refusal:  # a hand-written vector that does not parse derives nothing to contradict
                    return
                if changes["cvss"] != derived:
                    raise Refusal("invalid", f"invalid cvss {changes['cvss']!r}: the row's vector {stored} scores {derived}")
            return
        band = cvss31(changes["cvss_vector"])[2]
        justification = changes.get("cvss_justification", row.get("cvss_justification"))
        if band != row.get("severity") and _blank(justification):
            raise Refusal("needs_justification", f"la banda del vector es {band} y la severidad del hallazgo es "
                          f"{_t(row.get('severity'))}: escribe una justificación (cvss_justification)")
    return check


def cmd_add(a) -> None:
    ledger = Path(a.ledger)
    if a.status in ("confirmed", "needs_validation", "remediated"):
        sys.exit(f"refusing to add a finding as {a.status}: add it as a hypothesis and use "
                 f"`set` (which demands --corroboration / --blocker / --retest)")
    extra = _optional_fields(a)
    cvss_check(extra)({"severity": a.severity})
    with _locked(ledger):
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
            **extra,
            "created": _now(),
            "updated": _now(),
        }
        rows.append(row)
        _save(ledger, rows)
    print(row["id"])


def set_row(ledger: Path, fid: str, *, status=None, corroboration=None, blocker=None, extra=None,
            artifact=None, expect=None, max_bytes=None, drop: tuple[str, ...] = (), check=None,
            retest=None) -> tuple[str | None, dict]:
    extra = extra or {}
    if drop and (expect is None or not set(drop) <= set(DROPPABLE_FIELDS)):
        # only a row the caller saw loses a key, and only a narrative one (REQ-LED-007)
        raise Refusal("invalid", f"cannot drop {', '.join(drop)}: only narrative fields, and only with an expected fingerprint")
    with _locked(ledger):
        rows = _load(ledger, max_bytes)
        hits = [r for r in rows if r.get("id") == fid]
        if len(hits) != 1:
            raise Refusal("not_unique", f"expected exactly one finding {fid} in {ledger}, found {len(hits)}")
        r = hits[0]
        previous = r.get("status")
        if expect is not None and fingerprint(r) != expect:
            raise Refusal("stale", f"finding {fid} changed since it was displayed")
        if not _blank(corroboration):
            r["corroboration"] = corroboration
        if not _blank(blocker):
            r["blocker"] = blocker
        # §13 / style.md — corroboration is the bar. A finding cannot enter a deliverable
        # as `confirmed` on a single signal: the ledger REFUSES the flip unless an
        # independent second signal is recorded on the row. This is a mechanical guardrail,
        # not a prompt hint — it holds even if a model claims "confirmed" after one uid=33.
        if status == "confirmed" and _blank(r.get("corroboration")):
            raise Refusal("no_corroboration",
                f"refusing to confirm {fid} on a single signal: pass --corroboration "
                f"describing the independent second signal that agrees (style.md: a single "
                f"positive is a lead, corroboration makes it a finding)"
            )
        # needs_validation is the sandbox/paste-back state: the vector is understood but
        # blocked on a fact only the operator can observe. It carries the EXACT blocker so
        # the finding is actionable, not a vague "TODO" — mirror the corroboration guardrail.
        if status == "needs_validation" and _blank(r.get("blocker")):
            raise Refusal("no_blocker",
                f"refusing to mark {fid} needs_validation without a blocker: pass --blocker "
                f"naming the exact fact the operator must observe to resolve it"
            )
        # remediated (REQ-LED-011): only a confirmed row is fixed and re-tested, and the note is of THIS call
        # (an old one from an earlier cycle does not count); the corroboration that confirmed it still stands.
        if status == "remediated":
            if previous not in ("confirmed", "remediated"):
                raise Refusal("not_confirmed", f"refusing to mark {fid} remediated: only a confirmed finding can be (it is {previous})")
            if previous != "remediated" and _blank(retest):
                raise Refusal("no_retest", f"refusing to mark {fid} remediated without a retest note: pass --retest "
                                           f"saying what was re-tested after the fix and with what result")
            if _blank(r.get("corroboration")):
                raise Refusal("no_corroboration", f"refusing to mark {fid} remediated without corroboration: pass --corroboration")
            if not _blank(retest):
                r["retest"] = retest
        if check:
            check(r)  # under the lock, so a rule about the row (the severity) has no window
        r.update(extra)  # mutating rows is safe: every refusal above exits before _save
        for key in drop:
            r.pop(key, None)
        if status:
            r["status"] = status
        if artifact is not None:
            r.setdefault("evidence", {})["artifact"] = artifact
        r["updated"] = _now()
        _save(ledger, rows)
    return previous, r


def set_fields(ledger: Path, line: int, changes: dict, expect: str, max_bytes: int, *, allowed: frozenset) -> dict:
    """Write narrative fields of the row on physical `line` (None drops one); returns the saved row.

    The lock is taken by set_row, which compares `expect` with the row of that id: a line that moved
    to another row since it was shown fails as `stale`."""
    extra: dict = {}
    for name, value in changes.items():
        if name not in allowed or name not in NARRATIVE_FIELDS:
            raise Refusal("invalid", f"`{name}` no se puede escribir por aquí")
        if value is not None:
            extra[name] = validate_field(name, value)
    if "cvss_vector" in extra:
        extra["cvss"] = cvss31(extra["cvss_vector"])[1]  # the score is derived, never taken from the caller
    rows, _ = _scan(ledger, max_bytes)
    row = dict(rows).get(line)
    fid = row.get("id") if row else None
    if not isinstance(fid, str) or not fid:
        raise Refusal("not_unique", f"no finding with a usable id on line {line} of {ledger}")
    _, saved = set_row(ledger, fid, extra=extra, drop=tuple(k for k, v in changes.items() if v is None), expect=expect,
                       max_bytes=max_bytes, check=cvss_check(extra))
    return saved


def owner_ok(st_uid: int, euid: int, ws_uid: int) -> bool:
    """What the module and the CLI share under a workspace may belong to the effective user or to the workspace's
    owner: the toolbox container runs as root while the module runs as the operator."""
    return st_uid in (euid, ws_uid)


def _hand_over(fd: int, ws_uid: int, ws_gid: int) -> None:
    """A root process gives what it creates to the workspace's owner, so the operator's module can read it."""
    if os.geteuid() == 0 and ws_uid != 0:
        try:
            os.fchown(fd, ws_uid, ws_gid)
        except OSError as error:
            raise Refusal("not_regular", f"cannot hand a new file over to the workspace's owner: {error.strerror}") from error


def _web_parent(workspace: Path, parts: tuple[str, ...], create: bool) -> tuple[int, int, int]:
    """(fd of the directory holding parts[-1], workspace uid, workspace gid), walked by dir_fd with O_NOFOLLOW so no
    component is a followed link. Directories made here are 0700 and the workspace owner's."""
    directory = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    dir_fd = os.open(workspace, directory)
    try:
        info = os.fstat(dir_fd)
        for part in parts[:-1]:
            created = False
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=dir_fd)
                    created = True
                except FileExistsError:
                    pass
            next_fd = os.open(part, directory, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
            if created:
                _hand_over(dir_fd, info.st_uid, info.st_gid)
            elif not owner_ok(os.fstat(dir_fd).st_uid, os.geteuid(), info.st_uid):
                raise Refusal("not_regular", f"{part} belongs to neither the effective user nor the workspace's owner")
        return dir_fd, info.st_uid, info.st_gid
    except BaseException:
        os.close(dir_fd)
        raise


def web_open(workspace: Path, parts: tuple[str, ...], flags: int) -> int:
    """Open workspace/<parts> for the report module and the CLI: never through a symlink, never blocking on a FIFO,
    only a regular file (REQ-RPT-034). With O_DIRECTORY, open the directory itself. Missing directories are made 0700
    when `flags` has O_CREAT; the file is born 0600. What is created is the workspace owner's; what exists must be
    owned by the effective user or the workspace's owner."""
    try:
        if flags & os.O_DIRECTORY:
            return _web_parent(workspace, (*parts, ""), bool(flags & os.O_CREAT))[0]
        dir_fd, ws_uid, ws_gid = _web_parent(workspace, parts, bool(flags & os.O_CREAT))
        try:
            try:  # look before opening: a planted device node, FIFO or socket is never opened (the fstat below stays for a swap after this)
                if not stat.S_ISREG(os.stat(parts[-1], dir_fd=dir_fd, follow_symlinks=False).st_mode):
                    raise Refusal("not_regular", f"{workspace / Path(*parts)} is not a regular file")
            except FileNotFoundError:
                pass
            fd, created = _open_last(dir_fd, parts[-1], flags)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise Refusal("not_regular", f"{workspace / Path(*parts)} is not a regular file")
                if created:
                    _hand_over(fd, ws_uid, ws_gid)
                elif not owner_ok(info.st_uid, os.geteuid(), ws_uid):
                    raise Refusal("not_regular", f"{workspace / Path(*parts)} belongs to neither the effective user nor the workspace's owner")
            except BaseException:
                os.close(fd)
                if created:
                    os.unlink(parts[-1], dir_fd=dir_fd)
                raise
            return fd
        finally:
            os.close(dir_fd)
    except OSError as error:
        if error.errno not in (errno.ELOOP, errno.ENXIO, errno.ENOTDIR):  # a link, a FIFO without reader, a swapped directory
            raise
        raise Refusal("not_regular", f"{workspace / Path(*parts)} is not reachable without following a link") from error


def _open_last(dir_fd: int, name: str, flags: int) -> tuple[int, bool]:
    """(fd, whether this call created the file). O_EXCL tells a file we made from one that was there; a caller that
    passes it itself wants FileExistsError, not the existing file."""
    safe = flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
    if flags & os.O_CREAT:
        if flags & os.O_EXCL:
            return os.open(name, safe, 0o600, dir_fd=dir_fd), True
        try:
            return os.open(name, safe | os.O_EXCL, 0o600, dir_fd=dir_fd), True
        except FileExistsError:  # also a planted link: the open below meets it without O_CREAT and refuses it
            pass
    return os.open(name, safe & ~os.O_CREAT, 0o600, dir_fd=dir_fd), False


def web_unlink(workspace: Path, parts: tuple[str, ...]) -> None:
    """Remove workspace/<parts>: a link is removed as a link, its target is never touched."""
    try:
        dir_fd = _web_parent(workspace, parts, False)[0]
    except OSError as error:
        if error.errno not in (errno.ELOOP, errno.ENOTDIR):
            raise
        raise Refusal("not_regular", f"{workspace} is not reachable without following a link") from error
    try:
        os.unlink(parts[-1], dir_fd=dir_fd)
    finally:
        os.close(dir_fd)


# ---------------------------------------------------------------- operator comments (spec 019): an append-only file of events

COMMENTS_PARTS = (".gekko-web", "comentarios.jsonl")
COMMENT_MAX_BYTES = 8192
COMMENTS_MAX_BYTES = 2**20
COMMENT_ID = re.compile(r"C-[0-9a-f]{16}")
COMMENT_CHANNELS = ("web", "cli")


def comments_path(ledger: Path) -> Path:
    return ledger.parent.joinpath(*COMMENTS_PARTS)


def validate_comment(text) -> str:
    """The one rule for a comment's text, shared by the CLI and the web; never trims."""
    if _blank(text):
        raise Refusal("invalid", "comentario inválido: debe tener algún carácter visible")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise Refusal("invalid", "comentario inválido: no es UTF-8 válido") from error
    if size > COMMENT_MAX_BYTES:
        raise Refusal("invalid", f"comentario inválido: {size} bytes; el máximo es {COMMENT_MAX_BYTES} bytes y no se recorta")
    return text


def _read_all(fd: int, max_bytes: int) -> bytes:
    chunks, offset = [], 0
    while offset <= max_bytes and (chunk := os.pread(fd, max_bytes + 1 - offset, offset)):  # one byte over the cap is enough to refuse
        chunks.append(chunk)
        offset += len(chunk)
    if offset > max_bytes:
        raise Refusal("too_large", f"el archivo de comentarios supera {max_bytes} bytes")
    return b"".join(chunks)


def _apply_comment_event(raw: bytes, states: dict[str, dict]) -> None:
    """Fold one event line into `states`; ValueError names why the line is bad."""
    try:
        event = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError) as error:
        raise ValueError("no es JSON en UTF-8") from error
    if not isinstance(event, dict):
        raise ValueError("no es un objeto")
    op, finding, cid, at, via, prev = (event.get(k) for k in ("op", "finding", "comment", "at", "via", "prev"))
    if (event.get("v") != 1 or op not in ("add", "edit", "delete") or not isinstance(finding, str) or not finding
            or not isinstance(cid, str) or not COMMENT_ID.fullmatch(cid) or not isinstance(at, str)
            or via not in COMMENT_CHANNELS or not isinstance(prev, str)):
        raise ValueError("campos inválidos")
    try:
        finding.encode("utf-8")
    except UnicodeEncodeError as error:  # an edit or delete would copy it into a new line it cannot encode
        raise ValueError("campos inválidos") from error
    digest = hashlib.sha256(raw).hexdigest()
    if op == "add":
        if cid in states or prev:
            raise ValueError("alta repetida o con prev")
        text = _comment_text(event)
        images = _comment_images(event)
        if images is not None and not images:
            raise ValueError("imágenes inválidas")
        states[cid] = {"id": cid, "finding": finding, "text": text, "origin": text, "created": at, "edited": "", "via": via,
                       "images": images or [], "origin_images": images or [], "last": digest, "deleted": False}
        return
    state = states.get(cid)
    if state is None or state["deleted"] or state["finding"] != finding or prev != state["last"]:
        raise ValueError("comentario inexistente, borrado o cadena prev rota")
    if op == "edit":
        text, images = _comment_text(event), _comment_images(event)
        state.update(text=text, edited=at, via=via, **({} if images is None else {"images": images}))
    else:
        state["deleted"] = True
    state["last"] = digest


def _comment_images(event: dict) -> list[str] | None:
    """The `images` of an add/edit event: None when absent, else 0..8 distinct sha256 strings; ValueError otherwise."""
    if "images" not in event:
        return None
    images = event["images"]
    if (not isinstance(images, list) or len(images) > ROW_MAX_IMAGES or len(set(map(str, images))) != len(images)
            or not all(isinstance(h, str) and SHA_RE.fullmatch(h) for h in images)):
        raise ValueError("imágenes inválidas")
    return images


def _comment_text(event: dict) -> str:
    try:
        return validate_comment(event.get("text"))
    except Refusal as error:
        raise ValueError(str(error)) from error


def _fold_comments(data: bytes) -> tuple[dict[str, dict], list[tuple[int, str]]]:
    """(every comment by id in creation order, the bad lines as (number, reason))."""
    states: dict[str, dict] = {}
    bad: list[tuple[int, str]] = []
    *lines, unterminated = data.split(b"\n")
    for number, raw in enumerate(lines, 1):
        try:
            _apply_comment_event(raw, states)
        except ValueError as error:
            bad.append((number, str(error)))
    if unterminated:
        bad.append((len(lines) + 1, "línea final sin salto de línea"))
    return states, bad


def read_comments_state(ledger: Path, max_bytes: int | None = None) -> tuple[dict[str, list[dict]], list[tuple[int, str]], int]:
    """(live comments by finding id, in creation order; bad lines; the file's size, which only ever grows, so it names its state).
    Never follows a link; Refusal when over max_bytes."""
    try:
        fd = web_open(ledger.parent, COMMENTS_PARTS, os.O_RDONLY)
    except FileNotFoundError:
        return {}, [], 0
    try:
        data = _read_all(fd, COMMENTS_MAX_BYTES if max_bytes is None else max_bytes)
    finally:
        os.close(fd)
    states, bad = _fold_comments(data)
    visible: dict[str, list[dict]] = {}
    for state in states.values():
        if not state["deleted"]:
            visible.setdefault(state["finding"], []).append({k: v for k, v in state.items() if k not in ("deleted", "origin", "origin_images")})
    return visible, bad, len(data)


def read_comments(ledger: Path, max_bytes: int | None = None) -> tuple[dict[str, list[dict]], list[tuple[int, str]]]:
    return read_comments_state(ledger, max_bytes)[:2]


def _comment_append(ledger: Path, create: bool, decide, before_write=None) -> None:
    """Under an exclusive lock on the comments file: fold it, append the event (or list of events) `decide(states)` returns (None:
    nothing). `before_write()` runs once the file is known to take the line and before it is written (so a refusal leaves no side effect)."""
    try:
        fd = web_open(ledger.parent, COMMENTS_PARTS, os.O_RDWR | os.O_APPEND | (os.O_CREAT if create else 0))
    except FileNotFoundError as error:
        raise Refusal("not_found", "no existe ese comentario") from error
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)  # the file is only appended to, never replaced, so this lock holds across processes
        data = _read_all(fd, COMMENTS_MAX_BYTES)
        states, bad = _fold_comments(data)
        if bad:
            raise Refusal("corrupt", f"comentarios corruptos: línea {bad[0][0]} ({bad[0][1]}); no se escribió nada")
        event = decide(states)
        if event is None:
            return
        events = event if isinstance(event, list) else [event]
        line = memoryview("".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in events).encode("utf-8"))
        if len(data) + len(line) > COMMENTS_MAX_BYTES:
            raise Refusal("full", f"el archivo de comentarios está lleno (máximo {COMMENTS_MAX_BYTES} bytes); no se escribió nada")
        if before_write:
            before_write()
        while line:
            line = line[os.write(fd, line):]
    finally:
        os.close(fd)


def _check_channel(via: str) -> None:
    if via not in COMMENT_CHANNELS:
        raise Refusal("invalid", f"canal inválido {via!r}: debe ser uno de {', '.join(COMMENT_CHANNELS)}")


def _live_comment(states: dict[str, dict], cid: str, expect: str | None) -> dict:
    state = states.get(cid)
    if state is None or state["deleted"]:
        raise Refusal("not_found", "no existe ese comentario")
    if expect is not None and expect != state["last"]:
        raise Refusal("stale", "el comentario cambió desde que se mostró; no se escribió nada")
    return state


def comment_add(ledger: Path, fid: str, text: str, via: str, comment_id: str | None = None, max_bytes: int | None = None,
                images=(), choose=()) -> str:
    """Add a comment to the finding `fid` (it must appear exactly once), optionally with images: `choose` are hashes of the
    workspace's gallery, `images` new ones from prepare_images (stored only if the comment is written). Sending the same id,
    text and images again (a double submit) writes nothing; the same id with other text or images is stale."""
    validate_comment(text)
    _check_channel(via)
    if comment_id is not None and not COMMENT_ID.fullmatch(comment_id):
        raise Refusal("invalid", "id de comentario inválido")
    try:
        fid.encode("utf-8")
    except UnicodeEncodeError as error:  # json.dumps(ensure_ascii=False) could not write it
        raise Refusal("invalid", "id de hallazgo inválido: no es UTF-8 válido") from error
    rows, bad = _scan(ledger, max_bytes)
    if bad or sum(1 for _, row in rows if row.get("id") == fid) != 1:
        raise Refusal("not_unique", f"expected exactly one finding {fid} in {ledger}")
    cid = comment_id or "C-" + secrets.token_hex(8)
    wanted = list(dict.fromkeys([*choose, *(i.sha256 for i in images)]))

    def decide(states: dict[str, dict]):
        if cid in states:
            if states[cid]["finding"] != fid or states[cid]["origin"] != text or states[cid]["origin_images"] != wanted:
                raise Refusal("stale", "ese id de comentario ya existe con otro texto o imágenes; no se escribió nada")
            return None
        return {"v": 1, "op": "add", "finding": fid, "comment": cid, "text": text, "at": _now(), "via": via, "prev": "",
                **({"images": wanted} if wanted else {})}

    if not wanted:
        _comment_append(ledger, True, decide)
        return cid
    workspace = ledger.parent
    with _locked(ledger):  # ledger lock first, then the comments file's (the order gallery_delete uses too)
        gallery = read_gallery(workspace)
        if gallery.error or gallery.bad:
            raise Refusal("gallery_state", "el índice de Adjuntos está roto o lleno; no se escribió nada")
        if not all(isinstance(h, str) and h in gallery.live for h in choose):
            raise Refusal("not_in_gallery", "una imagen elegida no está en Adjuntos")
        if len(wanted) > ROW_MAX_IMAGES:
            raise Refusal("limit", f"un comentario admite {ROW_MAX_IMAGES} imágenes; no se escribió nada")
        _comment_append(ledger, True, decide, lambda: _store_images(workspace, list(images), gallery))
    return cid


def comment_edit(ledger: Path, cid: str, text: str, via: str, expect: str | None = None) -> None:
    validate_comment(text)
    _check_channel(via)

    def decide(states: dict[str, dict]):
        state = _live_comment(states, cid, expect)
        return {"v": 1, "op": "edit", "finding": state["finding"], "comment": cid, "text": text, "at": _now(), "via": via, "prev": state["last"]}

    _comment_append(ledger, False, decide)


def comment_delete(ledger: Path, cid: str, via: str, expect: str | None = None) -> None:
    """A tombstone: the comment leaves the fold, its text stays in the file until the engagement's retention."""
    _check_channel(via)

    def decide(states: dict[str, dict]):
        state = _live_comment(states, cid, expect)
        return {"v": 1, "op": "delete", "finding": state["finding"], "comment": cid, "at": _now(), "via": via, "prev": state["last"]}

    _comment_append(ledger, False, decide)


def cmd_comment_add(a) -> None:
    print(comment_add(Path(a.ledger), a.id, a.text, "cli"))


def cmd_comment_edit(a) -> None:
    comment_edit(Path(a.ledger), a.comment, a.text, "cli")


def cmd_comment_delete(a) -> None:
    comment_delete(Path(a.ledger), a.comment, "cli")


def cmd_comment_list(a) -> None:
    visible, bad = read_comments(Path(a.ledger))
    if bad:
        sys.exit(f"comentarios corruptos: línea {bad[0][0]} ({bad[0][1]})")
    for fid, comments in visible.items():
        if a.id in (None, fid):
            for c in comments:  # the file may be hostile: every printed field loses its control and format characters
                clean = lambda v: "".join(ch for ch in _oneline(v) if unicodedata.category(ch) not in ("Cc", "Cf"))
                print(f"{clean(c['id'])}  {clean(fid)}  {clean(c['created'])}  {clean(c['via'])}  {clean(c['text'])}")


# ---------------------------------------------------------------- image gallery (spec 023a): evidencia/<sha256>.(png|jpg) + an append-only index

SHA_RE = re.compile(r"[0-9a-f]{64}")
IMAGE_EXT = {"image/png": "png", "image/jpeg": "jpg"}
GALLERY_INDEX = ("evidencia", "galeria.jsonl")
GALLERY_INDEX_MAX_BYTES = 2**20
GALLERY_IMAGE_MAX_BYTES = 5 * 2**20
GALLERY_MAX_SIDE = 16384
GALLERY_MAX_PIXELS = 50_000_000
UPLOAD_MAX_FILES, ROW_MAX_IMAGES, GALLERY_MAX_LIVE = 4, 8, 200
_GALLERY_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
_ALTA_KEYS = {"evento", "sha256", "type", "bytes", "metadatos", "added", "via"}
_BAJA_KEYS = {"evento", "sha256", "at", "via", "hallazgos"}
_BAJA_OPTIONAL = {"archivo", "comentarios"}


class Prepared(NamedTuple):
    sha256: str
    mime: str
    data: bytes
    metadata: bool


class Entry(NamedTuple):
    sha256: str
    mime: str
    bytes: int
    added: str
    metadata: bool


class Gallery(NamedTuple):
    live: dict
    bad: list
    digest: str
    error: str
    size: int = 0


def image_name(sha: str, mime: str) -> str:
    """The only way a file name is built; anything that is not a lowercase sha256 and a known type opens nothing."""
    if not (isinstance(sha, str) and SHA_RE.fullmatch(sha) and mime in IMAGE_EXT):
        raise Refusal("not_found", "no existe esa imagen")
    return f"{sha}.{IMAGE_EXT[mime]}"


def prepare_images(blobs: list[bytes]) -> list[Prepared]:
    """Validate every upload by content before anything is written; one bad file refuses all."""
    if len(blobs) > UPLOAD_MAX_FILES:
        raise Refusal("limit", f"más de {UPLOAD_MAX_FILES} archivos por envío; no se guardó nada")
    prepared: dict[str, Prepared] = {}
    for number, data in enumerate(blobs, 1):
        try:
            if not data:
                _image_refusal("0 bytes")
            mime, width, height = validate_image(data, GALLERY_IMAGE_MAX_BYTES, GALLERY_MAX_SIDE)
            if width * height > GALLERY_MAX_PIXELS:
                _image_refusal("más de 50 megapíxeles")
        except Refusal as error:
            raise Refusal("invalid_image", f"archivo {number} de {len(blobs)}: {error}; no se guardó nada") from error
        sha = hashlib.sha256(data).hexdigest()
        prepared.setdefault(sha, Prepared(sha, mime, data, strip_image_metadata(data, GALLERY_IMAGE_MAX_BYTES, GALLERY_MAX_SIDE) != data))
    return list(prepared.values())


def _fold_gallery(data: bytes) -> tuple[dict, list]:
    """(live entries by sha256 in upload order, bad lines as (number, reason))."""
    live: dict[str, Entry] = {}
    bad: list[tuple[int, str]] = []
    *lines, unterminated = data.split(b"\n")
    for number, raw in enumerate(lines, 1):
        try:
            event = json.loads(raw.decode("utf-8"))
            if not isinstance(event, dict):
                raise ValueError("no es un objeto")
            sha = event.get("sha256")
            if not (isinstance(sha, str) and SHA_RE.fullmatch(sha)):
                raise ValueError("sha256 inválido")
            if event.get("evento") == "alta" and set(event) == _ALTA_KEYS:
                size = event["bytes"]
                if (sha in live or event["type"] not in IMAGE_EXT or event["via"] != "web" or type(size) is not int
                        or not 1 <= size <= GALLERY_IMAGE_MAX_BYTES or type(event["metadatos"]) is not bool
                        or not (isinstance(event["added"], str) and _GALLERY_TIME.fullmatch(event["added"]))):
                    raise ValueError("alta inválida")
                live[sha] = Entry(sha, event["type"], size, event["added"], event["metadatos"])
            elif (event.get("evento") == "baja" and set(event) - _BAJA_OPTIONAL == _BAJA_KEYS and event.get("archivo", "ausente") == "ausente"
                    and (not isinstance(event.get("comentarios", []), list) or all(isinstance(i, str) for i in event.get("comentarios", [])))
                    and isinstance(event.get("comentarios", []), list) and event["via"] == "web" and isinstance(event["at"], str) and _GALLERY_TIME.fullmatch(event["at"])
                    and isinstance(event["hallazgos"], list) and all(isinstance(i, str) for i in event["hallazgos"]) and sha in live):
                del live[sha]
            else:
                raise ValueError("evento inválido")
        except (ValueError, RecursionError) as error:
            bad.append((number, str(error)))
    if unterminated:
        bad.append((len(lines) + 1, "línea final sin salto de línea"))
    return live, bad


def _read_index(workspace: Path) -> bytes:
    try:
        fd = web_open(workspace, GALLERY_INDEX, os.O_RDONLY)
    except FileNotFoundError:
        return b""
    try:
        return _read_all(fd, GALLERY_INDEX_MAX_BYTES)
    except Refusal as error:
        raise Refusal("gallery_state", f"el índice de Adjuntos supera {GALLERY_INDEX_MAX_BYTES} bytes") from error
    finally:
        os.close(fd)


def read_gallery(workspace: Path) -> Gallery:
    """Never writes and never raises: a broken index comes back as `bad` or `error` (writes refuse then)."""
    try:
        data = _read_index(workspace)
    except Refusal as error:
        return Gallery({}, [], "", str(error))
    live, bad = _fold_gallery(data)
    return Gallery(live, bad, hashlib.sha256(data).hexdigest(), "", len(data))


def row_shots(row: dict) -> list | None:
    """The capture records of a row, or None when `evidence` or its `screenshots` is malformed (hand/model-written)."""
    evidence = row.get("evidence", {})
    shots = evidence.get("screenshots", []) if isinstance(evidence, dict) else None
    if isinstance(shots, list) and all(isinstance(x, dict) and isinstance(x.get("sha256"), str) for x in shots):
        return shots
    return None


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def read_image(workspace: Path, entry: Entry, *, validate: bool = False) -> bytes:
    """The bytes of a live entry, re-hashed on every call; validate also re-checks them as the entry's own type."""
    name = image_name(entry.sha256, entry.mime)
    try:
        data = _read_file(workspace, ("evidencia", name))
        if hashlib.sha256(data).hexdigest() != entry.sha256:
            raise Refusal("gallery_state", "")
        if validate and validate_image(data, GALLERY_IMAGE_MAX_BYTES, GALLERY_MAX_SIDE)[0] != entry.mime:
            raise Refusal("gallery_state", "")
    except (FileNotFoundError, Refusal) as error:
        raise Refusal("gallery_state", f"imagen ausente o alterada: {entry.sha256}") from error
    return data


def _store_images(workspace: Path, images, gallery: Gallery) -> list[Entry]:
    """Under the lock: write each new image once (O_EXCL), then append every alta in one write."""
    if gallery.error or gallery.bad:
        raise Refusal("gallery_state", "el índice de Adjuntos está roto o lleno; no se escribió nada")
    new = [i for i in images if i.sha256 not in gallery.live]
    if len(gallery.live) + len(new) > GALLERY_MAX_LIVE:
        raise Refusal("limit", f"Adjuntos admite {GALLERY_MAX_LIVE} imágenes; no se guardó nada")
    events = [{"evento": "alta", "sha256": i.sha256, "type": i.mime, "bytes": len(i.data), "metadatos": i.metadata, "added": _now(), "via": "web"}
              for i in new]
    line = "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events).encode()
    if gallery.size + len(line) > GALLERY_INDEX_MAX_BYTES:
        raise Refusal("gallery_state", "Adjuntos está lleno; no se escribió nada")
    for image in new:
        parts = ("evidencia", image_name(image.sha256, image.mime))
        try:
            fd = web_open(workspace, parts, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        except FileExistsError:  # planted or left by a cut: reuse it only if it is these very bytes
            try:
                if hashlib.sha256(_read_file(workspace, parts)).hexdigest() != image.sha256:
                    raise Refusal("gallery_state", f"ya existe {parts[1]} con otros bytes; no se escribió nada")
            except FileNotFoundError as error:
                raise Refusal("gallery_state", "el archivo cambió mientras se guardaba") from error
        else:
            try:
                _write_all(fd, image.data)
            except BaseException:
                os.close(fd)
                web_unlink(workspace, parts)  # a half-written file would block this hash for good
                raise
            os.close(fd)
    if line:
        _append_index(workspace, line)
    added = {e["sha256"]: Entry(e["sha256"], e["type"], e["bytes"], e["added"], e["metadatos"]) for e in events}
    return [gallery.live.get(i.sha256) or added[i.sha256] for i in images]


def _append_index(workspace: Path, line: bytes) -> None:
    fd = web_open(workspace, GALLERY_INDEX, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
    try:
        _write_all(fd, line)
    finally:
        os.close(fd)


def _read_file(workspace: Path, parts: tuple[str, ...]) -> bytes:
    fd = web_open(workspace, parts, os.O_RDONLY)
    try:
        return _read_all(fd, GALLERY_IMAGE_MAX_BYTES)
    finally:
        os.close(fd)


def gallery_upload(ledger: Path, images) -> list[Entry]:
    """Store validated images (from prepare_images) in the workspace's gallery; an image already there is not rewritten."""
    workspace = ledger.parent
    with _locked(ledger):
        return _store_images(workspace, images, read_gallery(workspace))


def delete_stamp(ledger_digest: str, gallery_digest: str, comments_size: int = 0) -> str:
    """What a delete form saw: the ledger's and the index's bytes, and the size of the comments file (it only grows, so its size
    names its state; omitted when 0, so a workspace without comments keeps the stamp of before). Any change makes the delete stale."""
    return hashlib.sha256(f"{ledger_digest}\n{gallery_digest}{f'{chr(10)}{comments_size}' if comments_size > 0 else ''}".encode()).hexdigest()


def gallery_delete(ledger: Path, sha: str, ext: str, *, expect: str, confirm: bool, max_bytes: int | None = None) -> dict:
    """Delete one image from the gallery. Order: rows lose their record, the index gains a baja, the file is unlinked, so a
    failure leaves at most an unused image or a file already given up, never a row pointing at a deleted file."""
    workspace = ledger.parent
    if not (isinstance(sha, str) and SHA_RE.fullmatch(sha)):
        raise Refusal("not_found", "no existe esa imagen")
    with _locked(ledger):
        try:
            data = _read_regular(ledger, LEDGER_MAX_BYTES if max_bytes is None else max_bytes)[0]
        except FileNotFoundError:
            data = b""
        scanned, bad = _scan_bytes(data)
        if bad:
            raise Refusal("corrupt", f"ledger corrupto en la línea {bad[0][0]}; no se escribió nada")
        gallery = read_gallery(workspace)
        if gallery.error or gallery.bad:
            raise Refusal("gallery_state", "el índice de Adjuntos está roto o lleno; no se escribió nada")
        try:
            visible, comments_bad, comments_size = read_comments_state(ledger)
        except Refusal as error:
            raise Refusal("comments_state", "el archivo de comentarios está roto o lleno; no se escribió nada") from error
        if comments_bad:
            raise Refusal("comments_state", "el archivo de comentarios está roto o lleno; no se escribió nada")
        if delete_stamp(hashlib.sha256(data).hexdigest(), gallery.digest, comments_size) != expect:
            raise Refusal("stale", "los hallazgos o Adjuntos cambiaron desde que se mostró; no se escribió nada")
        if not confirm:
            raise Refusal("no_confirm", "falta confirmar el borrado")
        entry = gallery.live.get(sha)
        if entry is None or IMAGE_EXT[entry.mime] != ext:
            raise Refusal("not_found", "no existe esa imagen")
        rows = [r for _, r in scanned]
        affected = [r for r in rows if any(x["sha256"] == sha for x in row_shots(r) or [])]
        ids = [r.get("id") for r in affected]
        if any(not isinstance(i, str) or sum(1 for r in rows if r.get("id") == i) != 1 for i in ids):
            raise Refusal("not_unique", "un hallazgo con esa imagen no tiene id único; no se escribió nada")
        missing = False
        try:
            if hashlib.sha256(_read_file(workspace, ("evidencia", image_name(sha, entry.mime)))).hexdigest() != sha:
                raise Refusal("gallery_state", f"imagen alterada: no se borra ({sha})")
        except FileNotFoundError:
            missing = True
        used: list[str] = []

        def decide(states: dict[str, dict]):  # rebuilt under the comments lock: the live comments that show this image now
            events = [{"v": 1, "op": "edit", "finding": c["finding"], "comment": c["id"], "text": c["text"], "at": _now(), "via": "web",
                       "prev": c["last"], "images": [h for h in c["images"] if h != sha]}
                      for c in states.values() if not c["deleted"] and sha in c["images"]]
            used[:] = [e["comment"] for e in events]
            return events or None

        has_comments = comments_size > 0
        # the baja is sized before (b) from the comments that show the image now: decide can only find a subset, so the real line is shorter
        maybe = [c["id"] for cs in visible.values() for c in cs if sha in c.get("images", [])]
        event = {"evento": "baja", "sha256": sha, "at": _now(), "via": "web", "hallazgos": ids,
                 **({"comentarios": maybe} if maybe else {}), **({"archivo": "ausente"} if missing else {})}
        if gallery.size + len(json.dumps(event, separators=(",", ":")).encode()) + 1 > GALLERY_INDEX_MAX_BYTES:
            raise Refusal("gallery_state", "Adjuntos está lleno; no se escribió nada")
        if has_comments:  # (b) first, so a full or broken comments file refuses with nothing written
            try:
                _comment_append(ledger, False, decide)
            except Refusal as error:
                if error.kind in ("corrupt", "full", "too_large"):
                    raise Refusal("comments_state", "el archivo de comentarios está roto o lleno; no se escribió nada") from error
                raise
        if used != maybe:
            event.pop("comentarios", None)
            event.update({"comentarios": list(used)} if used else {})
        line = (json.dumps(event, separators=(",", ":")) + "\n").encode()
        for r in affected:
            r["evidence"]["screenshots"] = [x for x in r["evidence"]["screenshots"] if x["sha256"] != sha]
            r["updated"] = _now()
        if affected:
            _save(ledger, rows)
        _append_index(workspace, line)
        if not missing:
            web_unlink(workspace, ("evidencia", image_name(sha, entry.mime)))
    return {"sha256": sha, "hallazgos": ids, "archivo": "ausente" if missing else "borrado"}


def set_evidence(ledger: Path, fid: str, *, status=None, corroboration=None, blocker=None, expect=None, max_bytes=None,
                 images=(), choose=(), remove=(), retest=None) -> tuple[str | None, dict]:
    """set_row plus the row's screenshots: attach images (from the gallery by sha256, or new from prepare_images) and
    remove some, all under set_row's lock and after its rules, so a refusal writes nothing, not even an image."""
    workspace = ledger.parent
    choose, remove = list(dict.fromkeys(choose)), set(remove)

    def commit(r: dict) -> None:
        evidence, shots = r.get("evidence", {}), row_shots(r)
        if shots is None:
            raise Refusal("evidence_not_object", f"{fid}: evidence o evidence.screenshots no tiene la forma esperada; no se escribió nada")
        attached = [x["sha256"] for x in shots]
        if not remove <= set(attached):
            raise Refusal("not_attached", "esa imagen no está adjunta a este hallazgo")
        if remove & set(choose):
            raise Refusal("conflict", "una imagen no puede elegirse y quitarse a la vez")
        if not (choose or images):
            r["evidence"] = {**evidence, "screenshots": [x for x in shots if x["sha256"] not in remove]} if remove else evidence
            return
        gallery = read_gallery(workspace)
        if gallery.error or gallery.bad:
            raise Refusal("gallery_state", "el índice de Adjuntos está roto o lleno; no se escribió nada")
        if not all(isinstance(h, str) and h in gallery.live for h in choose):
            raise Refusal("not_in_gallery", "una imagen elegida no está en Adjuntos")
        wanted = list(dict.fromkeys([*choose, *(i.sha256 for i in images)]))
        if set(wanted) & set(attached) - remove:
            raise Refusal("already_attached", "esa imagen ya está adjunta a este hallazgo")
        if len(attached) - len(remove) + len(wanted) > ROW_MAX_IMAGES:
            raise Refusal("limit", f"un hallazgo admite {ROW_MAX_IMAGES} imágenes; no se escribió nada")
        entries = {e.sha256: e for e in _store_images(workspace, list(images), gallery)}
        entries.update({h: gallery.live[h] for h in choose})
        now, estado = _now(), status or r.get("status")
        new = [{"sha256": h, "type": entries[h].mime, "estado": estado, "added": now, "via": "web"} for h in wanted]
        r["evidence"] = {**evidence, "screenshots": [x for x in shots if x["sha256"] not in remove] + new}

    return set_row(ledger, fid, status=status, corroboration=corroboration, blocker=blocker, expect=expect, max_bytes=max_bytes, check=commit,
                   retest=retest)


def cmd_set(a) -> None:
    extra = _optional_fields(a)
    _, row = set_row(Path(a.ledger), a.id, status=a.status,
                     corroboration=getattr(a, "corroboration", None), blocker=getattr(a, "blocker", None),
                     retest=getattr(a, "retest", None), extra=extra, artifact=getattr(a, "artifact", None), check=cvss_check(extra))
    print(f"{a.id} -> {row.get('status')}")


def cmd_list(a) -> None:
    rows = _load(Path(a.ledger))
    if a.status:
        rows = [r for r in rows if r.get("status") == a.status]
    for r in rows:
        print(f"{_oneline(r.get('id', '?')):<8}  [{_oneline(r.get('severity', '?')):>8}]  "
              f"{_oneline(r.get('status', '?')):<10}  {_oneline(r.get('title', '(no title)'))}")


def _fence(text: str) -> str:
    """A backtick fence longer than any run inside `text`, so an evidence payload
    (which may be untrusted target output) cannot break out of its code block."""
    longest = run = 0
    for ch in text:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    return "`" * max(3, longest + 1)


# A CommonMark code span: a backtick run closed by the next run of the same length (selftests strip
# them to see the Markdown a viewer would parse outside the values).
_CODE_SPAN = re.compile(r"(?<!`)(`+)(?!`)(.*?)(?<!`)\1(?!`)")


LABELS = {
    "en": {"severity": "Severity", "status": "Status", "target": "Target", "summary": "Summary",
           "impact": "Impact", "remediation": "Remediation", "cvss": "CVSS", "cwe": "CWE", "cve": "CVE",
           "corroboration": "Corroboration", "blocker": "Blocker", "command": "Command", "artifact": "Artifact",
           "evidence": "Evidence", "repro": "Repro", "retest": "Retest", "empty": "_No confirmed findings._",
           "cvss_vector": "CVSS vector", "cvss_justification": "CVSS justification",
           "technical": "Technical report", "executive": "Executive report", "by_severity": "Findings by severity",
           "findings": "Findings", "id": "ID", "title": "Title", "client": "Client", "period": "Period",
           "version": "Version", "author": "Author", "classification": "Classification", "scope": "Scope",
           "methodology": "Methodology", "limitations": "Limitations", "recommendations": "Recommendations"},
    "es": {"severity": "Severidad", "status": "Estado", "target": "Objetivo", "summary": "Resumen",
           "impact": "Impacto", "remediation": "Remediación", "cvss": "CVSS", "cwe": "CWE", "cve": "CVE",
           "corroboration": "Corroboración", "blocker": "Bloqueo", "command": "Comando", "artifact": "Artefacto",
           "evidence": "Evidencia", "repro": "Repro", "retest": "Nueva prueba", "empty": "_No hay hallazgos confirmados._",
           "cvss_vector": "Vector CVSS", "cvss_justification": "Justificación CVSS",
           "technical": "Reporte técnico", "executive": "Reporte ejecutivo", "by_severity": "Hallazgos por severidad",
           "findings": "Hallazgos", "id": "ID", "title": "Título", "client": "Cliente", "period": "Período",
           "version": "Versión", "author": "Autor", "classification": "Clasificación", "scope": "Alcance",
           "methodology": "Metodología", "limitations": "Limitaciones", "recommendations": "Recomendaciones"},
}


def included(rows: list[dict], show_all: bool = False) -> list[dict]:
    # open confirmed rows first, then remediated ones (corroborated and with a retest note); each group by severity
    selected = [r for r in rows if show_all or
                (not _blank(r.get("corroboration")) and (r.get("status") == "confirmed"
                 or r.get("status") == "remediated" and not _blank(r.get("retest"))))]
    rank = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    return sorted(selected, key=lambda r: (r.get("status") == "remediated", rank.get(r.get("severity"), 99)
                  if isinstance(r.get("severity"), str) else 99))


def _code(value: str) -> str:
    """One-line `value` as one inline code span. Code over escaping: CommonMark shows span content
    literally (no HTML, image, link, autolink or emphasis) and only an equal backtick run closes it."""
    tick = "`" * (max(map(len, re.findall("`+", value)), default=0) + 1)
    pad = " " if not value or "`" in (value[0], value[-1]) else ""  # CommonMark strips this one space
    return f"{tick}{pad}{value}{pad}{tick}"


def _field(label: str, value: str) -> list[str]:
    # inline code normally; if the value carries backticks/newlines, fence it wide
    if "`" in value or _LINE_BREAKS.search(value):
        f = _fence(value)
        return [f"- **{label}:**", "", f, value, f]
    return [f"- **{label}:** `{value}`"]


def report_fields(row: dict, lang: str = "en", keys=None) -> tuple[str, str, list[tuple[str, str, str]]]:
    if lang not in LABELS:
        raise ValueError(f"unsupported language: {lang}")
    labels = LABELS[lang]
    ev = row.get("evidence")
    ev = ev if isinstance(ev, dict) else {"output": ev}
    wanted = set(_FINDING_FIELDS if keys is None else keys)
    fields = []
    for key in ("summary", "impact", "remediation", "cvss", "cvss_vector", "cvss_justification", "cwe", "cve"):
        if key in wanted and row.get(key) is not None:
            fields.append(("campo", labels[key], _t(row[key])))
    blocker = None if row.get("status") in ("confirmed", "remediated") else row.get("blocker")  # a confirmed row's blocker is history
    retest = row.get("retest") if row.get("status") == "remediated" else None  # always shown for a remediated row, whatever `keys`
    for key, value in (("corroboration", row.get("corroboration")), ("retest", retest), ("blocker", blocker),
                       ("command", ev.get("command")), ("artifact", ev.get("artifact"))):
        if (key in wanted or key == "retest") and _t(value):
            fields.append(("campo", labels[key], _t(value)))
    if "evidence.output" in wanted and _t(ev.get("output")):
        fields.append(("bloque", labels["evidence"], _t(ev["output"])))
    if "repro" in wanted and _items(row.get("repro")):
        fields.extend(("pasos", labels["repro"], _oneline(step)) for step in _items(row["repro"]))
    return (_oneline(row.get("id", "?")), _oneline(row.get("title", "(no title)")), fields)


def _md_finding(lines: list[str], row: dict, lang: str, heading: str, local: bool, keys=None) -> None:
    """One finding as Markdown under `heading`; `local` shows severity/status in the report language (render_report)."""
    labels = LABELS[lang]
    shown = (lambda kind, v: loc(lang, kind, v)) if local else (lambda kind, v: _oneline(v))
    finding_id, title, fields = report_fields(row, lang, keys)
    lines.extend([f"{heading} {_code(finding_id)} — {_code(title)}",
                  f"- **{labels['severity']}:** {_code(shown('sev', row.get('severity', '?')))} · "
                  f"**{labels['status']}:** {_code(shown('status', row.get('status', '?')))} · "
                  f"**{labels['target']}:** {_code(_oneline(row.get('target', '?')))}"])
    steps_started = False
    step_number = 0
    for kind, label, value in fields:
        if kind == "campo":
            lines.extend(_field(label, value))
        elif kind == "bloque":
            fence = _fence(value)
            lines.extend([f"- **{label}:**", "", fence, value, fence])
        else:  # "pasos"
            if not steps_started:
                lines.append(f"- **{label}:**")
                steps_started = True
            step_number += 1
            lines.append(f"  {step_number}. {_code(value)}")
    lines.append("")


def _md_short(lines: list[str], row: dict, lang: str, keys) -> None:
    """Compact finding card; only non-blank selected narrative fields follow its title and severity."""
    labels = LABELS[lang]
    lines += [f"### {_code(_oneline(row.get('id', '?')))} — {_code(_oneline(row.get('title', '(no title)')))}",
              f"- **{labels['severity']}:** {_code(loc(lang, 'sev', row.get('severity', '?')))}"]
    _, _, fields = report_fields(row, lang, keys)
    for _, label, value in fields:
        if not _blank(value):
            lines += _field(label, value)
    lines.append("")


def render_md(rows: list[dict], lang: str = "en", show_all: bool = False) -> str:
    if lang not in LABELS:
        raise ValueError(f"unsupported language: {lang}")
    labels = LABELS[lang]
    rows = included(rows, show_all)
    lines = ["# Findings", ""]
    if not rows:
        return "\n".join([*lines, labels["empty"], ""])
    fixed = [r for r in rows if r.get("status") == "remediated"]
    for row in rows:
        if row.get("status") == "remediated" and row is fixed[0]:
            lines += [f"**{DOC[lang]['remediated']} ({len(fixed)})**", ""]
        _md_finding(lines, row, lang, "##", False)
    return "\n".join(lines) + "\n"


# Operator drafts for the report (spec 019b): presentation text, never evidence.
_COMMON_DRAFT = ("titulo", "cliente", "periodo", "version", "autor", "clasificacion", "resumen", "alcance")
DRAFT_FIELDS = {"tecnico": (*_COMMON_DRAFT, "metodologia", "limitaciones", "recomendaciones"),
                "ejecutivo": (*_COMMON_DRAFT, "limitaciones", "recomendaciones")}
ONE_LINE = ("titulo", "cliente", "periodo", "version", "autor", "clasificacion")
DRAFT_FIELD_MAX = 4096
DRAFT_MAX_BYTES = 6 * 11 * DRAFT_FIELD_MAX + DRAFT_FIELD_MAX  # worst JSON escape is 6 bytes per byte
_PROSE = {"resumen": "summary", "alcance": "scope", "metodologia": "methodology", "limitaciones": "limitations",
          "recomendaciones": "recommendations"}


def _template_map(plantillas=None):
    return load_templates()[0] if plantillas is None else plantillas


def validate_draft(tipo: str, data: bytes, plantillas=None) -> dict:
    """The draft's fields, or Refusal("invalid_draft") naming the one at fault; never trims or fixes."""
    templates = _template_map(plantillas)
    if tipo not in templates:
        raise Refusal("invalid_draft", f"plantilla desconocida o inválida {tipo!r}: válidas: {', '.join(templates)}")
    try:
        obj = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError) as error:
        raise Refusal("invalid_draft", f"el borrador no es JSON UTF-8 válido: {error}") from error
    if not isinstance(obj, dict):
        raise Refusal("invalid_draft", "el borrador debe ser un objeto JSON")
    for key, value in obj.items():
        if key not in templates[tipo].datos["borrador"]:
            raise Refusal("invalid_draft", f"{key!r}: no es un campo del borrador {tipo}")
        if not isinstance(value, str):
            raise Refusal("invalid_draft", f"{key}: debe ser texto")
        try:
            size = len(value.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise Refusal("invalid_draft", f"{key}: no es texto UTF-8 válido") from error
        if size > DRAFT_FIELD_MAX:
            raise Refusal("invalid_draft", f"{key}: como máximo {DRAFT_FIELD_MAX} bytes (tiene {size})")
        if key in ONE_LINE and _LINE_BREAKS.search(value):
            raise Refusal("invalid_draft", f"{key}: debe ser una sola línea")
    return obj


# The document's own wording (spec 019 UI-r3): cover, defaults and the severity/status names a client reads.
_SEV = {"es": {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja", "info": "Informativa"},
        "en": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational"}}
DOC = {
    "es": {"eyebrow": {"tecnico": "Informe técnico", "ejecutivo": "Informe ejecutivo"},
           "subtitle": {"tecnico": "Informe técnico de pentesting", "ejecutivo": "Informe ejecutivo de pentesting"},
           "title": "Evaluación de seguridad", "client": "Cliente no definido", "author": "GEKKO Offensive Security",
           "period": "Pendiente de definir", "version": "0.1 · Borrador", "class": "CONFIDENCIAL · BORRADOR",
           "for": "Preparado para", "by": "Preparado por", "period_l": "Período de evaluación", "version_l": "Versión",
           "notice": "Documento sujeto a revisión. Los hallazgos no confirmados no se incluyen.",
           "summary": "Resumen ejecutivo",
           "tiles": {"critical": "Críticas", "high": "Altas", "medium": "Medias", "low": "Bajas"},
           "remediated": "Remediados",
           "sev": _SEV["es"], "status": {"hypothesis": "Hipótesis", "triaged": "Triado", "confirmed": "Confirmado",
                                         "needs_validation": "Por validar", "refuted": "Refutado", "remediated": "Remediado"}},
    "en": {"eyebrow": {"tecnico": "Technical report", "ejecutivo": "Executive report"},
           "subtitle": {"tecnico": "Technical penetration testing report", "ejecutivo": "Executive penetration testing report"},
           "title": "Security assessment", "client": "Client not defined", "author": "GEKKO Offensive Security",
           "period": "To be defined", "version": "0.1 · Draft", "class": "CONFIDENTIAL · DRAFT",
           "for": "Prepared for", "by": "Prepared by", "period_l": "Assessment period", "version_l": "Version",
           "notice": "Document subject to review. Unconfirmed findings are not included.",
           "summary": "Executive summary",
           "tiles": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"},
           "remediated": "Remediated",
           "sev": _SEV["en"], "status": {"hypothesis": "Hypothesis", "triaged": "Triaged", "confirmed": "Confirmed",
                                         "needs_validation": "Needs validation", "refuted": "Refuted", "remediated": "Remediated"}},
}


def loc(lang: str, kind: str, value) -> str:
    """A severity/status as the document names it; anything unknown stays as written (and is escaped by its renderer)."""
    one = _oneline(value)
    return DOC[lang][kind].get(one, one)


TEMPLATES_DIR = Path(__file__).resolve().parent / "report-templates"
TEMPLATE_MAX_BYTES = 16384
TEMPLATES_MAX = 16
DEFAULT_TEMPLATE = "tecnico"
BUILTIN = ("tecnico", "ejecutivo")
DRAFT_KEYS = ("titulo", "cliente", "periodo", "version", "autor", "clasificacion", "resumen", "alcance", "metodologia", "limitaciones", "recomendaciones")
ACCENTS = {"grafito": None, "lima": ("#3b6600", "#3b6600", None), "verde": ("#14724a", "#14724a", None),
           "azul": ("#1f6aa0", "#1f6aa0", None), "ambar": ("#8a6410", "#8a6410", None),
           "lima-claro": ("#799a17", None, "#eef8d0"), "verde-claro": ("#4ba063", None, "#e3f6e8"),
           "azul-claro": ("#4c96c7", None, "#e4f3fd"), "ambar-claro": ("#b58737", None, "#fff4d6"),
           "gris-claro": ("#87918b", None, "#eef1ef")}
_SLUG = re.compile(r"[a-z][a-z0-9-]{0,23}\Z")
_LABEL_PUNCT = set(" ,;:()¿?¡!'·«»-–—")
_TEMPLATE_FIELDS = ("antetitulo", "subtitulo", "titulo", "cliente", "autor", "periodo", "version", "clasificacion")
_FINDING_FIELDS = ("summary", "impact", "remediation", "cvss", "cvss_vector", "cvss_justification", "cwe", "cve", "corroboration", "blocker", "command", "artifact", "evidence.output", "repro")


class Marca(NamedTuple):
    nombre: str
    logo: str
    archivo: str
    mime: str
    limpio: bytes
    sha256: str
    pie: dict | None
    color: str | None


class Plantilla(NamedTuple):
    nombre: str
    sha256: str
    datos: dict
    marca: Marca | None = None


IMAGE_MAX_BYTES = 262144
IMAGE_MAX_SIDE = 2048
IMAGE_TYPES = ("image/png", "image/jpeg")
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _template_error(nombre: str, clave: str, motivo: str) -> Refusal:
    safe_name = repr(f"{nombre}.json")
    return Refusal("invalid_template", f"Plantilla {safe_name}: {clave}: {motivo}")


def _image_refusal(reason: str):
    raise Refusal("invalid_image", reason)


def _png_image(data: bytes, max_side: int):
    if not data.startswith(_PNG_SIGNATURE):
        _image_refusal("firma PNG inválida")
    pos, width, height, color, palette_entries = len(_PNG_SIGNATURE), None, None, None, 0
    seen, records, idat_started, idat_closed = set(), [], False, False
    single_before_idat = {b"PLTE", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"pHYs"}
    while pos < len(data):
        start = pos
        if len(data) - pos < 12:
            _image_refusal("chunk PNG truncado")
        length = struct.unpack_from(">I", data, pos)[0]
        kind = data[pos + 4:pos + 8]
        end = pos + 12 + length
        if length > 0x7fffffff or end > len(data):
            _image_refusal("largo de chunk inválido")
        if len(kind) != 4 or any(not (65 <= byte <= 90 or 97 <= byte <= 122) for byte in kind) or 97 <= kind[2] <= 122:
            _image_refusal("tipo de chunk PNG inválido")
        payload = data[pos + 8:pos + 8 + length]
        expected_crc = struct.unpack_from(">I", data, pos + 8 + length)[0]
        if zlib.crc32(kind + payload) & 0xffffffff != expected_crc:
            _image_refusal("CRC incorrecto")
        if kind in (b"acTL", b"fcTL", b"fdAT"):
            _image_refusal("PNG animado no admitido")
        if start == len(_PNG_SIGNATURE) and kind != b"IHDR":
            _image_refusal("IHDR debe ser el primer chunk")
        if kind == b"IHDR":
            if width is not None:
                _image_refusal("IHDR repetido")
            if start != len(_PNG_SIGNATURE) or length != 13:
                _image_refusal("IHDR inválido")
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", payload)
            allowed_depths = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}
            if not width or not height or width > max_side or height > max_side:
                _image_refusal("dimensiones fuera del límite")
            if color not in allowed_depths or depth not in allowed_depths[color] or compression != 0 or filtering != 0 or interlace not in (0, 1):
                _image_refusal("IHDR no válido por el estándar PNG")
        elif width is None:
            _image_refusal("IHDR debe ser el primer chunk")
        if kind in single_before_idat:
            if kind in seen:
                _image_refusal(f"chunk {kind.decode('ascii')} repetido")
            if idat_started:
                _image_refusal(f"{kind.decode('ascii')} fuera de posición")
            seen.add(kind)
        if kind == b"PLTE":
            if length < 3 or length > 768 or length % 3 or color in (0, 4):
                _image_refusal("PLTE no permitido o inválido")
            if color == 3 and length // 3 > 2 ** depth:
                _image_refusal("PLTE excede la profundidad")
            palette_entries = length // 3
            if b"tRNS" in seen:
                _image_refusal("PLTE fuera de posición")
        if kind == b"tRNS":
            if color in (4, 6):
                _image_refusal("tRNS no permitido para este color")
            if color == 0 and length != 2 or color == 2 and length != 6:
                _image_refusal("tRNS inválido")
            if color == 3 and (b"PLTE" not in seen or length > palette_entries):
                _image_refusal("tRNS requiere PLTE")
        if kind == b"gAMA" and length != 4:
            _image_refusal("gAMA inválido")
        if kind == b"cHRM" and length != 32:
            _image_refusal("cHRM inválido")
        if kind == b"sRGB" and (length != 1 or payload[0] > 3):
            _image_refusal("sRGB inválido")
        if kind == b"pHYs" and (length != 9 or payload[8] > 1):
            _image_refusal("pHYs inválido")
        if kind == b"IDAT":
            if idat_closed:
                _image_refusal("chunks IDAT no consecutivos")
            idat_started = True
        elif idat_started and kind != b"IEND":
            idat_closed = True
        if kind == b"IEND":
            if length != 0 or not idat_started:
                _image_refusal("IEND inválido o sin IDAT")
            if color == 3 and b"PLTE" not in seen:
                _image_refusal("PLTE requerido para color indexado")
            if end != len(data):
                _image_refusal("bytes tras IEND")
            records.append((kind, start, end))
            return ("image/png", width, height, records)
        if kind[0] in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ" and kind not in (b"IHDR", b"PLTE", b"IDAT", b"IEND"):
            _image_refusal("chunk crítico PNG no admitido")
        records.append((kind, start, end))
        pos = end
    _image_refusal("falta IEND")


def _jpeg_table_counts(payload: bytes, marker_name: str) -> None:
    pos = 0
    while pos < len(payload):
        info = payload[pos]
        pos += 1
        if marker_name == "DQT":
            precision, table = info >> 4, info & 15
            size = 64 * (precision + 1)
            if precision not in (0, 1) or table > 3 or pos + size > len(payload):
                _image_refusal("DQT inválido")
            pos += size
        else:
            table_class, table = info >> 4, info & 15
            if table_class > 1 or table > 3 or pos + 16 > len(payload):
                _image_refusal("DHT inválido")
            count = sum(payload[pos:pos + 16])
            pos += 16
            if count > 256 or pos + count > len(payload):
                _image_refusal("DHT inválido")
            pos += count
    if pos != len(payload):
        _image_refusal(f"{marker_name} inválido")


def _jpeg_image(data: bytes, max_side: int):
    if not data.startswith(b"\xff\xd8"):
        _image_refusal("firma JPEG inválida")
    pos, frame, width, height, components, adobe_rgb = 2, None, None, None, {}, False
    scans = dqt_count = dht_count = restart_interval = 0
    records = [(0xd8, 0, 2)]
    while pos < len(data):
        start = pos
        if data[pos] != 0xff or pos + 1 >= len(data):
            _image_refusal("marcador JPEG inválido")
        pos += 1
        marker = data[pos]
        if marker == 0xff:
            _image_refusal("relleno FFFF no admitido")
        if marker == 0x00:
            _image_refusal("byte JPEG escapado fuera de barrido")
        pos += 1
        if 0xd0 <= marker <= 0xd7:
            _image_refusal("RSTn fuera del barrido")
        if marker == 0xd8:
            _image_refusal("SOI repetido")
        if marker == 0xd9:
            if scans == 0 or frame is None:
                _image_refusal("JPEG sin SOF o SOS")
            if pos != len(data):
                _image_refusal("bytes tras EOI")
            records.append((marker, start, pos))
            return ("image/jpeg", width, height, records)
        allowed = marker in (0xc0, 0xc1, 0xc2, 0xc4, 0xdb, 0xdd, 0xda, 0xfe) or 0xe0 <= marker <= 0xef
        if not allowed:
            _image_refusal("marcador JPEG no admitido")
        if pos + 2 > len(data):
            _image_refusal("segmento JPEG truncado")
        length = struct.unpack_from(">H", data, pos)[0]
        if length < 2 or pos + length > len(data):
            _image_refusal("segmento JPEG truncado")
        payload = data[pos + 2:pos + length]
        end = pos + length
        if marker == 0xdb:
            dqt_count += 1
            if dqt_count > 16:
                _image_refusal("más de 16 DQT")
            _jpeg_table_counts(payload, "DQT")
        elif marker == 0xc4:
            dht_count += 1
            if dht_count > 32:
                _image_refusal("más de 32 DHT")
            _jpeg_table_counts(payload, "DHT")
        elif marker == 0xdd:
            if length != 4:
                _image_refusal("DRI inválido")
            restart_interval = struct.unpack_from(">H", payload)[0]
        elif marker in (0xc0, 0xc1, 0xc2):
            if frame is not None or scans or len(payload) < 6:
                _image_refusal("SOF repetido o inválido")
            precision = payload[0]
            height, width, count = struct.unpack_from(">HHB", payload, 1)
            if len(payload) != 6 + 3 * count or precision not in (8, 12):
                _image_refusal("SOF inválido")
            if count not in (1, 3):
                _image_refusal("componentes JPEG no admitidos")
            if count == 3 and adobe_rgb:
                _image_refusal("RGB sin YCbCr no admitido")
            if not width or not height or width > max_side or height > max_side:
                _image_refusal("dimensiones fuera del límite")
            for i in range(count):
                ident, sampling, table = payload[6 + 3 * i:9 + 3 * i]
                if ident in components or not 1 <= sampling >> 4 <= 4 or not 1 <= (sampling & 15) <= 4 or table > 3:
                    _image_refusal("SOF inválido")
                components[ident] = table
            frame = marker
        elif marker == 0xda:
            if frame is None or len(payload) < 4:
                _image_refusal("SOS sin SOF")
            count = payload[0]
            if not 1 <= count <= len(components) or len(payload) != 4 + 2 * count:
                _image_refusal("SOS inválido")
            selected = set()
            for i in range(count):
                ident, tables = payload[1 + 2 * i:3 + 2 * i]
                if ident not in components or ident in selected or tables >> 4 > 3 or tables & 15 > 3:
                    _image_refusal("SOS refiere un componente inválido")
                selected.add(ident)
            ss, se, approximation = payload[-3:]
            if ss > 63 or se > 63 or ss > se or approximation >> 4 > 13 or approximation & 15 > 13:
                _image_refusal("SOS inválido")
            scans += 1
            if scans > 64:
                _image_refusal("más de 64 SOS")
            if frame == 0xc0 and (ss, se, approximation) != (0, 63, 0):
                _image_refusal("SOS baseline inválido")
            scan_pos = end
            while scan_pos < len(data):
                if data[scan_pos] != 0xff:
                    scan_pos += 1
                    continue
                if scan_pos + 1 >= len(data):
                    _image_refusal("barrido JPEG truncado")
                following = data[scan_pos + 1]
                if following == 0x00:
                    scan_pos += 2
                    continue
                if 0xd0 <= following <= 0xd7:
                    if not restart_interval:
                        _image_refusal("RSTn sin DRI")
                    scan_pos += 2
                    continue
                if following == 0xff:
                    _image_refusal("relleno FFFF no admitido")
                break
            records.append((marker, start, scan_pos))
            pos = scan_pos
            continue
        elif marker == 0xee and payload.startswith(b"Adobe"):
            if len(payload) < 12:
                _image_refusal("APP14 Adobe truncado")
            if payload[11] == 0:
                adobe_rgb = True
            if frame is not None and len(components) == 3 and adobe_rgb:
                _image_refusal("RGB sin YCbCr no admitido")
        records.append((marker, start, end))
        pos = end
    _image_refusal("falta EOI")


def validate_image(data: bytes, max_bytes: int = IMAGE_MAX_BYTES, max_side: int = IMAGE_MAX_SIDE) -> tuple[str, int, int]:
    """Validate PNG/JPEG structure without decoding pixels or decompressing data."""
    if not isinstance(data, bytes):
        _image_refusal("la imagen debe ser bytes")
    if len(data) > max_bytes:
        _image_refusal("supera el límite de bytes")
    try:
        if data.startswith(_PNG_SIGNATURE):
            image = _png_image(data, max_side)
        elif data.startswith(b"\xff\xd8"):
            image = _jpeg_image(data, max_side)
        else:
            _image_refusal("formato no admitido")
    except Refusal:
        raise
    except (IndexError, OverflowError, struct.error, ValueError) as error:
        raise Refusal("invalid_image", "estructura de imagen inválida") from error
    return image[:3]


def strip_image_metadata(data: bytes, max_bytes: int = IMAGE_MAX_BYTES, max_side: int = IMAGE_MAX_SIDE) -> bytes:
    """Copy validated image structures while retaining only format-specific safe chunks/markers."""
    try:
        if not isinstance(data, bytes):
            _image_refusal("la imagen debe ser bytes")
        if len(data) > max_bytes:
            _image_refusal("supera el límite de bytes")
        if data.startswith(_PNG_SIGNATURE):
            _, _, _, records = _png_image(data, max_side)
        elif data.startswith(b"\xff\xd8"):
            _, _, _, records = _jpeg_image(data, max_side)
        else:
            _image_refusal("formato no admitido")
    except Refusal as error:
        raise ValueError(str(error)) from error
    except (IndexError, OverflowError, struct.error, ValueError) as error:
        raise ValueError("estructura de imagen inválida") from error
    if data.startswith(_PNG_SIGNATURE):
        keep = {b"IHDR", b"PLTE", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"pHYs", b"IDAT", b"IEND"}
        return _PNG_SIGNATURE + b"".join(data[start:end] for kind, start, end in records if kind in keep)
    keep = {0xd8, 0xc0, 0xc1, 0xc2, 0xc4, 0xdb, 0xda, 0xdd, 0xd9}
    return b"".join(data[start:end] for marker, start, end in records if marker in keep)


def contrast_ratio(fg: str, bg: str) -> float:
    def luminance(color: str) -> float:
        channels = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4 for value in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]
    first, second = sorted((luminance(fg), luminance(bg)), reverse=True)
    return (first + 0.05) / (second + 0.05)


def _load_brand(nombre: str, value: dict, directory: Path) -> Marca:
    fd = None
    try:
        fd = os.open(directory / "marcas", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        files = []
        for extension in (".png", ".jpg"):
            try:
                os.lstat(value["logo"] + extension, dir_fd=fd)
                files.append(value["logo"] + extension)
            except FileNotFoundError:
                pass
        if not files:
            raise ValueError("falta el logo")
        if len(files) != 1:
            raise ValueError("logo ambiguo: hay PNG y JPEG")
        filename = files[0]
        raw, _ = _read_regular(filename, IMAGE_MAX_BYTES, dir_fd=fd)
        clean = strip_image_metadata(raw)
        mime, _, _ = validate_image(clean)
        if (filename.endswith(".png")) != (mime == "image/png"):
            raise ValueError("la extensión no coincide con el formato de imagen")
        return Marca(value["nombre"], value["logo"], f"marcas/{filename}", mime,
                     clean, hashlib.sha256(raw).hexdigest(), value.get("pie"), value.get("color"))
    except Refusal as error:
        reason = ("el logo supera el límite de bytes" if error.kind == "too_large"
                  else "el logo no es un archivo regular sin enlace" if error.kind == "not_regular"
                  else str(error))
        raise _template_error(nombre, "marca.logo", reason) from error
    except OSError as error:
        reason = "la carpeta marcas no es una carpeta regular" if fd is None else "no se pudo leer el logo"
        raise _template_error(nombre, "marca.logo", reason) from error
    except ValueError as error:
        raise _template_error(nombre, "marca.logo", str(error)) from error
    finally:
        if fd is not None:
            os.close(fd)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key:{key}")
        result[key] = value
    return result


def validate_template(nombre: str, data: bytes) -> dict:
    if not isinstance(nombre, str) or not _SLUG.fullmatch(nombre):
        raise _template_error(nombre, "nombre", "debe ser un slug válido")
    def bad(path, why="valor no válido"):
        raise _template_error(nombre, path, why)
    if len(data) > TEMPLATE_MAX_BYTES:
        bad("archivo", "supera 16384 bytes")
    def reject_constant(constant):
        raise ValueError(f"constant:{constant}")
    try:
        source = data.decode("utf-8")
    except UnicodeDecodeError:
        bad("json", "no es UTF-8")
    try:
        obj = json.loads(source, object_pairs_hook=_unique_object, parse_constant=reject_constant)
    except json.JSONDecodeError as e:
        bad("json", f"no es JSON válido (línea {e.lineno}, columna {e.colno})")
    except ValueError as e:
        detail = str(e)
        if detail.startswith("duplicate key:"):
            bad(f"json: clave repetida {detail.split(':', 1)[1]}")
        if detail.startswith("constant:"):
            bad(f"json: constante no estándar {detail.split(':', 1)[1]}")
        bad("json", "no es JSON válido")
    except RecursionError:
        bad("json", "anidamiento excesivo")
    def keys(value, allowed, path, exact=False):
        if not isinstance(value, dict):
            bad(path, "tipo incorrecto; se esperaba un objeto")
        unknown = sorted(set(value) - set(allowed))
        if unknown:
            bad(f"{path}.{unknown[0]}", "clave desconocida")
        if exact:
            missing = sorted(set(allowed) - set(value))
            if missing:
                bad(f"{path}.{missing[0]}", "falta la clave")
    def label(value, path, maximum):
        if not isinstance(value, str) or not 1 <= len(value) <= maximum or not value[0].isalpha() or any(not (c.isalnum() or c in _LABEL_PUNCT) for c in value):
            bad(path, "rótulo fuera del límite o charset")
    def line(value, path):
        if not isinstance(value, str) or not 1 <= len(value) <= 120 or not value.isprintable():
            bad(path, "texto fuera del límite o charset")
    keys(obj, ("etiqueta", "acento", "borrador", "textos", "secciones", "marca"), "raíz")
    for key in ("etiqueta", "acento", "borrador", "textos", "secciones"):
        if key not in obj:
            bad(f"raíz.{key}", "falta la clave")
    label(obj["etiqueta"], "etiqueta", 24)
    if not isinstance(obj["acento"], str) or obj["acento"] not in ACCENTS:
        bad("acento", "color fuera de la paleta")
    marca = obj.get("marca")
    if "marca" in obj:
        keys(marca, ("nombre", "logo", "pie", "color"), "marca")
        for key in ("nombre", "logo"):
            if key not in marca:
                bad(f"marca.{key}", "falta la clave")
        line(marca["nombre"], "marca.nombre")
        if not isinstance(marca["logo"], str) or not _SLUG.fullmatch(marca["logo"]):
            bad("marca.logo", "debe ser un slug válido")
        if "pie" in marca:
            keys(marca["pie"], ("es", "en"), "marca.pie", True)
            for lang in ("es", "en"):
                line(marca["pie"][lang], f"marca.pie.{lang}")
        if "color" in marca:
            color = marca["color"]
            if not isinstance(color, str) or re.fullmatch(r"#[0-9a-fA-F]{6}", color) is None:
                bad("marca.color", "debe ser #RRGGBB")
            ratio = contrast_ratio(color, "#ffffff")
            shown_ratio = math.floor(ratio * 100) / 100
            if ratio < 4.5:
                bad("marca.color", f"contraste insuficiente ({shown_ratio:.2f}:1)".replace(".", ","))
            marca["color"] = color.lower()
    draft = obj["borrador"]
    if not isinstance(draft, list) or any(not isinstance(k, str) for k in draft) or len(draft) != len(set(draft)) or not set(draft) <= set(DRAFT_KEYS):
        bad("borrador", "campos desconocidos o repetidos")
    keys(obj["textos"], ("es", "en"), "textos", True)
    for lang in ("es", "en"):
        text = obj["textos"][lang]
        keys(text, (*_TEMPLATE_FIELDS, "rotulos", "conteo"), f"textos.{lang}", True)
        for key in _TEMPLATE_FIELDS:
            (label(text[key], f"textos.{lang}.{key}", 80) if key == "subtitulo"
             else line(text[key], f"textos.{lang}.{key}"))
        if "marca" in obj and "gekko" in text["autor"].casefold():
            bad(f"textos.{lang}.autor", "no puede contener gekko cuando hay marca propia")
        keys(text["rotulos"], ("cliente", "autor", "periodo", "version"), f"textos.{lang}.rotulos", True)
        for key, value in text["rotulos"].items(): label(value, f"textos.{lang}.rotulos.{key}", 80)
        keys(text["conteo"], ("critical", "high", "medium", "low"), f"textos.{lang}.conteo", True)
        for key, value in text["conteo"].items(): label(value, f"textos.{lang}.conteo.{key}", 80)
    sections = obj["secciones"]
    if not isinstance(sections, list) or not 1 <= len(sections) <= 12:
        bad("secciones", "se requieren 1–12 secciones y una de hallazgos")
    has_findings = False
    for i, section in enumerate(sections):
        path = f"secciones.{i}"
        if not isinstance(section, dict): bad(path)
        keys(section, ("titulo", "prosa", "conteo", "hallazgos"), path)
        if "titulo" not in section: bad(path + ".titulo")
        keys(section["titulo"], ("es", "en"), path + ".titulo", True)
        for lang, value in section["titulo"].items(): label(value, path + f".titulo.{lang}", 80)
        modes = sum(k in section for k in ("prosa", "conteo", "hallazgos"))
        if modes == 0 or ("prosa" in section and modes != 1): bad(path, "sección sin contenido o modos incompatibles")
        if "prosa" in section and (section["prosa"] not in draft or section["prosa"] in ONE_LINE): bad(path + ".prosa")
        if "conteo" in section and section["conteo"] is not True: bad(path + ".conteo")
        if "hallazgos" in section:
            has_findings = True
            h = section["hallazgos"]
            keys(h, ("tabla", "ficha", "campos"), path + ".hallazgos")
            if not any(k in h for k in ("tabla", "ficha")) or ("campos" in h) != ("ficha" in h): bad(path + ".hallazgos")
            if "tabla" in h and (not isinstance(h["tabla"], list) or any(not isinstance(k, str) for k in h["tabla"]) or not 1 <= len(h["tabla"]) <= 7 or len(set(h["tabla"])) != len(h["tabla"]) or not set(h["tabla"]) <= {"id", "title", "severity", "target", "cvss", "cwe", "cve"}): bad(path + ".hallazgos.tabla")
            if "ficha" in h and (not isinstance(h["ficha"], str) or h["ficha"] not in ("completa", "corta")): bad(path + ".hallazgos.ficha")
            if "campos" in h:
                allowed = _FINDING_FIELDS if h["ficha"] == "completa" else ("summary", "impact", "remediation", "cvss_vector", "cvss_justification", "cwe", "cve")
                if not isinstance(h["campos"], list) or any(not isinstance(k, str) for k in h["campos"]) or len(set(h["campos"])) != len(h["campos"]) or not set(h["campos"]) <= set(allowed): bad(path + ".hallazgos.campos")
    if not has_findings: bad("secciones", "falta una sección de hallazgos")
    return obj


def load_templates(directory: Path = TEMPLATES_DIR) -> tuple[dict[str, Plantilla], list[str]]:
    errors, templates = [], {}
    try:
        dst = os.lstat(directory)
        if not stat.S_ISDIR(dst.st_mode):
            errors.append(f"Directorio de plantillas {str(directory)!r}: directorio: debe ser una carpeta regular")
            names = []
        else:
            names = sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    except OSError as e:
        errors.append(f"Directorio de plantillas {str(directory)!r}: directorio: no se pudo listar ({e.strerror})")
        names = []
    ordered = [f"{n}.json" for n in BUILTIN if f"{n}.json" in names]
    ordered += [n for n in names if n not in ordered]
    for excess in ordered[TEMPLATES_MAX:]: errors.append(f"Plantilla {excess!r}: archivo: excede el máximo de {TEMPLATES_MAX}; no se leyó")
    for filename in ordered[:TEMPLATES_MAX]:
        name = filename[:-5]
        try:
            raw, _ = _read_regular(directory / filename, TEMPLATE_MAX_BYTES)
        except (OSError, Refusal, ValueError, RecursionError) as e:
            if isinstance(e, Refusal):
                reason = "supera 16384 bytes" if e.kind == "too_large" else "no es un archivo regular sin enlace" if e.kind == "not_regular" else "no se pudo leer"
            else:
                reason = "no se pudo leer"
            errors.append(f"Plantilla {filename!r}: archivo: {reason}")
            continue
        try:
            datos = validate_template(name, raw)
        except Refusal as e:
            errors.append(str(e))
            continue
        try:
            marca = _load_brand(name, datos["marca"], directory) if "marca" in datos else None
        except Refusal as e:
            errors.append(str(e))
            continue
        templates[name] = Plantilla(name, hashlib.sha256(raw).hexdigest(), datos, marca)
    for name in BUILTIN:
        if f"{name}.json" not in names:
            errors.append(f"Plantilla {name}.json: archivo: falta la plantilla incorporada {name}.json")
        elif name not in templates and not any(f"{name}.json" in e for e in errors):
            errors.append(f"Plantilla {name}.json: archivo: falta la plantilla incorporada {name}.json")
    return templates, errors


SELFTEST_TEMPLATE = {
    "etiqueta": "Prueba", "acento": "azul",
    "borrador": ["titulo", "cliente", "periodo", "version", "autor", "clasificacion", "resumen", "recomendaciones"],
    "textos": {
        "es": {"antetitulo": "Plan de remediación", "subtitulo": "Reporte para el cliente", "titulo": "Prioridades de seguridad",
               "cliente": "Cliente de prueba", "autor": "Equipo de prueba", "periodo": "Periodo de prueba", "version": "1.0", "clasificacion": "INTERNO",
               "rotulos": {"cliente": "Para", "autor": "Por", "periodo": "Periodo", "version": "Versión"},
               "conteo": {"critical": "Críticas", "high": "Altas", "medium": "Medias", "low": "Bajas"}},
        "en": {"antetitulo": "Remediation plan", "subtitulo": "Client report", "titulo": "Security priorities",
               "cliente": "Test client", "autor": "Test team", "periodo": "Test period", "version": "1.0", "clasificacion": "INTERNAL",
               "rotulos": {"cliente": "For", "autor": "By", "periodo": "Period", "version": "Version"},
               "conteo": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}},
    },
    "secciones": [
        {"titulo": {"es": "Prioridades", "en": "Priorities"}, "conteo": True},
        {"titulo": {"es": "Recomendaciones", "en": "Recommendations"}, "prosa": "recomendaciones"},
        {"titulo": {"es": "Hallazgos y remediación", "en": "Findings and remediation"},
         "hallazgos": {"tabla": ["id", "severity", "cwe"], "ficha": "corta", "campos": ["remediation"]}},
        {"titulo": {"es": "Resumen", "en": "Summary"}, "prosa": "resumen"},
    ],
}
SELFTEST_MARCA = {
    **SELFTEST_TEMPLATE,
    "textos": {lang: {**SELFTEST_TEMPLATE["textos"][lang], "autor": "Equipo de prueba ficticio"} for lang in ("es", "en")},
    "marca": {"nombre": "Marca de prueba", "logo": "selftest-logo",
              "pie": {"es": "Uso ficticio", "en": "Fictional use"}, "color": "#2B5D8C"},
}


def _selftest_png_chunk(kind: bytes, payload: bytes) -> bytes:
    body = kind + payload
    return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body) & 0xffffffff)


def selftest_png(width: int, height: int, chunks=(), cola: bytes = b"") -> bytes:
    """Build structural PNG fixtures; chunks are (type, data[, placement]) records."""
    before_ihdr, before_idat, after_idat, before_iend = [], [], [], []
    for item in chunks:
        kind, payload, *placement = item
        destination = (placement[0] if placement else "before_idat")
        record = _selftest_png_chunk(kind, payload)
        {"before_ihdr": before_ihdr, "before_idat": before_idat,
         "after_idat": after_idat, "before_iend": before_iend}[destination].append(record)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + b"".join(before_ihdr) + _selftest_png_chunk(b"IHDR", ihdr)
            + b"".join(before_idat) + _selftest_png_chunk(b"IDAT", b"\x00")
            + b"".join(after_idat) + b"".join(before_iend) + _selftest_png_chunk(b"IEND", b"") + cola)


def _selftest_jpeg_segment(marker: int, payload: bytes) -> bytes:
    return b"\xff" + bytes((marker,)) + struct.pack(">H", len(payload) + 2) + payload


def selftest_jpeg(width: int, height: int, segmentos=(), componentes: int = 3, cola: bytes = b"") -> bytes:
    """Build structural JPEG fixtures; segments are marker records with optional placement."""
    before_sof, before_sos, after_sos = [], [], []
    for item in segmentos:
        if isinstance(item, bytes):
            before_sos.append(item)
            continue
        marker, payload, *placement = item
        destination = placement[0] if placement else "before_sos"
        record = _selftest_jpeg_segment(marker, payload)
        {"before_sof": before_sof, "before_sos": before_sos, "after_sos": after_sos}[destination].append(record)
    dqt = _selftest_jpeg_segment(0xdb, b"\x00" + b"\x01" * 64)
    dht = _selftest_jpeg_segment(0xc4, b"\x00" + b"\x01" + b"\x00" * 15 + b"\x00")
    sof_payload = bytes((8,)) + struct.pack(">HH", height, width) + bytes((componentes,))
    sof_payload += b"".join(bytes((i + 1, 0x11, 0)) for i in range(componentes))
    sof = _selftest_jpeg_segment(0xc0, sof_payload)
    scan_payload = bytes((componentes,)) + b"".join(bytes((i + 1, 0)) for i in range(componentes)) + b"\x00\x3f\x00"
    scan = _selftest_jpeg_segment(0xda, scan_payload)
    return (b"\xff\xd8" + b"".join(before_sof) + dqt + dht + sof + b"".join(before_sos)
            + scan + b"\x10\xff\x00\x20" + b"".join(after_sos) + b"\xff\xd9" + cola)


def report_model(rows: list[dict], lang: str, tipo: str, draft: dict | None = None, workspace: str = "", plantillas=None) -> dict:
    """What every format (Markdown, HTML and its print view) shows: cover, notice, numbered sections; values are plain text, escaped by each renderer."""
    if lang not in LABELS:
        raise ValueError(f"unsupported language: {lang}")
    templates = _template_map(plantillas)
    if tipo not in templates:
        raise ValueError(f"unknown report template {tipo!r}; valid: {', '.join(templates)}")
    labels, d, template = LABELS[lang], DOC[lang], templates[tipo].datos
    text = template["textos"][lang]
    draft = {k: v for k, v in (draft or {}).items() if not _blank(v)}
    one = lambda key: _oneline(draft[key]) if key in draft else text[key]
    everything = included(rows)
    chosen = [r for r in everything if r.get("status") != "remediated"]  # the counts and the first block are the open ones
    fixed = [r for r in everything if r.get("status") == "remediated"]
    tiles = [(text["conteo"][s], sum(1 for r in chosen if r.get("severity") == s), s) for s in ("critical", "high", "medium", "low")]
    sections = []
    for spec in template["secciones"]:
        section = {"title": spec["titulo"][lang]}
        if "prosa" in spec and spec["prosa"] in draft:
            section["prose"] = draft[spec["prosa"]]
        if spec.get("conteo"):
            section["tiles"] = True
        if "hallazgos" in spec:
            finding = spec["hallazgos"]
            if "ficha" in finding:
                section["findings"] = "full" if finding["ficha"] == "completa" else "table"
                section["fields"] = finding["campos"]
            elif "tabla" in finding:
                section["findings"] = "table"
            if "tabla" in finding:
                section["columns"] = finding["tabla"]
            if finding.get("ficha") == "corta":
                section["short"] = True
        if "prose" in section or section.get("tiles") or section.get("findings"):
            sections.append(section)
    eyebrow = text["antetitulo"].upper() + (f" / {_oneline(workspace)}" if workspace else "")
    return {"classification": one("clasificacion"), "eyebrow": eyebrow, "title": one("titulo"), "accent": template["acento"],
            "subtitle": text["subtitulo"], "notice": d["notice"], "tiles": tiles, "chosen": chosen, "remediated": fixed, "sections": sections,
            "cover": [(text["rotulos"][key], one(key)) for key in ("cliente", "autor", "periodo", "version")],
            "brand": templates[tipo].marca}


def render_report(rows: list[dict], lang: str = "en", tipo: str = "tecnico", draft: dict | None = None, workspace: str = "", plantillas=None) -> str:
    """The one Markdown projection of the report (cover as the prototype, numbered sections); never carries the KB."""
    m = report_model(rows, lang, tipo, draft, workspace, plantillas)
    labels = LABELS[lang]
    lines = [_code(m["classification"]), "", _code(m["eyebrow"]), "", f"# {_code(m['title'])}", "", m["subtitle"], ""]
    lines += [f"- **{label}:** {_code(value)}" for label, value in m["cover"]] + ["", f"> {m['notice']}", ""]
    cell = lambda v: _code(_oneline(v)).replace("|", "\\|")  # GFM reads \| inside a code span as a literal pipe
    for number, section in enumerate(m["sections"], 1):
        lines += [f"## {number:02d} {section['title']}", ""]
        if "prose" in section:
            fence = _fence(section["prose"])
            lines += [fence, section["prose"], fence, ""]
        if section.get("tiles"):
            lines += ["- " + " · ".join([f"**{label}:** {n}" for label, n, _ in m["tiles"]]
                                         + ([f"**{DOC[lang]['remediated']}:** {len(m['remediated'])}"] if m["remediated"] else [])), ""]
        mode = section.get("findings")
        if mode and not m["chosen"]:
            lines += [labels["empty"], ""]
        for group, rows_ in (("open", m["chosen"]), ("fixed", m["remediated"])):
            if not mode or not rows_:
                continue
            if group == "fixed":
                lines += [f"**{DOC[lang]['remediated']} ({len(rows_)})**", ""]
            if mode == "full":
                if "columns" in section:
                    columns = section["columns"]
                    lines += ["| " + " | ".join(labels[key] for key in columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
                    lines += ["| " + " | ".join(cell(loc(lang, "sev", row.get(key, "?")) if key == "severity" else row.get(key, "(no title)" if key == "title" else "?")) for key in columns) + " |"
                              for row in rows_] + [""]
                for row in rows_:
                    _md_finding(lines, row, lang, "###", True, section.get("fields"))
            elif mode == "table":
                columns = section.get("columns")
                if columns:
                    lines += ["| " + " | ".join(labels[key] for key in columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
                    lines += ["| " + " | ".join(cell(loc(lang, "sev", r.get(key, "?")) if key == "severity" else r.get(key, "(no title)" if key == "title" else "?")) for key in columns) + " |"
                              for r in rows_] + [""]
                if section.get("short"):
                    for r in rows_:
                        _md_short(lines, r, lang, section.get("fields", ("impact",)))
    return "\n".join(lines) + "\n"


def cmd_render(a) -> None:
    tipo, draft_path = getattr(a, "tipo", None), getattr(a, "borrador", None)
    if (draft_path or tipo) and (getattr(a, "all", False) or not tipo):
        sys.exit("--borrador needs --tipo and --tipo cannot be combined with --all")
    rows = _load(Path(a.ledger))
    try:
        if tipo:
            templates, errors = load_templates()
            if tipo not in templates:
                detail = next((e for e in errors if tipo in e), "")
                sys.exit(f"plantilla desconocida o inválida {tipo!r}: {detail}; válidas: {', '.join(templates)}")
            draft = validate_draft(tipo, _read_regular(Path(draft_path), DRAFT_MAX_BYTES)[0], templates) if draft_path else None
            folder = Path(a.ledger).resolve().parent  # only a codename folder under engagements/ may reach the client document
            workspace = getattr(a, "workspace", None) or (folder.name if folder.parent.name == "engagements" else "")
            print(render_report(rows, getattr(a, "lang", "en"), tipo, draft, workspace, templates), end="")
        else:
            print(render_md(rows, getattr(a, "lang", "en"), getattr(a, "all", False)), end="")
    except (ValueError, OSError) as e:
        sys.exit(str(e))


def cmd_selftest(_a) -> None:
    import tempfile, types, io, contextlib, shutil, subprocess, copy, inspect
    from unittest import mock
    tmp = Path(tempfile.mkdtemp())
    led = tmp / "findings.jsonl"
    ns = lambda **k: types.SimpleNamespace(**k)

    def ok(req: str, cond: bool, desc: str) -> None:
        if not cond:
            raise AssertionError(desc)
        print(f"ok {req} {desc}")

    # REQ-RPT-058: structural image parsing, metadata removal and contrast math.
    png = selftest_png(1, 1)
    jpeg = selftest_jpeg(1, 1)
    def image_result(data, expected=None, max_bytes=262144, max_side=2048):
        try:
            result = validate_image(data, max_bytes=max_bytes, max_side=max_side)
        except Refusal as error:
            return expected is not None and expected in str(error), str(error)
        except Exception as error:
            return False, f"{type(error).__name__}: {error}"
        return expected is None and result in (("image/png", 1, 1), ("image/jpeg", 1, 1)), repr(result)

    def image_case(label, data, expected=None, max_bytes=262144, max_side=2048):
        passed, reason = image_result(data, expected, max_bytes, max_side)
        ok("REQ-RPT-058", passed, f"validate_image {label}: {reason}")

    image_case("PNG mínimo", png)
    image_case("JPEG mínimo", jpeg)
    png_color = lambda color, depth=8: (b"\x89PNG\r\n\x1a\n" + _selftest_png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, depth, color, 0, 0, 0))
                                        + _selftest_png_chunk(b"IDAT", b"\x00") + _selftest_png_chunk(b"IEND", b""))
    phys_canary = b"</title><script>LOGO-CANARY"
    png_cases = [
        ("SVG renombrado", b"<svg onload='x'>", "formato no admitido"),
        ("HTML renombrado", b"<script>x</script>", "formato no admitido"),
        ("GIF", b"GIF89a", "formato no admitido"), ("WebP", b"RIFFxxxxWEBP", "formato no admitido"),
        ("BMP", b"BMxxxx", "formato no admitido"),
        ("HTML antes de PNG", b"<script>x</script>" + png, "formato no admitido"),
        ("byte tras IEND", selftest_png(1, 1, cola=b"x"), "bytes tras IEND"),
        ("ZIP tras IEND", selftest_png(1, 1, cola=b"PK\x03\x04"), "bytes tras IEND"),
        ("sin IEND", png[:-12], "falta IEND"),
        ("IDAT antes de IHDR", selftest_png(1, 1, chunks=((b"IDAT", b"x", "before_ihdr"),)), "IHDR debe ser el primer chunk"),
        ("CRC alterado", png[:29] + bytes((png[29] ^ 1,)) + png[30:], "CRC incorrecto"),
        ("largo fuera del archivo", png[:33] + b"\xff\xff\xff\xff" + png[37:], "largo de chunk inválido"),
        ("APNG", selftest_png(1, 1, chunks=((b"acTL", b"\x00" * 8),)), "PNG animado no admitido"),
        ("lado 2049", selftest_png(2049, 1), "dimensiones fuera del límite"),
        ("pHYs con bytes libres", selftest_png(1, 1, chunks=((b"pHYs", phys_canary + b"x" * (4000 - len(phys_canary))),)), "pHYs inválido"),
        ("IHDR repetido", selftest_png(1, 1, chunks=((b"IHDR", struct.pack(">IIBBBBB", 9000, 9000, 8, 6, 0, 0, 0)),)), "IHDR repetido"),
        ("gAMA tras IDAT", selftest_png(1, 1, chunks=((b"gAMA", b"\x00\x00\xb1\x8f", "after_idat"),)), "gAMA fuera de posición"),
        ("tRNS en color 6", (b"\x89PNG\r\n\x1a\n" + _selftest_png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
                              + _selftest_png_chunk(b"tRNS", b"\x00\x00") + _selftest_png_chunk(b"IDAT", b"\x00") + _selftest_png_chunk(b"IEND", b"")), "tRNS no permitido"),
        ("PLTE en color 0", (b"\x89PNG\r\n\x1a\n" + _selftest_png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
                              + _selftest_png_chunk(b"PLTE", b"\x00\x00\x00") + _selftest_png_chunk(b"IDAT", b"\x00") + _selftest_png_chunk(b"IEND", b"")), "PLTE no permitido"),
        ("sobre el tope de bytes", selftest_png(1, 1, cola=b"x" * (262145 - len(png))), "supera el límite de bytes"),
    ]
    for label, data, expected in png_cases:
        image_case(label, data, expected)

    dqt = (0xdb, b"\x00" + b"\x01" * 64)
    dht = (0xc4, b"\x00" + b"\x01" + b"\x00" * 15 + b"\x00")
    sos = (0xda, b"\x01\x01\x00\x00\x3f\x00")
    app14_zero = (0xee, b"Adobe\x00d\x00\x00\x00\x00\x00")
    jpeg_cases = [
        ("DAC 0xFFCC", selftest_jpeg(1, 1, segmentos=((0xcc, b""),)), "marcador JPEG no admitido"),
        ("sin SOI", b"\x00\x00" + jpeg[2:], "formato no admitido"),
        ("segmento truncado", selftest_jpeg(1, 1)[:-2] + b"\xff\xe0\x00", "segmento JPEG truncado"),
        ("sin EOI", jpeg[:-2], "falta EOI"), ("bytes tras EOI", selftest_jpeg(1, 1, cola=b"x"), "bytes tras EOI"),
        ("cuatro componentes", selftest_jpeg(1, 1, componentes=4), "componentes JPEG no admitidos"),
        ("lado 2049", selftest_jpeg(2049, 1), "dimensiones fuera del límite"),
        ("DQT 60000 B con canario", selftest_jpeg(1, 1, segmentos=((dqt[0], b"\x00" + b"LOGO-CANARY" + b"x" * 59928),)), "DQT inválido"),
        ("DHT con suma incorrecta", selftest_jpeg(1, 1, segmentos=((0xc4, b"\x00" + b"\x02" + b"\x00" * 15 + b"\x00"),)), "DHT inválido"),
        ("FFF0", selftest_jpeg(1, 1, segmentos=((0xf0, b"html"),)), "marcador JPEG no admitido"),
        ("SOI doble", selftest_jpeg(1, 1, segmentos=(b"\xff\xd8",)), "SOI repetido"),
        ("relleno FFFF", selftest_jpeg(1, 1, segmentos=(b"\xff\xff",)), "relleno FFFF no admitido"),
        ("65 SOS", selftest_jpeg(1, 1, segmentos=tuple(sos for _ in range(64))), "más de 64 SOS"),
        ("APP14 Adobe transform 0", selftest_jpeg(1, 1, segmentos=(app14_zero,)), "RGB sin YCbCr no admitido"),
        ("17 DQT", selftest_jpeg(1, 1, segmentos=tuple(dqt for _ in range(16))), "más de 16 DQT"),
        ("33 DHT", selftest_jpeg(1, 1, segmentos=tuple(dht for _ in range(32))), "más de 32 DHT"),
        ("sobre el tope de bytes", selftest_jpeg(1, 1, cola=b"x" * (262145 - len(jpeg))), "supera el límite de bytes"),
    ]
    for label, data, expected in jpeg_cases:
        image_case(label, data, expected)

    png_metadata = selftest_png(1, 1, chunks=tuple((kind, b"</title><script>LOGO-CANARY") for kind in
        (b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME", b"prVt")))
    jpeg_metadata = selftest_jpeg(1, 1, segmentos=((0xfe, b"COM-LOGO-CANARY"), (0xe1, b"Exif\x00\x00APP1-LOGO-CANARY")))
    png_clean, jpeg_clean = strip_image_metadata(png_metadata), strip_image_metadata(jpeg_metadata)
    ok("REQ-RPT-058", b"LOGO-CANARY" not in png_clean and all(tag not in png_clean for tag in (b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME", b"prVt"))
       and b"IDAT\x00" in png_clean and validate_image(png_clean) == ("image/png", 1, 1)
       and strip_image_metadata(png_clean) == png_clean,
       "PNG metadata is removed by whitelist while IDAT is retained and the clean image revalidates idempotently")
    ok("REQ-RPT-058", b"LOGO-CANARY" not in jpeg_clean and b"COM" not in jpeg_clean and b"Exif" not in jpeg_clean
       and b"\x10\xff\x00\x20" in jpeg_clean and validate_image(jpeg_clean) == ("image/jpeg", 1, 1)
       and strip_image_metadata(jpeg_clean) == jpeg_clean,
       "JPEG APP and COM metadata is removed while scan data is retained and the clean image revalidates idempotently")
    import random
    rng = random.Random(0x021058)
    robust = True
    for minimum in (png, jpeg):
        for _ in range(500):
            mutations = (minimum[:rng.randrange(len(minimum))],
                         minimum[:(at := rng.randrange(len(minimum)))] + bytes((minimum[at] ^ (1 << rng.randrange(8)),)) + minimum[at + 1:])
            for candidate in mutations:
                try:
                    result = validate_image(candidate)
                    robust = robust and isinstance(result, tuple) and len(result) == 3
                except Refusal:
                    pass
                except Exception:
                    robust = False
    ok("REQ-RPT-058", robust, "2000 deterministic truncations and bit flips return only an image tuple or Refusal")
    image_sources = (inspect.getsource(validate_image), inspect.getsource(strip_image_metadata))
    ok("REQ-RPT-058", not any(token in source for source in image_sources for token in ("decompress(", "decompressobj", "eval(", "exec(", "importlib")),
       "image validation and metadata stripping never decompress or dynamically evaluate image data")
    ok("REQ-RPT-058", abs(contrast_ratio("#777777", "#ffffff") - 4.478) < 0.001
       and abs(contrast_ratio("#767676", "#ffffff") - 4.542) < 0.001
       and abs(contrast_ratio("#c0f425", "#ffffff") - 1.296) < 0.001,
       "contrast_ratio matches the WCAG reference values")

    # REQ-RPT-058: AC5's optional brand object rejects every malformed shape before file access.
    brand_base = copy.deepcopy(SELFTEST_TEMPLATE)
    brand_base["marca"] = {"nombre": "Empresa de prueba", "logo": "selftest-logo"}
    def brand_variant(**changes):
        value = copy.deepcopy(brand_base)
        value["marca"].update(changes)
        return value
    def brand_case(label, value, expected):
        try:
            validate_template("invalida", json.dumps(value, ensure_ascii=False).encode())
            passed, detail = expected is None, "aceptada"
        except Refusal as error:
            passed, detail = expected is not None and "invalida.json" in str(error) and expected in str(error), str(error)
        except Exception as error:
            passed, detail = False, f"{type(error).__name__}: {error}"
        ok("REQ-RPT-058", passed, f"marca {label}: {detail}")

    unknown_brand = brand_variant(inesperada="x")
    cases = [
        ("clave desconocida", unknown_brand, "marca.inesperada"),
        ("sin nombre", {**brand_base, "marca": {"logo": "selftest-logo"}}, "marca.nombre"),
        ("sin logo", {**brand_base, "marca": {"nombre": "Empresa"}}, "marca.logo"),
        ("marca no objeto", {**brand_base, "marca": []}, "marca"),
        ("marca null", {**brand_base, "marca": None}, "marca"),
        ("logo null", brand_variant(logo=None), "marca.logo"), ("logo vacío", brand_variant(logo=""), "marca.logo"),
        ("logo con salto", brand_variant(logo="x\n"), "marca.logo"),
        *[(f"slug {slug!r}", brand_variant(logo=slug), "marca.logo") for slug in ("../x", "/etc/x", "x/y", "ñ", "A", "x.png")],
        ("color tipo", brand_variant(color=123), "marca.color"), ("pie tipo", brand_variant(pie="x"), "marca.pie"),
        *[(f"color {color!r}", brand_variant(color=color), "marca.color") for color in
          ("red", "#fff", "#12345g", "#000000;}body{", "#000000\n", "#777777", "#c0f425")],
        ("nombre vacío", brand_variant(nombre=""), "marca.nombre"),
        ("nombre largo", brand_variant(nombre="N" * 121), "marca.nombre"),
        ("nombre salto", brand_variant(nombre="Empresa\nX"), "marca.nombre"),
        ("nombre U2028", brand_variant(nombre="Empresa\u2028X"), "marca.nombre"),
        ("nombre control", brand_variant(nombre="Empresa\x01X"), "marca.nombre"),
        ("pie sin inglés", brand_variant(pie={"es": "Solo español"}), "marca.pie.en"),
        ("pie largo", brand_variant(pie={"es": "P" * 121, "en": "Footer"}), "marca.pie.es"),
        ("pie salto", brand_variant(pie={"es": "Pie\nX", "en": "Footer"}), "marca.pie.es"),
        ("pie U2028", brand_variant(pie={"es": "Pie", "en": "Footer\u2028X"}), "marca.pie.en"),
        ("pie control", brand_variant(pie={"es": "Pie", "en": "Footer\x01X"}), "marca.pie.en"),
        ("autor español Gekko", {**brand_base, "textos": {**brand_base["textos"], "es": {**brand_base["textos"]["es"], "autor": "GEKKO propio"}}}, "textos.es.autor"),
        ("autor inglés Gekko", {**brand_base, "textos": {**brand_base["textos"], "en": {**brand_base["textos"]["en"], "autor": "by gekko"}}}, "textos.en.autor"),
        ("color #767676", brand_variant(color="#767676"), None),
        ("color normalizado", brand_variant(color="#2B5D8C"), None),
    ]
    for label, value, expected in cases:
        brand_case(label, value, expected)
    normalized_brand = validate_template("prueba", json.dumps(brand_variant(color="#2B5D8C")).encode())
    ok("REQ-RPT-058", normalized_brand["marca"]["color"] == "#2b5d8c",
       "brand color is normalized to lowercase after contrast validation")

    def brand_tree(root):
        root.mkdir()
        for builtin in BUILTIN:
            shutil.copyfile(TEMPLATES_DIR / f"{builtin}.json", root / f"{builtin}.json")
        (root / "marcas").mkdir()
        (root / "marca-prueba.json").write_text(json.dumps(SELFTEST_MARCA, ensure_ascii=False), encoding="utf-8")
        return root / "marcas"

    def brand_load_case(label, setup, expected="marca.logo"):
        with tempfile.TemporaryDirectory(dir=tmp) as temp:
            root = Path(temp) / "plantillas"
            marks = brand_tree(root)
            setup(Path(temp), root, marks)
            loaded, errors = load_templates(root)
            message = next((e for e in errors if "marca-prueba.json" in e), "")
            ok("REQ-RPT-058", set(loaded) == set(BUILTIN) and all(t.marca is None for t in loaded.values())
               and message and expected in message and "marca-prueba.json" in message,
               f"logo {label} rechaza sólo marca-prueba.json con marca.logo: {message or errors}")

    logo_cases = [
        ("ausente", lambda temp, root, marks: None),
        ("ambiguo PNG/JPEG", lambda temp, root, marks: (marks / "selftest-logo.png").write_bytes(selftest_png(1, 1))
         and (marks / "selftest-logo.jpg").write_bytes(selftest_jpeg(1, 1))),
        ("enlace fuera de raíz", lambda temp, root, marks: (temp / "afuera.png").write_bytes(selftest_png(1, 1))
         and (marks / "selftest-logo.png").symlink_to(temp / "afuera.png")),
        ("FIFO", lambda temp, root, marks: os.mkfifo(marks / "selftest-logo.png")),
        ("directorio", lambda temp, root, marks: (marks / "selftest-logo.png").mkdir()),
        ("sobre tope", lambda temp, root, marks: (marks / "selftest-logo.png").write_bytes(b"x" * (IMAGE_MAX_BYTES + 1))),
        ("extensión no coincide", lambda temp, root, marks: (marks / "selftest-logo.png").write_bytes(selftest_jpeg(1, 1))),
        ("imagen cortada", lambda temp, root, marks: (marks / "selftest-logo.png").write_bytes(selftest_png(1, 1)[:-5])),
    ]
    for label, setup in logo_cases:
        brand_load_case(label, setup)
    def symlink_brand_dir(temp, root, marks):
        marks.rmdir()
        outside = temp / "directorio-externo"
        outside.mkdir()
        (root / "marcas").symlink_to(outside, target_is_directory=True)
    brand_load_case("carpeta marcas enlazada", symlink_brand_dir)

    with tempfile.TemporaryDirectory(dir=tmp) as temp:
        root = Path(temp) / "plantillas"
        marks = brand_tree(root)
        raw_logo = selftest_png(1, 1, chunks=((b"tEXt", b"LOGO-LOAD-CANARY"),))
        (marks / "selftest-logo.png").write_bytes(raw_logo)
        original_read_regular = _read_regular
        logo_reads = []
        def count_logo_read(path, max_bytes, dir_fd=None):
            if dir_fd is not None:
                logo_reads.append(path)
            return original_read_regular(path, max_bytes, dir_fd)
        with mock.patch(__name__ + "._read_regular", side_effect=count_logo_read):
            marked_templates, marked_errors = load_templates(root)
        marked = marked_templates["marca-prueba"].marca
        plain_data = copy.deepcopy(SELFTEST_MARCA)
        plain_data.pop("marca")
        plain_templates = {**marked_templates,
                           "marca-prueba": Plantilla("marca-prueba", marked_templates["marca-prueba"].sha256, plain_data)}
        rendered_equal = all(
            render_report([], lang, "marca-prueba", draft, plantillas=marked_templates)
            == render_report([], lang, "marca-prueba", draft, plantillas=plain_templates)
            and "gekko" not in render_report([], lang, "marca-prueba", draft, plantillas=marked_templates).casefold()
            for lang in ("es", "en") for draft in (None, {"titulo": "Prueba"})
        )
        ok("REQ-RPT-058", not marked_errors and set(marked_templates) == {*BUILTIN, "marca-prueba"}
           and all(marked_templates[name].marca is None for name in BUILTIN)
           and marked is not None and marked.archivo == "marcas/selftest-logo.png"
           and marked.mime == "image/png" and marked.limpio == strip_image_metadata(raw_logo)
           and marked.sha256 == hashlib.sha256(raw_logo).hexdigest() and logo_reads == ["selftest-logo.png"]
           and Plantilla("prueba", "0" * 64, SELFTEST_TEMPLATE).marca is None
           and report_model([], "es", "marca-prueba", plantillas=marked_templates)["brand"] == marked
           and rendered_equal,
           "a marked template loads one safe logo read, keeps built-ins unmarked, and leaves Markdown unchanged")

    # REQ-RPT-055: rejection matrix and safe directory loading, independent of rendering.
    builtin_templates, builtin_errors = load_templates()
    ok("REQ-RPT-055", set(builtin_templates) == set(BUILTIN) and not builtin_errors
       and all(len(t.sha256) == 64 for t in builtin_templates.values()),
       "the two built-in template files load with their byte sha256")
    template_data = json.loads((TEMPLATES_DIR / "tecnico.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(dir=tmp) as temp:
        template_dir = Path(temp)
        for builtin in BUILTIN:
            shutil.copyfile(TEMPLATES_DIR / f"{builtin}.json", template_dir / f"{builtin}.json")
        (template_dir / "prueba.json").write_text(json.dumps(SELFTEST_TEMPLATE, ensure_ascii=False), encoding="utf-8")
        todo_template = copy.deepcopy(SELFTEST_TEMPLATE)
        todo_findings = next(s for s in todo_template["secciones"] if "hallazgos" in s)
        todo_findings["hallazgos"] = {"tabla": ["id", "title", "severity", "target", "cvss", "cwe", "cve"],
                                         "ficha": "completa", "campos": list(_FINDING_FIELDS)}
        (template_dir / "todo.json").write_text(json.dumps(todo_template, ensure_ascii=False), encoding="utf-8")
        test_templates, test_errors = load_templates(template_dir)
        ok("REQ-RPT-057", set(test_templates) == {"tecnico", "ejecutivo", "prueba", "todo"} and not test_errors,
           "SELFTEST_TEMPLATE and the all-fields template load from data files")
        fixture = [{"id": "F-T7-A", "title": "Finding A", "severity": "high", "status": "confirmed", "corroboration": "CANARY-CORROBORATION", "target": "lab",
                    "summary": "CANARY-SUMMARY", "impact": "CANARY-IMPACT", "remediation": "CANARY-REMEDIATION", "cvss": "8.1",
                    "cvss_vector": "CANARY-VECTOR", "cvss_justification": "CANARY-JUSTIFICATION", "cwe": "CWE-79", "cve": "CVE-2024-0001",
                    "blocker": "CANARY-BLOCKER", "evidence": {"command": "CANARY-COMMAND", "artifact": "CANARY-ARTIFACT", "output": "CANARY-OUTPUT"},
                    "repro": ["CANARY-REPRO"]},
                   {"id": "F-T7-B", "title": "Finding B", "severity": "medium", "status": "triaged", "target": "lab-b"},
                   {"id": "F-T7-C", "title": "Finding C", "severity": "confirmed", "status": "confirmed", "target": "lab-c"},
                   {"id": "F-T7-D", "title": "Finding D", "severity": "low", "status": "refuted", "target": "lab-d", "corroboration": "no"},
                   {"id": "F-T7-E", "title": "Finding E", "severity": "critical", "status": "needs_validation", "target": "lab-e", "blocker": "CANARY-ONLY-BLOCKER", "corroboration": "no"},
                   {"id": "F-T7-G", "title": "Finding G", "severity": "low", "status": "hypothesis", "target": "lab-g", "corroboration": "no"},
                   {"id": "F-T7-F", "title": "Finding F", "severity": "critical", "status": "confirmed", "corroboration": "corroborated", "target": "lab-f", "kb": ["KB-CANARY"]}]
        es = render_report(fixture, "es", "prueba", {"resumen": "RESUMEN-DRAFT", "recomendaciones": "CANARY-RECOMMENDATION"}, plantillas=test_templates)
        en = render_report(fixture, "en", "prueba", {"resumen": "RESUMEN-DRAFT", "recomendaciones": "CANARY-RECOMMENDATION"}, plantillas=test_templates)
        headings = [f"## {i:02d} {title}" for i, title in enumerate(("Prioridades", "Recomendaciones", "Hallazgos y remediación", "Resumen"), 1)]
        ok("REQ-RPT-057", all(h in es for h in headings) and es.index(headings[1]) < es.index(headings[2]) < es.index(headings[3])
           and "## 01 Priorities" in en and "Security priorities" in en and "Prioridades de seguridad" in es
           and "| ID | Severidad | CWE |" in es and "CANARY-REMEDIATION" in es and "CANARY-CORROBORATION" not in es
           and "CANARY-COMMAND" not in es and "CANARY-ARTIFACT" not in es and "CANARY-OUTPUT" not in es
           and "CANARY-REPRO" not in es and "CANARY-SUMMARY" not in es and "CANARY-IMPACT" not in es,
           "AC4 prueba template changes texts, section order, table columns and selected fields visibly")
        tech = render_report(fixture, "en", "tecnico", plantillas=test_templates)
        ok("REQ-RPT-057", all(v in tech for v in ("CANARY-SUMMARY", "CANARY-IMPACT", "CANARY-REMEDIATION", "CANARY-COMMAND", "CANARY-ARTIFACT", "CANARY-OUTPUT", "CANARY-REPRO")),
           "Technical template retains the fields omitted by prueba as a control")
        todo = render_report(fixture, "en", "todo", plantillas=test_templates)
        ok("REQ-RPT-056", all(v in todo for v in ("| ID | Title | Severity | Target | CVSS | CWE | CVE |", "CANARY-SUMMARY", "CANARY-IMPACT", "CANARY-REMEDIATION", "CANARY-VECTOR", "CANARY-JUSTIFICATION", "CWE-79", "CVE-2024-0001", "CANARY-COMMAND", "CANARY-ARTIFACT", "CANARY-OUTPUT", "CANARY-REPRO"))
           and "CANARY-BLOCKER" not in todo,
           "todo renders each selected table column and reportable field; confirmed-row blocker history stays hidden")
        blocker_fields = report_fields(fixture[4], "en", ("blocker",))[2]
        ok("REQ-RPT-056", any(label == "Blocker" and value == "CANARY-ONLY-BLOCKER" for _, label, value in blocker_fields)
           and "F-T7-E" not in todo,
           "blocker is a known field for a validation-required row but that non-included row stays out of the report")
        selected_ids = {row["id"] for row in included(fixture)}
        ok("REQ-RPT-056", selected_ids == {"F-T7-A", "F-T7-F"} and all(f"{fid}" in todo for fid in selected_ids)
           and all(f"F-T7-{letter}" not in todo for letter in "BCDEG") and "KB-CANARY" not in todo,
           "all sections and fields still show only included IDs and never KB")
        original_included = included
        calls = []
        def counted_included(rows, *args):
            calls.append(rows)
            return original_included(rows, *args)
        with mock.patch(__name__ + ".included", side_effect=counted_included):
            report_model(fixture, "en", "todo", plantillas=test_templates)
        ok("REQ-RPT-056", calls == [fixture], "report_model calls included(rows) exactly once")
        notices_ok = all(DOC[lang]["notice"] in render_report(fixture, lang, name, plantillas=test_templates)
                         for lang in LABELS for name in test_templates)
        ok("REQ-RPT-056", notices_ok, "fixed D1 notice appears in every language and valid template")
        model = report_model(fixture, "en", "prueba", plantillas=test_templates)
        ok("REQ-RPT-057", model["accent"] == "azul" and "**Critical:** 1" in en and "**Críticas:** 1" in es,
           "selected palette name and template count labels are visible in the projection")
        hostile_values = ("`", "|", "## ", "](http://x)", "![a](http://x)", "</style>", "<script>", "javascript:alert(1)", "x) Tj ET BT /F1 99 Tf (y)")
        hostile_ok = True
        line_fields = ("antetitulo", "titulo", "cliente", "autor", "periodo", "version", "clasificacion")
        for field in line_fields:
            for i, payload in enumerate(hostile_values):
                marker = f"ZQX{i}"
                hostile = f"{marker}{payload}{marker}"
                hostile_template = copy.deepcopy(SELFTEST_TEMPLATE)
                hostile_template["textos"]["en"][field] = hostile
                try:
                    hostile_valid = validate_template("hostile", json.dumps(hostile_template, ensure_ascii=False).encode())
                except Refusal:
                    hostile_ok = False
                    continue
                hostile_map = {**test_templates, "hostile": Plantilla("hostile", "0" * 64, hostile_valid)}
                output = render_report(fixture, "en", "hostile", plantillas=hostile_map)
                outside = _CODE_SPAN.sub("", output)
                outside = re.sub(r"(?ms)^(`{3,})\n.*?\n\1$", "", outside)
                expected_hostile = hostile.upper() if field == "antetitulo" else hostile
                hostile_ok = hostile_ok and marker in output and marker not in outside
        for i, payload in enumerate(hostile_values):
            marker = f"ZQXLABEL{i}"
            hostile = f"{marker}{payload}{marker}"
            allowed = hostile[0].isalpha() and all(c.isalnum() or c in _LABEL_PUNCT for c in hostile)
            for field in ("subtitulo", "section-title"):
                hostile_template = copy.deepcopy(SELFTEST_TEMPLATE)
                if field == "subtitulo":
                    hostile_template["textos"]["en"][field] = hostile
                else:
                    hostile_template["secciones"][0]["titulo"]["en"] = hostile
                try:
                    hostile_valid = validate_template("hostile", json.dumps(hostile_template, ensure_ascii=False).encode())
                    accepted = True
                except Refusal:
                    hostile_valid, accepted = None, False
                hostile_ok = hostile_ok and accepted == allowed
                if accepted:
                    hostile_map = {**test_templates, "hostile": Plantilla("hostile", "0" * 64, hostile_valid)}
                    hostile_ok = hostile_ok and marker in render_report(fixture, "en", "hostile", plantillas=hostile_map)
        for field, payload in (("titulo", "linea\nquebrada"), ("cliente", "línea\u2028hostil"), ("autor", "control\x01")):
            marker = f"ZQX-NONPRINT-{field}"
            hostile_template = copy.deepcopy(SELFTEST_TEMPLATE)
            hostile_template["textos"]["en"][field] = f"{marker}{payload}{marker}"
            try:
                validate_template("hostile", json.dumps(hostile_template, ensure_ascii=False).encode())
                hostile_ok = False
            except Refusal:
                pass
        ok("REQ-RPT-056", hostile_ok, "printable hostile template lines stay inside Markdown code spans")
        forbidden = ("eval(", "exec(", "format_map", "Template(", "importlib", ".format(")
        sources = (inspect.getsource(validate_template), inspect.getsource(load_templates), inspect.getsource(report_model), inspect.getsource(render_report))
        with mock.patch("socket.socket", side_effect=AssertionError("socket opened")):
            socket_free = load_templates(template_dir)[0].keys() == test_templates.keys() and bool(render_report(fixture, "en", "todo", plantillas=test_templates))
        ok("REQ-RPT-056", not any(token in source for source in sources for token in forbidden) and socket_free,
           "template loading and rendering use no dynamic evaluation or sockets")
    bad_templates = [
        ("json roto", b"{", "json: no es JSON válido"), ("no utf8", b"\xff", "json: no es UTF-8"),
        ("clave repetida", b'{"etiqueta":"a","etiqueta":"b"}', "json: clave repetida etiqueta"),
        ("constante", json.dumps(template_data).replace('"acento": "grafito"', '"acento": NaN').encode(), "json: constante no estándar NaN"),
        ("clave raíz", {**template_data, "aviso": "falso"}, "raíz.aviso"), ("clave kb", {**template_data, "kb": []}, "raíz.kb"),
        ("clave comentarios", {**template_data, "comentarios": []}, "raíz.comentarios"), ("clave interna", {**template_data, "__class__": "x"}, "raíz.__class__"),
        ("idioma", {**template_data, "textos": {**template_data["textos"], "fr": {}}}, "textos.fr"),
        ("etiqueta charset", {**template_data, "etiqueta": "- lista"}, "etiqueta"),
        ("rótulo control", {**template_data, "etiqueta": "Texto\nhostil"}, "etiqueta"),
        ("etiqueta larga", {**template_data, "etiqueta": "A" * 25}, "etiqueta"),
        ("texto largo", {**template_data, "textos": {**template_data["textos"], "es": {**template_data["textos"]["es"], "titulo": "x" * 121}}}, "textos.es.titulo"),
        ("texto U2028", {**template_data, "textos": {**template_data["textos"], "es": {**template_data["textos"]["es"], "titulo": "línea\u2028hostil"}}}, "textos.es.titulo"),
        ("secciones límite", {**template_data, "secciones": template_data["secciones"] * 3}, "secciones"),
        ("trece secciones", {**template_data, "secciones": template_data["secciones"] + [template_data["secciones"][0]] * 7}, "secciones"),
        ("sin hallazgos", {**template_data, "secciones": template_data["secciones"][:-2]}, "secciones"),
        ("prosa una línea", {**template_data, "secciones": [{**template_data["secciones"][0], "prosa": "titulo"}, *template_data["secciones"][1:]]}, "secciones.0.prosa"),
        ("prosa fuera borrador", {**template_data, "borrador": [k for k in template_data["borrador"] if k != "resumen"]}, "secciones.0.prosa"),
        ("campos repetidos", {**template_data, "secciones": [*template_data["secciones"][:4], {**template_data["secciones"][4], "hallazgos": {"ficha": "completa", "campos": ["impact", "impact"]}}, *template_data["secciones"][5:]]}, "secciones.4.hallazgos.campos"),
        ("campo kb", {**template_data, "secciones": [*template_data["secciones"][:4], {**template_data["secciones"][4], "hallazgos": {"ficha": "completa", "campos": ["kb"]}}, *template_data["secciones"][5:]]}, "secciones.4.hallazgos.campos"),
        ("ficha corta cvss", {**template_data, "secciones": [*template_data["secciones"][:4], {**template_data["secciones"][4], "hallazgos": {"ficha": "corta", "campos": ["cvss"]}}, *template_data["secciones"][5:]]}, "secciones.4.hallazgos.campos"),
        ("aviso plantilla", {**template_data, "secciones": [*template_data["secciones"][:4], {**template_data["secciones"][4], "aviso": "falso"}, *template_data["secciones"][5:]]}, "secciones.4.aviso"),
        ("acento", {**template_data, "acento": "#ff0000"}, "acento"), ("acento desconocido", {**template_data, "acento": "rojo"}, "acento"),
        ("notice raíz", {**template_data, "notice": "variable"}, "raíz.notice"),
    ]
    for label_, value, expected in bad_templates:
        raw = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode()
        try:
            validate_template("invalida", raw)
            refused = False
        except Refusal as e:
            refused = "invalida.json" in str(e) and expected in str(e) and "Plantilla" in str(e)
        ok("REQ-RPT-055", refused, f"invalid template {label_!r} is refused naming invalida.json and {expected}")
    for bad_name in ("A", "a.b", "a\"b", "ñ", "../x"):
        try:
            validate_template(bad_name, json.dumps(template_data).encode())
            refused = False
        except Refusal as e:
            refused = f"{bad_name}.json" in str(e) and "nombre" in str(e)
        ok("REQ-RPT-055", refused, f"invalid template name {bad_name!r} is named in the rejection")
    try:
        validate_template("invalida", b" " * (TEMPLATE_MAX_BYTES + 1))
        refused = False
    except Refusal as e:
        refused = "invalida.json" in str(e) and "archivo" in str(e)
    ok("REQ-RPT-055", refused, "oversized template rejection names invalida.json and archivo")
    with tempfile.TemporaryDirectory(dir=tmp) as temp:
        folder = Path(temp) / "templates"
        folder.mkdir()
        shutil.copyfile(TEMPLATES_DIR / "tecnico.json", folder / "tecnico.json")
        shutil.copyfile(TEMPLATES_DIR / "ejecutivo.json", folder / "ejecutivo.json")
        invalid_path = json.loads((TEMPLATES_DIR / "tecnico.json").read_text(encoding="utf-8"))
        invalid_path["kb"] = []
        (folder / "invalid.json").write_text(json.dumps(invalid_path), encoding="utf-8")
        _, invalid_errors = load_templates(folder)
        ok("REQ-RPT-055", any("invalid.json" in e and "raíz.kb" in e for e in invalid_errors),
           "loader preserves the invalid template filename and offending key path")
        (folder / "extra.json").write_bytes(b"{}")
        (folder / "large.json").write_bytes(b" " * (TEMPLATE_MAX_BYTES + 1))
        os.mkfifo(folder / "fifo.json")
        (folder / "link.json").symlink_to(folder / "tecnico.json")
        loaded, load_errors = load_templates(folder)
        named_bad_files = ("invalid.json", "extra.json", "large.json", "fifo.json", "link.json")
        ok("REQ-RPT-055", set(loaded) == set(BUILTIN)
           and all(any(filename in error for error in load_errors) for filename in named_bad_files)
           and all("Plantilla " in e and ":" in e for e in load_errors),
           "regular files load while malformed, oversized, linked and FIFO templates are rejected with named errors")
        for i in range(17): shutil.copyfile(TEMPLATES_DIR / "tecnico.json", folder / f"extra-{i:02}.json")
        _, overflow_errors = load_templates(folder)
        ok("REQ-RPT-055", any("máximo de 16" in e for e in overflow_errors), "the loader caps discovered templates at sixteen")
        missing, missing_errors = load_templates(folder / "absent")
        ok("REQ-RPT-055", not missing and any("falta la plantilla incorporada tecnico.json" in e for e in missing_errors), "a missing template directory reports missing built-ins")
        linked_dir = Path(temp) / "linked-dir"
        linked_dir.symlink_to(folder, target_is_directory=True)
        linked, linked_errors = load_templates(linked_dir)
        ok("REQ-RPT-055", not linked and linked_errors, "a symlink template directory is rejected")

    cli_root = tmp / "template-cli"
    cli_code = cli_root / "code"
    cli_templates = cli_code / "report-templates"
    cli_templates.mkdir(parents=True)
    shutil.copy2(Path(__file__), cli_code / "findings.py")
    for builtin in BUILTIN:
        shutil.copyfile(TEMPLATES_DIR / f"{builtin}.json", cli_templates / f"{builtin}.json")
    prueba = json.loads((cli_templates / "tecnico.json").read_text(encoding="utf-8"))
    prueba["etiqueta"] = "Prueba"
    prueba["textos"]["es"]["antetitulo"] = "Informe de prueba"
    prueba["textos"]["en"]["antetitulo"] = "Test report"
    prueba["borrador"].remove("metodologia")
    prueba["secciones"] = [s for s in prueba["secciones"] if s.get("prosa") != "metodologia"]
    (cli_templates / "prueba.json").write_text(json.dumps(prueba, ensure_ascii=False), encoding="utf-8")
    cli_ledger = cli_root / "ledger.jsonl"
    _save(cli_ledger, [])
    cli_script = cli_code / "findings.py"
    valid_cli = subprocess.run([sys.executable, str(cli_script), "render", "--ledger", str(cli_ledger), "--tipo", "prueba", "--lang", "es"], capture_output=True, text=True)
    valid_cli_en = subprocess.run([sys.executable, str(cli_script), "render", "--ledger", str(cli_ledger), "--tipo", "prueba", "--lang", "en"], capture_output=True, text=True)
    ok("REQ-RPT-049", valid_cli.returncode == valid_cli_en.returncode == 0 and "INFORME DE PRUEBA" in valid_cli.stdout and "TEST REPORT" in valid_cli_en.stdout,
       "CLI loads a file-only template named prueba")
    bad_cli = [subprocess.run([sys.executable, str(cli_script), "render", "--ledger", str(cli_ledger), "--tipo", name], capture_output=True, text=True)
               for name in ("otro", "tecnico.json", "../x")]
    ok("REQ-RPT-049", all(p.returncode != 0 and not p.stdout and "válidas: tecnico, ejecutivo, prueba" in p.stderr for p in bad_cli),
       "CLI rejects unknown and non-slug template names without output and lists valid templates")
    draft_path = cli_root / "draft.json"
    draft_path.write_text(json.dumps({"resumen": "CLI draft"}), encoding="utf-8")
    draft_cli = subprocess.run([sys.executable, str(cli_script), "render", "--ledger", str(cli_ledger), "--tipo", "prueba", "--borrador", str(draft_path)], capture_output=True, text=True)
    draft_path.write_text(json.dumps({"metodologia": "not in prueba"}), encoding="utf-8")
    invalid_draft_cli = subprocess.run([sys.executable, str(cli_script), "render", "--ledger", str(cli_ledger), "--tipo", "prueba", "--borrador", str(draft_path)], capture_output=True, text=True)
    ok("REQ-RPT-049", draft_cli.returncode == 0 and "CLI draft" in draft_cli.stdout and invalid_draft_cli.returncode != 0 and not invalid_draft_cli.stdout,
       "CLI validates drafts against the selected template's allowed fields")

    def ok_unless_root(req: str, cond: bool, desc: str) -> None:
        """A case that is vacuous as root (the chown paths only run for root): say so instead of counting it."""
        if os.getuid() == 0:
            print(f"skip {req} {desc} (running as root: NOT checked)")
        else:
            ok(req, cond, desc)

    # REQ-LED-007: canonical fingerprints and compare-before-write.
    sample = {"id": "F-1", "status": "hypothesis", "title": "x"}
    ok("REQ-LED-007", fingerprint(sample) == fingerprint(dict(reversed(list(sample.items())))),
       "fingerprint ignores key order")
    ok("REQ-LED-007", fingerprint(sample) != fingerprint({**sample, "title": "y"}),
       "fingerprint changes with row content")
    stale = tmp / "stale.jsonl"
    _save(stale, [sample])
    stale_before = stale.read_bytes()
    try:
        set_row(stale, "F-1", status="triaged", expect="stale")
        stale_refusal = None
    except Refusal as error:
        stale_refusal = error.kind
    ok("REQ-LED-007", stale_refusal == "stale" and stale.read_bytes() == stale_before,
       "stale expected fingerprint refuses without writing")
    for kind, rows, fid, state, kwargs in (
            ("no_corroboration", [sample], "F-1", "confirmed", {}),
            ("no_blocker", [sample], "F-1", "needs_validation", {}),
            ("not_unique", [sample, sample], "F-1", "triaged", {}),
            ("corrupt", None, "F-1", "triaged", {})):
        target = tmp / f"{kind}.jsonl"
        target.write_bytes(b"not-json\n" if rows is None else "".join(json.dumps(r) + "\n" for r in rows).encode())
        try:
            set_row(target, fid, status=state, **kwargs)
            actual_kind = None
        except Refusal as error:
            actual_kind = error.kind
        ok("REQ-LED-003" if kind in ("no_corroboration", "no_blocker") else "REQ-LED-004" if kind == "corrupt" else "REQ-LED-006",
           actual_kind == kind, f"set refusal exposes kind {kind}")
    cli_ledger = tmp / "cli.jsonl"
    cli_ledger.write_text(json.dumps(sample) + "\n")
    cli = subprocess.run([sys.executable, __file__, "set", "--ledger", str(cli_ledger), "--id", "F-1",
                          "--status", "confirmed"], capture_output=True, text=True)
    cli_message = ("refusing to confirm F-1 on a single signal: pass --corroboration describing the independent "
                   "second signal that agrees (style.md: a single positive is a lead, corroboration makes it a finding)")
    ok("REQ-LED-003", cli.returncode == 1 and cli.stderr.strip() == cli_message,
       "CLI set retains its exit code and refusal text")
    # REQ-LED-007: with max_bytes (the web's call) set_row never reads through a symlink, never blocks on a
    # FIFO and refuses a ledger over the cap, all before saving.
    import threading, time
    guarded = tmp / "guarded"
    guarded.mkdir()
    outside = tmp / "outside.jsonl"
    outside.write_text(json.dumps(sample) + "\n")
    outside_before = outside.read_bytes()
    linked, fifo, big = guarded / "linked.jsonl", guarded / "fifo.jsonl", guarded / "big.jsonl"
    linked.symlink_to(outside)
    os.mkfifo(fifo)
    big.write_text(json.dumps({**sample, "output": "x" * 200}) + "\n")
    big_before = big.read_bytes()
    guarded_kinds: dict[str, str] = {}

    def guarded_set(name: str, path: Path) -> None:
        try:
            set_row(path, "F-1", status="triaged", max_bytes=100)
        except Refusal as error:
            guarded_kinds[name] = error.kind

    for name, path in (("link", linked), ("fifo", fifo), ("big", big)):
        worker = threading.Thread(target=guarded_set, args=(name, path), daemon=True)
        worker.start()
        worker.join(2)
    ok("REQ-LED-007", guarded_kinds == {"link": "not_regular", "fifo": "not_regular", "big": "too_large"}
       and linked.is_symlink() and outside.read_bytes() == outside_before and big.read_bytes() == big_before,
       "set_row with max_bytes refuses a symlinked, FIFO or oversized ledger within 2 s, without following or writing")

    # REQ-RPT-008: the capped read pulls at most max_bytes + 1 from the kernel and a socket is not a regular file
    read_sizes: list[int] = []
    real_read, real_fstat = os.read, os.fstat
    big.write_bytes(b"x" * 10_000)

    def counting_read(fd, n):
        chunk = real_read(fd, n)
        read_sizes.append(len(chunk))
        return chunk

    # the file "grows after fstat": fstat reports it small, so only the read loop bounds the bytes pulled
    os.read = counting_read
    os.fstat = lambda fd: types.SimpleNamespace(st_mode=real_fstat(fd).st_mode, st_size=0)
    try:
        _read_regular(big, 100)
    except Refusal:
        pass
    finally:
        os.read, os.fstat = real_read, real_fstat
    import socket
    socket_path = guarded / "s.jsonl"
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(socket_path))
        try:
            _read_regular(socket_path, 100)
            socket_kind = None
        except Refusal as error:
            socket_kind = error.kind
    ok("REQ-RPT-008", sum(read_sizes) == 101 and socket_kind == "not_regular",
       "a capped read pulls at most max_bytes + 1 bytes and a socket swapped in is not_regular")

    def add_ns(**k):
        base = dict(ledger=str(led), title="t", severity="low", status="hypothesis",
                    target="10.0.0.5", command="", artifact="", output="", repro=[], kb=[])
        return ns(**{**base, **k})

    def refusal(fn, args) -> str | None:
        try:
            fn(args)
        except SystemExit as e:
            return str(e.code)
        return None

    def rendered(show_all: bool) -> str:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cmd_render(ns(ledger=str(led), all=show_all))
        return buf.getvalue()

    baseline = [{"id": "F-0001", "title": "baseline", "severity": "high", "status": "confirmed",
                 "corroboration": "second signal", "target": "fixture", "summary": "sum `x`", "impact": "impact",
                 "remediation": "fix", "cvss": 7.5, "cwe": "CWE-1", "cve": "CVE-2020-1234",
                 "evidence": {"command": "curl x", "artifact": "a.txt", "output": "```\noutput\n```"},
                 "repro": ["step"], "kb": ["slug"]}]
    expected = ("# Findings\n\n## `F-0001` — `baseline`\n- **Severity:** `high` · **Status:** `confirmed` · **Target:** `fixture`\n"
                "- **Summary:**\n\n```\nsum `x`\n```\n- **Impact:** `impact`\n- **Remediation:** `fix`\n- **CVSS:** `7.5`\n- **CWE:** `CWE-1`\n"
                "- **CVE:** `CVE-2020-1234`\n- **Corroboration:** `second signal`\n- **Command:** `curl x`\n- **Artifact:** `a.txt`\n"
                "- **Evidence:**\n\n````\n```\noutput\n```\n````\n- **Repro:**\n  1. `step`\n\n")
    ok("REQ-LED-002", render_md(baseline) == expected, "render Markdown baseline remains byte-for-byte stable")
    kb_row = {**baseline[0], "kb": ["KB-CANARY-slug"]}
    kb_outputs = [render_md([kb_row], lang) for lang in LABELS] + [render_report([kb_row], lang, tipo, None, "ws") for lang in LABELS for tipo in DRAFT_FIELDS]
    ok("REQ-LED-002", all("KB-CANARY" not in out and "KB:" not in out for out in kb_outputs),
       "a row with kb set renders no KB line or value in the plain, Technical or Executive Markdown (the KB is internal)")
    # an inline value (id, title, severity, status, target, step, KB) is target data: outside its code span
    # the report must be the same skeleton whatever it holds — no HTML, image, link, autolink or forged bold
    hostile_inline = ['<img src="https://attacker.example/opened.png">', "![x](https://attacker.example/y.png)",
                      "[ok](javascript:alert(1))", "<https://attacker.example>", "lab · **Severity:** critical _em_ *i*",
                      "a ``` b ` c", "`edge`", "trail\\", "# head", "a | b", ""]
    inline_row = lambda v: {"id": v, "title": v, "severity": v, "status": v, "target": v, "repro": [v, v], "kb": [v, v]}
    hostile_md = render_md([inline_row(v) for v in hostile_inline], show_all=True)
    skeleton = _CODE_SPAN.sub("C", hostile_md)
    ok("REQ-LED-002", skeleton == _CODE_SPAN.sub("C", render_md([inline_row("v") for _ in hostile_inline], show_all=True))
       and not any(t in skeleton for t in ("<", "![", "](", "\\", "_", "*i*")) and all(v in hostile_md for v in hostile_inline),
       "hostile inline values each stay inside one code span and the report skeleton outside them does not change")
    uncorroborated = [{**baseline[0], "corroboration": ""},
                      {**baseline[0], "id": "F-0002", "corroboration": "   "}]
    ok("REQ-LED-002", all(f"F-000{i}" not in render_md(uncorroborated) for i in (1, 2))
       and all(f"F-000{i}" in render_md(uncorroborated, show_all=True) for i in (1, 2)),
       "confirmed findings without nonblank corroboration are excluded unless --all is set")
    # one blankness rule: a corroboration of only Cc/Cf characters is no corroboration for render and set_row
    invisible = [{**baseline[0], "corroboration": "​"}, {"id": "F-9", "status": "hypothesis", "title": "t"}]
    invisible_ledger = tmp / "invisible.jsonl"
    _save(invisible_ledger, invisible)
    invisible_before = invisible_ledger.read_bytes()
    try:
        set_row(invisible_ledger, "F-9", status="confirmed", corroboration="​")
        invisible_kind = None
    except Refusal as error:
        invisible_kind = error.kind
    ok("REQ-LED-002", "F-0001" not in render_md(invisible) and "F-0001" in render_md(invisible, show_all=True)
       and invisible_kind == "no_corroboration" and invisible_ledger.read_bytes() == invisible_before,
       "a zero-width corroboration is excluded from render and refused by set_row")
    # a row with a number past float range reads as a bad line, so no rewrite can turn it into `Infinity`
    huge_ledger = tmp / "huge.jsonl"
    huge_ledger.write_text(json.dumps(sample) + '\n{"id": "F-2", "cvss": 1e400}\n')
    huge_before = huge_ledger.read_bytes()
    try:
        set_row(huge_ledger, "F-1", status="triaged")
        huge_kind = None
    except Refusal as error:
        huge_kind = error.kind
    ok("REQ-LED-004", [n for n, _ in _scan(huge_ledger)[1]] == [2] and huge_kind == "corrupt"
       and huge_ledger.read_bytes() == huge_before,
       "a number that overflows to infinity is a bad line and set_row refuses without writing")
    # the report never shows the blocker of a confirmed row; the ledger keeps it
    blocked_ledger = tmp / "blocked.jsonl"
    _save(blocked_ledger, [{"id": "F-1", "status": "hypothesis", "title": "t", "severity": "low"}])
    set_row(blocked_ledger, "F-1", status="needs_validation", blocker="operator pastes the response")
    set_row(blocked_ledger, "F-1", status="confirmed", corroboration="second signal")
    blocked_rows = _load(blocked_ledger)
    ok("REQ-LED-002", blocked_rows[0]["blocker"] == "operator pastes the response"
       and all("operator pastes" not in render_md(blocked_rows, lang) for lang in LABELS)
       and "operator pastes" in render_md([{**blocked_rows[0], "status": "needs_validation"}], show_all=True),
       "a confirmed row keeps its blocker in the ledger but not in the report")
    # fields of one row sit side by side in the status line: their code spans must not merge
    adjacent = {**baseline[0], "severity": "`x", "status": 'a `` <img src="https://attacker.example/b.png">'}
    adjacent_md = render_md([adjacent], show_all=True)
    ok("REQ-LED-002", "<" not in _CODE_SPAN.sub("C", adjacent_md) and adjacent["status"] in adjacent_md,
       "adjacent hostile values in different fields leave no markup outside code spans")
    spanish = render_md(baseline, "es")
    expected_spanish = render_md(baseline)
    for key, english_label in LABELS["en"].items():
        expected_spanish = expected_spanish.replace(f"**{english_label}:**", f"**{LABELS['es'][key]}:**")
    ok("REQ-LED-002", spanish == expected_spanish and "F-0001" in spanish,
       "Spanish translates labels only and keeps report values")
    try:
        render_md(baseline, "fr")
        bad_language = False
    except ValueError:
        bad_language = True
    ok("REQ-LED-002", bad_language, "unsupported report language raises without emitting a report")

    baseline_ledger = tmp / "baseline.jsonl"
    _save(baseline_ledger, baseline)
    language_cli = subprocess.run([sys.executable, os.path.abspath(__file__), "render", "--ledger", str(baseline_ledger), "--lang", "es"],
                                  capture_output=True, text=True)
    invalid_language_cli = subprocess.run([sys.executable, os.path.abspath(__file__), "render", "--ledger", str(baseline_ledger), "--lang", "fr"],
                                          capture_output=True, text=True)
    ok("REQ-LED-002", language_cli.returncode == 0 and "**Severidad:**" in language_cli.stdout
       and invalid_language_cli.returncode != 0 and not invalid_language_cli.stdout,
       "CLI accepts Spanish and rejects unknown language without report output")

    # REQ-LED-002 (spec 019b): the report by type, with an operator draft; Technical without a draft is today's render.
    def confirmed_row(fid, severity, title, **extra):
        return {"id": fid, "status": "confirmed", "severity": severity, "title": title, "target": "10.0.0.1",
                "corroboration": "CANARY-CORR", "summary": "CANARY-SUMMARY", "remediation": "CANARY-REM",
                "repro": ["CANARY-REPRO"], "evidence": {"command": "CANARY-CMD", "artifact": "CANARY-ART",
                                                      "output": "CANARY-OUT"}, **extra}
    typed = [confirmed_row("F-0001", "high", "T`itle | pipe\n## injected", impact="Impact text"),
             confirmed_row("F-0002", "critical", "No impact"),
             {"id": "F-0003", "status": "hypothesis", "severity": "low", "title": "Not included"}]
    draft = {"titulo": "Informe X", "cliente": "acme-codename", "resumen": "RESUMEN-D", "alcance": "ALC-D",
             "metodologia": "METOD-D", "limitaciones": "LIM-D", "recomendaciones": "REC-D"}
    draft_bytes = json.dumps(draft).encode()
    technical = render_report(typed, "en", "tecnico", validate_draft("tecnico", draft_bytes), "ws-x")
    ok("REQ-LED-002", technical.splitlines()[:8] == ["`CONFIDENTIAL · DRAFT`", "", "`TECHNICAL REPORT / ws-x`", "", "# `Informe X`", "",
                                                   "Technical penetration testing report", ""]
       and "- **Prepared for:** `acme-codename`" in technical and "- **Prepared by:** `GEKKO Offensive Security`" in technical
       and "- **Assessment period:** `To be defined`" in technical and "- **Version:** `0.1 · Draft`" in technical
       and "> Document subject to review. Unconfirmed findings are not included." in technical,
       "Technical cover: classification, eyebrow, title, subtitle, 2x2 data with defaults and the review notice")
    ok("REQ-LED-002", technical.index("## 01 Executive summary") < technical.index("RESUMEN-D") < technical.index("## 02 Scope") < technical.index("ALC-D")
       < technical.index("## 03 Methodology") < technical.index("## 04 Limitations") < technical.index("## 05 Findings")
       < technical.index("**Critical:** 1 · **High:** 1 · **Medium:** 0 · **Low:** 0") < technical.index("### `F-0002`") < technical.index("### `F-0001`")
       < technical.index("## 06 Recommendations") < technical.index("REC-D"),
       "Technical numbers its sections, opens the findings with severity counts and ends with the recommendations")
    ok("REQ-LED-002", "- **Severity:** `Critical` · **Status:** `Confirmed`" in technical
       and "- **Severidad:** `Crítica` · **Estado:** `Confirmado`" in render_report(typed, "es", "tecnico", None, "ws")
       and "INFORME TÉCNICO / ws" in render_report(typed, "es", "tecnico", None, "ws")
       and "`CONFIDENCIAL · BORRADOR`" in render_report(typed, "es", "tecnico", None)
       and "- **Preparado para:** `Cliente no definido`" in render_report(typed, "es", "tecnico", None),
       "severity, status and the cover defaults are localized per language")
    body = render_md(typed, "en")
    executive = render_report(typed, "en", "ejecutivo", validate_draft("ejecutivo", json.dumps(
        {k: v for k, v in draft.items() if k != "metodologia"}).encode()))
    table = [l for l in executive.splitlines() if l.startswith("| `F-")]
    cells = [len(re.split(r"(?<!\\)\|", l)) - 2 for l in table]
    ok("REQ-LED-002", len(table) == 2 and cells == [4, 4] and executive.count("\n### ") == 2
       and "- **Critical:** 1 · **High:** 1 · **Medium:** 0 · **Low:** 0" in executive
       and "\n## injected" not in executive and "- **Impact:** `Impact text`" in executive
       and executive.index("RESUMEN-D") < executive.index("ALC-D") < executive.index("## 03 Findings by severity")
       and executive.index("## 04 Findings\n") < executive.index("LIM-D") < executive.index("REC-D")
       and "METOD-D" not in executive,
       "Executive: severity counts, one table row and one ### per included finding, hostile title stays in its span")
    ok("REQ-LED-002", not any(c in executive for c in ("CANARY-SUMMARY", "CANARY-REM", "CANARY-REPRO", "CANARY-CMD",
                                                         "CANARY-ART", "CANARY-OUT", "CANARY-CORR")),
       "Executive carries no evidence, command, artifact, repro, corroboration, summary or remediation")
    ok("REQ-LED-002", "_No hay hallazgos confirmados._" in render_report([typed[2]], "es", "ejecutivo", None)
       and "| ID |" not in render_report([typed[2]], "es", "ejecutivo", None), "Executive with nothing included says so, no table")
    for bad_tipo, bad_data, field in (
            ("ejecutivo", b'{"metodologia": "x"}', "metodologia"), ("tecnico", b'{"nope": "x"}', "nope"),
            ("tecnico", b'{"resumen": 5}', "resumen"), ("tecnico", json.dumps({"resumen": "\u20ac" * 1366}).encode(), "resumen"),
            ("tecnico", b'{"titulo": "a\\nb"}', "titulo"), ("tecnico", b'[1]', "objeto"), ("tecnico", b'\xff', "JSON"),
            ("otro", b'{}', "otro")):
        try:
            validate_draft(bad_tipo, bad_data)
            refused = None
        except Refusal as error:
            refused = (error.kind, field in str(error))
        ok("REQ-LED-002", refused == ("invalid_draft", True), f"draft {bad_data[:24]!r} for {bad_tipo} is refused naming {field}")
    esc_key = json.dumps({"\x1b]0;X\x07\x1b[31m": "x"}).encode()
    esc_draft = tmp / "esc-draft.json"
    esc_draft.write_bytes(esc_key)
    try:
        validate_draft("tecnico", esc_key)
        esc_msg = ""
    except Refusal as error:
        esc_msg = str(error)
    _save(tmp / "typed.jsonl", typed)
    esc_cli = subprocess.run([sys.executable, os.path.abspath(__file__), "render", "--ledger", str(tmp / "typed.jsonl"), "--tipo", "tecnico",
                              "--borrador", str(esc_draft)], capture_output=True, text=True)
    ok("REQ-LED-002", esc_msg and "\x1b" not in esc_msg and "\x07" not in esc_msg and esc_cli.returncode != 0 and "\x1b" not in esc_cli.stderr,
       "a refusal naming a hostile draft key carries no control byte, also on the CLI's stderr")
    ok("REQ-LED-002", validate_draft("tecnico", json.dumps({"resumen": "\u20ac" * 1365}).encode())["resumen"] == "\u20ac" * 1365
       and render_report(typed, "en", "tecnico", validate_draft("tecnico", b"{}")) == render_report(typed, "en", "tecnico", None),
       "a draft at its 4096-byte cap is accepted and an empty draft is no draft")
    draft_file = tmp / "draft.json"
    draft_file.write_bytes(draft_bytes)
    typed_ledger = tmp / "typed.jsonl"
    _save(typed_ledger, typed)
    def run_render(*args):
        return subprocess.run([sys.executable, os.path.abspath(__file__), "render", "--ledger", str(typed_ledger), *args],
                              capture_output=True, text=True)
    cli_tech = run_render("--tipo", "tecnico", "--borrador", str(draft_file), "--lang", "es", "--workspace", "ws-x")
    cli_exec = run_render("--tipo", "ejecutivo", "--workspace", "ws-x")
    ok("REQ-LED-002", cli_tech.stdout == render_report(typed, "es", "tecnico", validate_draft("tecnico", draft_bytes), "ws-x")
       and cli_exec.stdout == render_report(typed, "en", "ejecutivo", None, "ws-x") and cli_tech.returncode == cli_exec.returncode == 0,
       "render --tipo --borrador prints exactly the one projection")
    md_lines = {l for l in render_md(typed, "en").splitlines() if l and not l.startswith("#") and not l.startswith("- **Severity:**")}
    tech_lines = set(technical.splitlines())
    ok("REQ-LED-002", md_lines <= tech_lines and "CANARY-OUT" in technical and "  1. `CANARY-REPRO`" in technical,
       f"UI-r3 review: every field line of each included finding in render_md (summary, impact, corroboration, command, artifact, evidence fence, repro) is in the Technical report: missing {sorted(md_lines - tech_lines)[:3]}")
    outside_cli = subprocess.run([sys.executable, os.path.abspath(__file__), "render", "--ledger", str(typed_ledger), "--tipo", "tecnico"],
                                 capture_output=True, text=True).stdout
    ok("REQ-LED-002", outside_cli.splitlines()[2] == "`TECHNICAL REPORT`" and tmp.name not in outside_cli,
       "UI-r3 review: render --tipo without --workspace names the folder only when it sits under engagements/<codename>/")
    failing = [run_render("--tipo", "otro"), run_render("--tipo", "ejecutivo", "--borrador", str(draft_file)),
               run_render("--tipo", "tecnico", "--borrador", str(tmp / "missing.json")), run_render("--tipo", "tecnico", "--all"),
               run_render("--borrador", str(draft_file))]
    ok("REQ-LED-002", all(r.returncode != 0 and not r.stdout for r in failing),
       "unknown type, invalid or missing draft, --all with --tipo, draft without --tipo exit non-zero with no report")

    with contextlib.redirect_stdout(io.StringIO()):
        cmd_add(add_ns(title="SQLi in login", severity="high", command="sqlmap -u http://10.0.0.5/login",
                       repro=["POST id=1'"], kb=["web-app-attacks"]))
        cmd_add(add_ns(title="Verbose error"))
    ok("REQ-LED-006", [r["id"] for r in _load(led)] == ["F-0001", "F-0002"], "ids are sequential")

    # §13 — confirming on a single signal is refused; a recorded corroboration is required.
    before = led.read_bytes()
    msg = refusal(cmd_set, ns(ledger=str(led), id="F-0001", status="confirmed",
                              artifact="evidence/dump.txt", corroboration=None))
    ok("REQ-LED-003", msg is not None and led.read_bytes() == before,
       "set confirmed without corroboration is refused and writes nothing")

    cmd_set(ns(ledger=str(led), id="F-0001", status="confirmed", artifact="evidence/dump.txt",
               corroboration="second signal: manual curl repro returned the same 200 + body"))
    r0 = _load(led)[0]
    ok("REQ-LED-003", r0["status"] == "confirmed" and r0["evidence"]["artifact"] == "evidence/dump.txt"
       and r0["corroboration"].startswith("second signal") and r0["updated"] >= r0["created"],
       "set confirmed with corroboration is accepted")

    out = rendered(False)
    ok("REQ-LED-002", "F-0001" in out and "F-0002" not in out, "default render is confirmed only")

    before = led.read_bytes()
    msg = refusal(cmd_set, ns(ledger=str(led), id="F-0002", status="needs_validation",
                              artifact=None, corroboration=None, blocker=None))
    ok("REQ-LED-003", msg is not None and led.read_bytes() == before,
       "set needs_validation without blocker is refused and writes nothing")

    # AC4: the same refusals hold when the call also carries new fields
    for status, extra in (("confirmed", {}), ("needs_validation", {})):
        msg = refusal(cmd_set, ns(ledger=str(led), id="F-0002", status=status, summary="sneaky",
                                  cvss="5.0", artifact=None, corroboration=None, blocker=None, **extra))
        ok("REQ-LED-003", msg is not None and led.read_bytes() == before,
           f"set {status} refused with new fields writes nothing, not even the fields")

    cmd_set(ns(ledger=str(led), id="F-0002", status="needs_validation", artifact=None, corroboration=None,
               blocker="operator must run the payload against the live target and paste the response"))
    r1 = _load(led)[1]
    ok("REQ-LED-003", r1["status"] == "needs_validation" and r1["blocker"].startswith("operator must run"),
       "set needs_validation with blocker is accepted")
    ok("REQ-LED-002", "F-0002" not in rendered(False), "needs_validation is absent from the default render")
    all_out = rendered(True)
    ok("REQ-LED-002", "F-0002" in all_out and "operator must run" in all_out, "--all shows it with its blocker")

    # AC27: add cannot mint a state that only set may reach
    before = led.read_bytes()
    for status in ("confirmed", "needs_validation"):
        msg = refusal(cmd_add, add_ns(status=status))
        ok("REQ-LED-003", msg is not None and led.read_bytes() == before,
           f"add --status {status} is refused and writes nothing")

    # AC1: the six optional fields
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_add(add_ns(title="Full", summary="s", impact="i", remediation="r",
                       cvss="7.5", cwe="CWE-89", cve="CVE-2024-12345"))
    full = _load(led)[2]
    ok("REQ-LED-001", (full["summary"], full["impact"], full["remediation"], full["cwe"], full["cve"])
       == ("s", "i", "r", "CWE-89", "CVE-2024-12345") and full["cvss"] == 7.5
       and isinstance(full["cvss"], float), "add stores the six fields (cvss as a number)")
    ok("REQ-LED-001", not {"summary", "impact", "remediation", "cvss", "cwe", "cve"} & _load(led)[1].keys(),
       "a row added without them carries none of the keys")
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_set(ns(ledger=str(led), id="F-0003", status=None, summary="s2", cvss="9", cwe="CWE-1", cve="CVE-1999-0001",
                   impact=None, remediation="r2"))
        cmd_set(ns(ledger=str(led), id="F-0002", status=None, summary="late"))
        cmd_list(ns(ledger=str(led), status=None))
    rows = _load(led)
    ok("REQ-LED-001", (rows[2]["summary"], rows[2]["cvss"], rows[2]["cwe"], rows[2]["cve"], rows[2]["remediation"],
                       rows[2]["impact"]) == ("s2", 9.0, "CWE-1", "CVE-1999-0001", "r2", "i")
       and rows[1]["summary"] == "late", "set updates the fields it is given and keeps the rest")

    bad_values = [("cvss", "11"), ("cvss", "-0.1"), ("cvss", "abc"), ("cvss", "nan"), ("cwe", "CWE-"),
                  ("cwe", "cwe-79"), ("cwe", "CWE-7x"), ("cve", "CVE-24-1234"), ("cve", "CVE-2024-123"),
                  ("cve", "CVE-2024-12x")]
    before = led.read_bytes()
    add_msgs = [refusal(cmd_add, add_ns(**{field: value})) for field, value in bad_values]
    ok("REQ-LED-001", all(m is not None and f in m for m, (f, _) in zip(add_msgs, bad_values))
       and led.read_bytes() == before, "add rejects malformed cvss/cwe/cve, names the field, ledger unchanged")
    set_msgs = [refusal(cmd_set, ns(ledger=str(led), id="F-0003", status=None, summary="changed", **{field: value}))
                for field, value in bad_values]
    ok("REQ-LED-001", all(m is not None and f in m for m, (f, _) in zip(set_msgs, bad_values))
       and led.read_bytes() == before, "set rejects malformed cvss/cwe/cve, names the field, ledger unchanged")

    # AC3: the fields are projected, and a hostile value cannot break out of its fence
    cmd_set(ns(ledger=str(led), id="F-0003", status="confirmed", corroboration="second signal",
               summary="x ```\n# not a heading\n```"))
    out = rendered(False)
    ok("REQ-LED-002", all(t in out for t in ("CWE-1", "CVE-1999-0001", "9.0", "r2")) and "````" in out,
       "render shows the six fields and widens the fence past a hostile value")

    # AC30 + corrupt lines: every command refuses with the line number, no traceback
    variants = {"broken text": b"not-json", "42": b"42", "[]": b"[]", "null": b"null", '"x"': b'"x"',
                "non-UTF-8": b'{"id":"F-0002","title":"\xff\xfe"}'}
    for name, line in variants.items():
        led.write_bytes(b'{"id":"F-0001"}\n' + line + b"\n")
        before = led.read_bytes()
        msgs = [refusal(cmd_list, ns(ledger=str(led), status=None)),
                refusal(cmd_render, ns(ledger=str(led), all=True)),
                refusal(cmd_add, add_ns()),
                refusal(cmd_set, ns(ledger=str(led), id="F-0001", status="triaged"))]
        ok("REQ-LED-004", all(m is not None and "corrupt ledger" in m and "line 2" in m for m in msgs)
           and led.read_bytes() == before, f"{name} line: list/render/add/set exit with 'corrupt ledger ... line 2'")

    # resilience: partial / hand-edited rows must not crash list or render
    _save(led, [{"id": "F-0001", "title": "x", "severity": "high", "status": "confirmed", "corroboration": "verified", "target": "t",
                 "evidence": {}}, {"id": "F-0099"}])
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_list(ns(ledger=str(led), status=None))
        cmd_render(ns(ledger=str(led), all=True))
    ok("REQ-LED-006", True, "partial rows do not crash list/render")

    _save(led, [{"id": "F-0001", "status": "hypothesis"}, {"id": "F-0001", "status": "hypothesis"}])
    before = led.read_bytes()
    msg = refusal(cmd_set, ns(ledger=str(led), id="F-0001", status="triaged", artifact=None))
    ok("REQ-LED-006", msg is not None and led.read_bytes() == before, "duplicate id makes set refuse")
    ok("REQ-LED-006", _next_id([{"id": "F-"}, {"id": "F-x"}, {"id": "F-0007"}]) == "F-0008",
       "id minting survives non-numeric F- ids")

    # untrusted output with a triple-backtick can't break out of the fence
    _save(led, [{"id": "F-0001", "title": "t", "severity": "high", "status": "confirmed", "corroboration": "verified", "target": "t",
                 "evidence": {"output": "```\n# not a heading\n```"}}])
    ok("REQ-LED-002", "````" in rendered(False), "evidence fence widens past the payload's backticks")
    ok("REQ-LED-006", not led.with_suffix(led.suffix + ".tmp").exists(), "atomic save leaves no temp file")

    # REQ-LED-006: a new ledger is 0660 only under a default ACL (toolbox workspace; 0600 would zero its mask), else 0600.
    def new_modes(acl: bool) -> list[int] | None:
        modes = []
        for mask in (0o022, 0o077):
            fresh = tmp / f"fresh-{'acl' if acl else 'plain'}-{mask:o}" / "findings.jsonl"
            fresh.parent.mkdir()
            if acl and subprocess.run(["setfacl", "-m", f"d:u:{os.getuid()}:rwx", str(fresh.parent)],
                                      capture_output=True).returncode != 0:
                return None
            previous_umask = os.umask(mask)
            try:
                _save(fresh, [{"id": "F-1", "status": "hypothesis"}])
            finally:
                os.umask(previous_umask)
            modes.append(fresh.stat().st_mode & 0o777)
        return modes
    plain = new_modes(False)
    ok("REQ-LED-006", plain == [0o600, 0o600], f"a new ledger outside a default-ACL directory is 0600 under umask 022 and 077 (got {[oct(m) for m in plain]})")
    shared = new_modes(True) if shutil.which("setfacl") else None
    if shared is None:
        print("  skip REQ-LED-006 default-ACL ledger mode NOT checked (no setfacl or no ACL support)")
    else:
        ok("REQ-LED-006", shared == [0o660, 0o660], f"a new ledger under a default ACL is 0660 under umask 022 and 077 (got {[oct(m) for m in shared]})")

    # REQ-LED-007: a rewrite keeps the ledger's permissions; invisible text is no corroboration.
    private = tmp / "private" / "findings.jsonl"
    _save(private, [{"id": "F-1", "status": "hypothesis"}])
    private.chmod(0o600)
    previous_umask = os.umask(0o022)
    try:
        set_row(private, "F-1", status="triaged")
    finally:
        os.umask(previous_umask)
    ok("REQ-LED-007", (private.stat().st_mode & 0o777) == 0o600, "set_row keeps a 0600 ledger at 0600")
    invisible_codes = []
    for invisible in ("\x01", "\u200b", "\u202e\ufeff", " \x07 "):
        invisible_ledger = tmp / "invisible.jsonl"
        invisible_ledger.write_text(json.dumps({"id": "F-1", "status": "hypothesis"}) + "\n")
        confirm = subprocess.run([sys.executable, os.path.abspath(__file__), "set", "--ledger", str(invisible_ledger),
                                  "--id", "F-1", "--status", "confirmed", "--corroboration", invisible],
                                 capture_output=True, text=True)
        invisible_codes.append(confirm.returncode != 0 and "corroboration" not in json.loads(invisible_ledger.read_text()))
    ok("REQ-LED-007", all(invisible_codes), "control and format characters alone are not a corroboration")

    # AC28: 20 real processes at once, none may lose its row
    conc = tmp / "conc" / "findings.jsonl"
    procs = [subprocess.Popen([sys.executable, os.path.abspath(__file__), "add", "--ledger", str(conc),
                               "--title", f"t{i}", "--severity", "low", "--target", "10.0.0.5"],
                              stdout=subprocess.DEVNULL) for i in range(20)]
    codes = [p.wait() for p in procs]
    ids = [r["id"] for r in _load(conc)]
    ok("REQ-LED-005", codes == [0] * 20 and len(ids) == 20 and len(set(ids)) == 20,
       "20 concurrent adds leave 20 rows with 20 distinct ids")

    # L1: lines the json module cannot or must not parse are bad lines, never a traceback
    hostile = {"5000-digit integer": b"1" * 5000, "nesting 100000 deep": b"[" * 100000,
               "NaN constant": b'{"status":"confirmed","cvss":NaN}', "Infinity": b'{"cvss":Infinity}',
               "-Infinity": b'{"cvss":-Infinity}'}
    for name, line in hostile.items():
        led.write_bytes(b'{"id":"F-0001"}\n' + line + b"\n")
        before = led.read_bytes()
        msgs = [refusal(cmd_list, ns(ledger=str(led), status=None)),
                refusal(cmd_render, ns(ledger=str(led), all=True)),
                refusal(cmd_add, add_ns()),
                refusal(cmd_set, ns(ledger=str(led), id="F-0001", status="triaged"))]
        ok("REQ-LED-004", all(m is not None and "corrupt ledger" in m and "line 2" in m for m in msgs)
           and led.read_bytes() == before, f"{name}: list/render/add/set exit with 'corrupt ledger ... line 2'")
    led.write_bytes(b'{"id":"F-0001"}\r\n{"id":"F-0002"}\x0b\n')
    ok("REQ-LED-004", [n for n, _ in _scan(led)[0]] == [1] and [n for n, _ in _scan(led)[1]] == [2],
       "lines split on LF only: CRLF is one line, a trailing \\x0b makes the line bad")

    # L2: the temp file is never a followed symlink; a lone surrogate round-trips
    victim = tmp / "victim.txt"
    victim.write_bytes(b"VICTIM")
    sym = tmp / "sym" / "findings.jsonl"
    sym.parent.mkdir()
    sym.with_suffix(".jsonl.tmp").symlink_to(victim)
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_add(add_ns(ledger=str(sym), title="planted"))
    ok("REQ-LED-006", victim.read_bytes() == b"VICTIM" and [r["title"] for r in _load(sym)] == ["planted"]
       and not sym.with_suffix(".jsonl.tmp").exists(), "a symlink planted at <ledger>.tmp is replaced, never followed")
    lone = tmp / "lone" / "findings.jsonl"
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_add(add_ns(ledger=str(lone), title="caf\udce9"))
        cmd_list(ns(ledger=str(lone), status=None))
        cmd_render(ns(ledger=str(lone), all=True))
    ok("REQ-LED-006", _load(lone)[0]["title"] == "caf\udce9", "a lone surrogate in a title is saved as a JSON escape and reads back identical")

    # REQ-LED-006: the CLI never reads through a link, never blocks on a FIFO and refuses a ledger over the cap
    # (a root process in the toolbox container can plant any of them at <workspace>/findings.jsonl).
    secret = tmp / "other-engagement.jsonl"
    secret.write_bytes(b'{"id":"F-0001","title":"OTHER-ENGAGEMENT-SECRET"}\n')
    linked_ledger = tmp / "cli-link" / "findings.jsonl"
    linked_ledger.parent.mkdir()
    linked_ledger.symlink_to(secret)
    fifo_ledger = tmp / "cli-fifo" / "findings.jsonl"
    fifo_ledger.parent.mkdir()
    os.mkfifo(fifo_ledger)
    big_ledger = tmp / "cli-big" / "findings.jsonl"
    big_ledger.parent.mkdir()
    big_ledger.write_bytes(b'{"id":"F-0001"}\n' * 8)
    cli_kinds = {}
    global LEDGER_MAX_BYTES
    real_cap, LEDGER_MAX_BYTES = LEDGER_MAX_BYTES, 64
    try:
        for name, path in (("link", linked_ledger), ("fifo", fifo_ledger), ("big", big_ledger)):
            for verb, fn, args in (("add", cmd_add, add_ns(ledger=str(path), title="x")),
                                   ("list", cmd_list, ns(ledger=str(path), status=None)),
                                   ("render", cmd_render, ns(ledger=str(path), all=True))):
                try:
                    with contextlib.redirect_stdout(io.StringIO()) as out:
                        fn(args)
                    cli_kinds[f"{name}:{verb}"] = "OTHER-ENGAGEMENT-SECRET" in out.getvalue() and "leaked" or "read"
                except Refusal as error:
                    cli_kinds[f"{name}:{verb}"] = error.kind
    finally:
        LEDGER_MAX_BYTES = real_cap
    ok("REQ-LED-006", all(v == ("too_large" if k.startswith("big") else "not_regular") for k, v in cli_kinds.items())
       and linked_ledger.is_symlink() and b"OTHER-ENGAGEMENT-SECRET" in secret.read_bytes() and secret.read_bytes().count(b"\n") == 1
       and stat.S_ISFIFO(os.lstat(fifo_ledger).st_mode),
       f"CLI add/list/render refuse a symlinked, FIFO or over-cap ledger without following it or writing (got {cli_kinds})")

    # L4: blank is not corroboration or a blocker
    _save(led, [{"id": "F-0001", "status": "hypothesis"}])
    before = led.read_bytes()
    msgs = [refusal(cmd_set, ns(ledger=str(led), id="F-0001", status="confirmed", corroboration=" ")),
            refusal(cmd_set, ns(ledger=str(led), id="F-0001", status="needs_validation", blocker=" "))]
    ok("REQ-LED-003", all(m is not None for m in msgs) and led.read_bytes() == before,
       "a blank --corroboration / --blocker is refused like the empty one and writes nothing")

    # L5: wrong-typed rows do not crash list or render
    _save(led, [{"id": None, "title": ["x"], "evidence": "text", "repro": "one", "kb": [1, {"a": 2}], "severity": ["high"]}])
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_list(ns(ledger=str(led), status=None))
        cmd_render(ns(ledger=str(led), all=True))
    ok("REQ-LED-006", True, "wrong-typed id, title, evidence, repro, kb and severity do not crash list/render")

    # L6: a title / step / target cannot forge a finding heading in the projection
    forged = {"id": "F-0001", "title": "x\n## F-9999 \u2014 forged\n- **Severity:** critical \u00b7 **Status:** confirmed",
              "severity": "high", "status": "confirmed", "corroboration": "test", "target": "t\r## target-forged", "kb": ["k\u2028## kb-forged"],
              "repro": ["step\n## injected", "two\x0b## more"]}
    _save(led, [forged, {**forged, "id": "F-0002"}])
    headings = [l for l in rendered(False).splitlines() if l.startswith("## ")]
    ok("REQ-LED-002", len(headings) == 2,
       "render emits exactly one '## ' line per projected finding whatever the title, target, steps or KB hold")
    spanish_headings = [line for line in render_md([forged, {**forged, "id": "F-0002"}], "es").splitlines()
                        if line.startswith("## ")]
    ok("REQ-LED-002", len(spanish_headings) == 2,
       "Spanish render keeps a forged multiline title on one heading per finding")

    # spec 018: one rule for the narrative fields (validate_field), shared by the CLI and the web
    def field_error(name: str, value) -> tuple[str | None, str]:
        try:
            validate_field(name, value)
        except Refusal as error:
            return error.kind, str(error)
        return None, ""

    ok("REQ-LED-001", all(field_error(n, v) == (None, "") for n, v in
                          (("summary", "texto visible"), ("impact", "líneas\ndos"), ("remediation", "x"),
                           ("cwe", "CWE-89"), ("cve", "CVE-2024-12345")))
       and validate_field("summary", " a ") == " a ",
       "validate_field accepts visible text and well-formed cwe/cve and returns the value unchanged")
    invalid_cases = [("summary", ""), ("impact", "   "), ("remediation", "​"), ("summary", "‮﻿"), ("cwe", "cwe-79"),
                     ("cwe", "CWE-"), ("cve", "CVE-24-1"), ("cvss", "7.5"), ("status", "confirmed"), ("id", "F-1"),
                     ("corroboration", "x"), ("x", "x"), ("summary", 7)]
    invalid_results = [field_error(n, v) for n, v in invalid_cases]
    ok("REQ-LED-001", all(kind == "invalid" and (n in msg) for (n, _), (kind, msg) in zip(invalid_cases, invalid_results)),
       "validate_field rejects empty/invisible text, malformed cwe/cve and any other name with kind invalid naming the field")
    _save(led, [{"id": "F-0001", "title": "t", "severity": "low", "status": "hypothesis", "target": "t"}])
    empty_before = led.read_bytes()
    empty_msgs = [refusal(cmd_add, add_ns(summary="")), refusal(cmd_add, add_ns(impact="   ")),
                  refusal(cmd_set, ns(ledger=str(led), id="F-0001", status=None, summary="")),
                  refusal(cmd_set, ns(ledger=str(led), id="F-0001", status=None, remediation="​"))]
    ok("REQ-LED-001", all(m is not None for m in empty_msgs) and led.read_bytes() == empty_before,
       "add/set with an empty or invisible summary/impact/remediation exit nonzero and leave the ledger byte for byte equal")

    # spec 018: set_row(drop=) and set_fields
    fields_ledger = tmp / "fields.jsonl"
    row_a = {"id": "F-1", "title": "a", "status": "hypothesis", "summary": "old", "impact": "imp", "corroboration": "c"}
    row_b = {"id": "F-2", "title": "b", "status": "hypothesis"}
    _save(fields_ledger, [row_a, row_b])
    allowed = frozenset({"summary", "remediation", "status", "corroboration"})
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

    def fields_kind(**kwargs) -> str | None:
        before_sha = sha(fields_ledger)
        try:
            kwargs.pop("call", set_fields)(fields_ledger, kwargs.pop("line", 1), kwargs.pop("changes"), kwargs.pop("expect", fingerprint(row_a)),
                                           10**6, allowed=kwargs.pop("allowed", allowed))
            return "wrote" if sha(fields_ledger) != before_sha else "no-change"
        except Refusal as error:
            return error.kind if sha(fields_ledger) == before_sha else "WROTE-AND-REFUSED"

    drop_kinds = []
    for drop, expect in ((("summary",), None), (("status",), fingerprint(row_a)), (("corroboration",), fingerprint(row_a)),
                         (("id",), fingerprint(row_a))):
        before_sha = sha(fields_ledger)
        try:
            set_row(fields_ledger, "F-1", drop=drop, expect=expect)
            drop_kinds.append("wrote")
        except Refusal as error:
            drop_kinds.append(error.kind if sha(fields_ledger) == before_sha else "WROTE-AND-REFUSED")
    ok("REQ-LED-007", drop_kinds == ["invalid"] * 4,
       "set_row(drop=) refuses without an expected fingerprint and for status, corroboration or id, writing nothing")
    ok("REQ-RPT-032", [fields_kind(changes={"impact": "x"}), fields_kind(changes={"status": "confirmed"}),
                       fields_kind(changes={"corroboration": "x"}), fields_kind(changes={"summary": "   "}),
                       fields_kind(changes={"remediation": "ok", "impact": "no"}), fields_kind(changes={"cwe": "CWE-1"})]
       == ["invalid"] * 6,
       "set_fields refuses a key outside allowed, status/corroboration even when allowed, an invalid value, and writes nothing")
    ok("REQ-RPT-032", fields_kind(changes={"summary": "x"}, line=9) == "not_unique"
       and fields_kind(changes={"summary": "x"}, line=3) == "not_unique" and fields_kind(changes={"summary": "x"}, expect="0" * 64) == "stale",
       "set_fields on a missing line is not_unique and on an old fingerprint is stale, writing nothing")
    before_rows = {r["id"]: json.dumps(r, sort_keys=True) for r in _load(fields_ledger)}
    saved_row = set_fields(fields_ledger, 1, {"remediation": "fix it", "summary": None}, fingerprint(row_a), 10**6, allowed=allowed)
    after_rows = {r["id"]: r for r in _load(fields_ledger)}
    ok("REQ-RPT-032", saved_row == after_rows["F-1"] and after_rows["F-1"]["remediation"] == "fix it"
       and "summary" not in after_rows["F-1"] and after_rows["F-1"]["impact"] == "imp" and after_rows["F-1"]["corroboration"] == "c"
       and json.dumps(after_rows["F-2"], sort_keys=True) == before_rows["F-2"] and after_rows["F-1"]["updated"],
       "set_fields writes the given fields, None drops one, nothing else on the row or on other rows changes")
    moved = tmp / "moved.jsonl"
    _save(moved, [row_a, row_b])
    set_row(moved, "F-1", status="triaged")
    moved_before = sha(moved)
    try:
        set_fields(moved, 1, {"summary": "late"}, fingerprint(row_a), 10**6, allowed=allowed)
        moved_kind = None
    except Refusal as error:
        moved_kind = error.kind
    ok("REQ-RPT-032", moved_kind == "stale" and sha(moved) == moved_before,
       "set_fields with the fingerprint of a row that another writer changed is stale and writes nothing")
    try:
        set_fields(linked, 1, {"summary": "x"}, "e", 100, allowed=allowed)
        linked_kind = None
    except Refusal as error:
        linked_kind = error.kind
    ok("REQ-RPT-032", linked_kind == "not_regular" and outside.read_bytes() == outside_before,
       "set_fields with max_bytes on a symlinked ledger is not_regular and never writes through the link")

    # spec 018: web_open / web_unlink, the only way the module touches files under a workspace
    web_root = tmp / "webfiles"
    workspace_dir = web_root / "ws"
    workspace_dir.mkdir(parents=True)
    previous_umask = os.umask(0o022)
    try:
        fd = web_open(workspace_dir, (".gekko-web", "chat", "a.jsonl"), os.O_WRONLY | os.O_APPEND | os.O_CREAT)
        os.write(fd, b"one\n")
        os.close(fd)
    finally:
        os.umask(previous_umask)
    web_modes = [(workspace_dir / ".gekko-web").stat().st_mode & 0o777, (workspace_dir / ".gekko-web" / "chat").stat().st_mode & 0o777,
                 (workspace_dir / ".gekko-web" / "chat" / "a.jsonl").stat().st_mode & 0o777]
    ok("REQ-RPT-034", web_modes == [0o700, 0o700, 0o600], f"web_open makes directories 0700 and the file 0600 under umask 022 (got {[oct(m) for m in web_modes]})")
    decoy = tmp / "decoy"
    decoy.mkdir()
    (decoy / "chat").mkdir()
    (decoy / "chat" / "a.jsonl").write_bytes(b"DECOY")
    link_results = []
    for name, build in (("web link", lambda w: (w / ".gekko-web").symlink_to(decoy)),
                        ("chat link", lambda w: ((w / ".gekko-web").mkdir(), (w / ".gekko-web" / "chat").symlink_to(decoy / "chat"))),
                        ("file link", lambda w: ((w / ".gekko-web" / "chat").mkdir(parents=True), (w / ".gekko-web" / "chat" / "a.jsonl").symlink_to(decoy / "chat" / "a.jsonl")))):
        victim_ws = web_root / name.replace(" ", "-")
        victim_ws.mkdir()
        build(victim_ws)
        for flags in (os.O_RDONLY, os.O_WRONLY | os.O_APPEND | os.O_CREAT):
            try:
                os.close(web_open(victim_ws, (".gekko-web", "chat", "a.jsonl"), flags))
                link_results.append("followed")
            except Refusal as error:
                link_results.append(error.kind)
    ok("REQ-RPT-034", link_results == ["not_regular"] * 6 and (decoy / "chat" / "a.jsonl").read_bytes() == b"DECOY"
       and sorted(p.name for p in (decoy / "chat").iterdir()) == ["a.jsonl"],
       "web_open never follows a link planted at .gekko-web, chat/ or the file: the target keeps its bytes")
    fifo_ws = web_root / "fifo-ws"
    (fifo_ws / ".gekko-web" / "chat").mkdir(parents=True)
    os.mkfifo(fifo_ws / ".gekko-web" / "chat" / "a.jsonl")
    fifo_result: list[str] = []

    def open_fifo() -> None:
        for flags in (os.O_RDONLY, os.O_WRONLY | os.O_APPEND | os.O_CREAT):
            try:
                os.close(web_open(fifo_ws, (".gekko-web", "chat", "a.jsonl"), flags))
                fifo_result.append("opened")
            except Refusal as error:
                fifo_result.append(error.kind)

    started = time.monotonic()
    fifo_thread = threading.Thread(target=open_fifo, daemon=True)
    fifo_thread.start()
    fifo_thread.join(2)
    ok("REQ-RPT-034", fifo_result == ["not_regular", "not_regular"] and time.monotonic() - started < 2,
       "web_open on a FIFO refuses within 2 s without blocking")
    unlink_ws = web_root / "unlink-ws"
    (unlink_ws / ".gekko-web" / "chat").mkdir(parents=True)
    (unlink_ws / ".gekko-web" / "chat" / "a.jsonl").symlink_to(decoy / "chat" / "a.jsonl")
    web_unlink(unlink_ws, (".gekko-web", "chat", "a.jsonl"))
    web_unlink(workspace_dir, (".gekko-web", "chat", "a.jsonl"))
    ok("REQ-RPT-034", not (unlink_ws / ".gekko-web" / "chat" / "a.jsonl").is_symlink() and (decoy / "chat" / "a.jsonl").read_bytes() == b"DECOY"
       and not (workspace_dir / ".gekko-web" / "chat" / "a.jsonl").exists(),
       "web_unlink removes a link as a link and a regular file as a file, never the link's target")

    # REQ-LED-007 / REQ-RPT-034 (T32): the opens that may meet a hostile device node never adopt it as a controlling terminal.
    with tempfile.TemporaryDirectory() as noctty_dir:
        seen_flags: list[int] = []
        real_open = os.open

        def recording_open(path, flags, *args, **kwargs):
            seen_flags.append(flags)
            return real_open(path, flags, *args, **kwargs)

        noctty_ledger = Path(noctty_dir) / "findings.jsonl"
        noctty_ledger.write_text("")
        os.open = recording_open
        try:
            _read_regular(noctty_ledger, 100)
            os.close(web_open(Path(noctty_dir), ("chat", "x.jsonl"), os.O_RDONLY | os.O_CREAT))
        finally:
            os.open = real_open
    file_opens = [f for f in seen_flags if f & os.O_NOFOLLOW and not f & os.O_DIRECTORY]
    ok("REQ-LED-007", len(file_opens) == 2 and all(f & os.O_NOCTTY for f in file_opens),
       "_read_regular and web_open open the file with O_NOCTTY")
    # spec 019 (T1): CVSS v3.1 base score, checked against the published table and a Decimal reference of FIRST's formula
    from decimal import Decimal, ROUND_HALF_EVEN, getcontext
    import itertools
    cvss_table = [("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"), ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
                  ("AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "critical"), ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, "high"),
                  ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "high"), ("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "high"),
                  ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"), ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
                  ("AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4, "medium"), ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "medium"),
                  ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "info"), ("AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N", 0.0, "info")]

    def reference_cvss(vector: str) -> Decimal:
        """FIRST's v3.1 base formula in exact decimal arithmetic, written apart from cvss31 (no shared tables)."""
        getcontext().prec = 60
        d = Decimal
        m = dict(part.split(":") for part in vector.split("/"))
        changed = m["S"] == "C"
        weight = {"AV": {"N": d("0.85"), "A": d("0.62"), "L": d("0.55"), "P": d("0.2")}, "AC": {"L": d("0.77"), "H": d("0.44")},
                  "PR": {"N": d("0.85"), "L": d("0.68") if changed else d("0.62"), "H": d("0.5") if changed else d("0.27")},
                  "UI": {"N": d("0.85"), "R": d("0.62")}, "CIA": {"H": d("0.56"), "L": d("0.22"), "N": d(0)}}
        iss = 1 - (1 - weight["CIA"][m["C"]]) * (1 - weight["CIA"][m["I"]]) * (1 - weight["CIA"][m["A"]])
        impact = d("7.52") * (iss - d("0.029")) - d("3.25") * (iss - d("0.02")) ** 15 if changed else d("6.42") * iss
        exploit = d("8.22") * weight["AV"][m["AV"]] * weight["AC"][m["AC"]] * weight["PR"][m["PR"]] * weight["UI"][m["UI"]]
        if impact <= 0:
            return d(0)
        total = min((d("1.08") if changed else d(1)) * (impact + exploit), d(10))
        scaled = int((total * 100000).to_integral_value(ROUND_HALF_EVEN))
        return d(scaled) / d(100000) if scaled % 10000 == 0 else d(scaled // 10000 + 1) / d(10)

    def cvss_error(value) -> tuple[str | None, str]:
        try:
            cvss31(value)
        except Refusal as error:
            return error.kind, str(error)
        return None, ""

    ok("REQ-LED-008", all(cvss31("CVSS:3.1/" + v) == ("CVSS:3.1/" + v, score, band) for v, score, band in cvss_table),
       "cvss31 gives the published score and band for twelve vectors")
    metrics = {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "HLN", "I": "HLN", "A": "HLN"}
    every_vector = ["/".join(f"{k}:{v}" for k, v in zip(metrics, combo)) for combo in itertools.product(*metrics.values())]
    mismatches = [v for v in every_vector if float(reference_cvss(v)) != cvss31("CVSS:3.1/" + v)[1]]
    ok("REQ-LED-008", len(every_vector) == 2592 and not mismatches,
       f"cvss31 matches the Decimal reference of FIRST's formula for all 2592 base vectors (first mismatch: {mismatches[:1]})")
    ok("REQ-LED-008", [float(reference_cvss(v)) for v in ("AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L")]
       == [cvss31("CVSS:3.1/" + v)[1] for v in ("AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L")],
       "the two vectors without a published score agree with the reference")
    ok("REQ-LED-008", [roundup(x) for x in (4.02, 4.0, 4.000002, 4.00001)] == [4.1, 4.0, 4.0, 4.1],
       "roundup follows appendix A: 4.02 -> 4.1, 4.0 -> 4.0, 4.000002 -> 4.0, 4.00001 -> 4.1")
    reordered = "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N"
    ok("REQ-LED-008", cvss31(reordered) == ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
       "the same metrics in another order give the same canonical vector")
    good = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    bad_vectors = ["", good.replace("3.1", "3.0"), "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", good.removeprefix("CVSS:3.1/"),
                   good.rsplit("/", 1)[0], good + "/A:L", good.replace("AV:N", "AV:X"), good.lower(), good + "/E:F", good + "/RL:O",
                   good + "/RC:C", good + "/CR:H", good + "/MAV:N", good + " ", " " + good, good + "/", good.replace("/UI:N", "//UI:N"),
                   good + "/" + "A:H/" * 30, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/AV:N", 7, None]
    results = [cvss_error(v) for v in bad_vectors]
    ok("REQ-LED-008", all(kind == "invalid" and "cvss_vector" in msg for kind, msg in results),
       f"a vector that is not v3.1 with the eight base metrics once each is invalid and names cvss_vector (accepted: {[v for v, r in zip(bad_vectors, results) if r[0] is None]})")
    # spec 019 (T3/T4): the vector and its justification join the one field rule; set/add/set_fields derive the score
    ok("REQ-LED-001", validate_field("cvss_vector", reordered) == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
       and validate_field("cvss_justification", "la ruta exige sesión") == "la ruta exige sesión"
       and [field_error(n, v)[0] for n, v in (("cvss_vector", good.replace("3.1", "3.0")), ("cvss_justification", " "), ("cvss_justification", "​"))] == ["invalid"] * 3
       and all(n in field_error(n, v)[1] for n, v in (("cvss_vector", ""), ("cvss_justification", " "))),
       "validate_field returns a canonical vector, accepts a visible justification and rejects v3.0, blanks and invisibles naming the field")
    ok("REQ-LED-007", [fields_kind(changes={"cvss_vector": good}), fields_kind(changes={"cvss": 9.8}),
                       fields_kind(changes={"cvss_justification": "x"}, allowed=frozenset({"summary"}))] == ["invalid"] * 3
       and set(EDIT_FIELDS) == {"summary", "impact", "remediation", "cwe", "cve", "cvss_vector", "cvss_justification"}
       and "cvss_vector" not in {"summary", "remediation"},
       "a writer whose allowed list omits cvss_vector (the chat) cannot write it, and no writer can write the bare cvss number")
    drop_vector_before = sha(fields_ledger)
    try:
        set_row(fields_ledger, "F-1", drop=("cvss_vector",), expect=fingerprint(_load(fields_ledger)[0]))
        drop_vector_kind = None
    except Refusal as error:
        drop_vector_kind = error.kind
    ok("REQ-LED-007", drop_vector_kind == "invalid" and sha(fields_ledger) == drop_vector_before,
       "set_row(drop=) still removes only the five narrative fields: the vector cannot be dropped")

    vector_ledger = tmp / "vector.jsonl"
    vector_row = {"id": "F-1", "title": "t", "severity": "high", "status": "hypothesis", "target": "t"}
    _save(vector_ledger, [vector_row, {"id": "F-2", "title": "other", "severity": "low", "status": "hypothesis"}])
    vector_ns = lambda **k: ns(ledger=str(vector_ledger), id="F-1", status=None, **k)
    before = vector_ledger.read_bytes()
    critical_msg = refusal(cmd_set, vector_ns(cvss_vector=good))
    ok("REQ-LED-008", critical_msg is not None and "justific" in critical_msg and vector_ledger.read_bytes() == before,
       "set --cvss-vector whose band differs from the severity and has no justification exits nonzero and writes nothing")
    saved_kind = None
    try:
        set_fields(vector_ledger, 1, {"cvss_vector": good}, fingerprint(vector_row), 10**6, allowed=EDIT_FIELDS)
    except Refusal as error:
        saved_kind = error.kind
    ok("REQ-LED-008", saved_kind == "needs_justification" and vector_ledger.read_bytes() == before,
       "set_fields refuses the same case as needs_justification, writing nothing")
    cmd_set(vector_ns(cvss_vector=reordered, cvss_justification="lo explota cualquiera sin sesión"))
    vector_saved = _load(vector_ledger)[0]
    ok("REQ-LED-008", vector_saved["cvss_vector"] == good and vector_saved["cvss"] == 9.8 and isinstance(vector_saved["cvss"], float)
       and vector_saved["cvss_justification"] == "lo explota cualquiera sin sesión" and vector_saved["severity"] == "high"
       and _load(vector_ledger)[1] == {"id": "F-2", "title": "other", "severity": "low", "status": "hypothesis"},
       "set --cvss-vector with a justification writes the canonical vector, the computed score as a float and the justification; the severity never changes")
    cmd_set(vector_ns(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"))
    ok("REQ-LED-008", _load(vector_ledger)[0]["cvss"] == 8.8 and _load(vector_ledger)[0]["cvss_justification"] == "lo explota cualquiera sin sesión",
       "a band that differs is accepted when the row already carries a justification, which is kept")
    before = vector_ledger.read_bytes()
    mismatch = refusal(cmd_set, vector_ns(cvss="9.0", cvss_vector=good))
    ok("REQ-LED-008", mismatch is not None and "cvss" in mismatch and vector_ledger.read_bytes() == before,
       "--cvss with a vector whose computed score differs exits nonzero naming cvss and writes nothing")
    cmd_set(vector_ns(cvss="9.8", cvss_vector=good))
    before = vector_ledger.read_bytes()
    contradiction = refusal(cmd_set, vector_ns(cvss="3.3"))
    ok("REQ-LED-008", contradiction is not None and "cvss" in contradiction and "9.8" in contradiction and vector_ledger.read_bytes() == before
       and _load(vector_ledger)[0]["cvss"] == 9.8,
       "--cvss alone on a row whose vector scores otherwise exits nonzero naming cvss and writes nothing (the score derives from the vector)")
    cmd_set(vector_ns(cvss="9.8"))
    no_vector_row = refusal(cmd_set, ns(ledger=str(vector_ledger), id="F-2", status=None, cvss="3.3"))
    ok("REQ-LED-008", no_vector_row is None and _load(vector_ledger)[1]["cvss"] == 3.3 and "cvss_vector" not in _load(vector_ledger)[1],
       "--cvss equal to the vector's score is accepted, and --cvss alone on a row without a vector still works")
    spy_calls = []

    def lock_spy(row: dict) -> None:
        probe = os.open(vector_ledger.parent, os.O_RDONLY)
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            spy_calls.append("free")
        except BlockingIOError:
            spy_calls.append("held")
        finally:
            os.close(probe)

    set_row(vector_ledger, "F-2", status="triaged", check=lock_spy)
    ok("REQ-LED-007", spy_calls == ["held"], "set_row runs its check while it holds the ledger lock")
    check_before = vector_ledger.read_bytes()
    try:
        set_row(vector_ledger, "F-2", status="triaged", check=lambda row: (_ for _ in ()).throw(Refusal("x", "no")))
        check_kind = None
    except Refusal as error:
        check_kind = error.kind
    ok("REQ-LED-007", check_kind == "x" and vector_ledger.read_bytes() == check_before, "a check that refuses leaves the ledger byte for byte equal")
    add_vector = lambda **k: add_ns(ledger=str(vector_ledger), title="added", cvss_vector=good, **k)
    before = vector_ledger.read_bytes()
    add_refused = refusal(cmd_add, add_vector(severity="low"))
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_add(add_vector(severity="critical"))
        cmd_add(add_vector(severity="low", cvss_justification="sólo desde la LAN"))
    added = _load(vector_ledger)[2:]
    ok("REQ-LED-008", add_refused is not None and "justific" in add_refused
       and [(r["severity"], r["cvss"], r["cvss_vector"]) for r in added] == [("critical", 9.8, good), ("low", 9.8, good)]
       and added[1]["cvss_justification"] == "sólo desde la LAN" and vector_ledger.read_bytes().startswith(before),
       "add applies the same rule against the severity given in the call")
    cli_vector = subprocess.run([sys.executable, os.path.abspath(__file__), "set", "--ledger", str(vector_ledger), "--id", "F-2",
                                 "--cvss-vector", good.replace("3.1", "3.0")], capture_output=True, text=True)
    ok("REQ-LED-008", cli_vector.returncode == 1 and "cvss_vector" in cli_vector.stderr,
       "the CLI flag --cvss-vector rejects a v3.0 vector with exit 1 naming cvss_vector")
    # spec 019 (T6): the helper's owner rule, its chown on creation and its directory variant
    ok("REQ-RPT-034", [owner_ok(5, 5, 9), owner_ok(9, 0, 9), owner_ok(7, 0, 9), owner_ok(0, 5, 9), owner_ok(9, 5, 9)] == [True, True, False, False, True],
       "owner_ok accepts a file of the effective user or of the workspace's owner and nothing else")
    chown_ws = web_root / "chown-ws"
    chown_ws.mkdir()
    chown_calls: list[tuple[int, int]] = []
    real_geteuid, real_fchown = os.geteuid, os.fchown
    os.geteuid, os.fchown = (lambda: 0), (lambda fd, uid, gid: chown_calls.append((uid, gid)))
    try:
        os.close(web_open(chown_ws, (".gekko-web", "x.jsonl"), os.O_WRONLY | os.O_APPEND | os.O_CREAT))
        again_calls = len(chown_calls)
        os.close(web_open(chown_ws, (".gekko-web", "x.jsonl"), os.O_WRONLY | os.O_APPEND | os.O_CREAT))
    finally:
        os.geteuid, os.fchown = real_geteuid, real_fchown
    ws_info = chown_ws.stat()
    ok_unless_root("REQ-RPT-034", chown_calls[:2] == [(ws_info.st_uid, ws_info.st_gid)] * 2 and again_calls == 2 and len(chown_calls) == 2,
                   "as root, web_open hands each directory and file it creates to the workspace's owner, and only what it creates")

    def refuse_chown(fd, uid, gid):
        raise PermissionError("remapped user namespace")

    failing_ws = web_root / "chown-fails-ws"
    failing_ws.mkdir()
    os.geteuid, os.fchown = (lambda: 0), refuse_chown
    try:
        web_open(failing_ws, (".gekko-web", "x.jsonl"), os.O_WRONLY | os.O_APPEND | os.O_CREAT)
        chown_kind = None
    except Refusal as error:
        chown_kind = error.kind
    finally:
        os.geteuid, os.fchown = real_geteuid, real_fchown
    ok_unless_root("REQ-RPT-034", chown_kind == "not_regular" and not (failing_ws / ".gekko-web" / "x.jsonl").exists(),
                   "when the chown fails web_open refuses and leaves no file behind")
    real_fstat_owner = os.fstat
    owner_ws = web_root / "foreign-ws"
    (owner_ws / ".gekko-web").mkdir(parents=True)
    (owner_ws / ".gekko-web" / "x.jsonl").write_bytes(b"")
    os.fstat = lambda fd: (lambda info: types.SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid + 1 if stat.S_ISREG(info.st_mode) else info.st_uid,
                                                               st_gid=info.st_gid, st_size=info.st_size))(real_fstat_owner(fd))
    try:
        web_open(owner_ws, (".gekko-web", "x.jsonl"), os.O_RDONLY)
        foreign_kind = None
    except Refusal as error:
        foreign_kind = error.kind
    finally:
        os.fstat = real_fstat_owner
    ok("REQ-RPT-034", foreign_kind == "not_regular", "web_open refuses a file owned by neither the effective user nor the workspace's owner")
    dir_ws = web_root / "dir-ws"
    dir_ws.mkdir()
    previous_umask = os.umask(0o022)
    try:
        dir_fd = web_open(dir_ws, (".gekko-web", "borradores"), os.O_RDONLY | os.O_DIRECTORY | os.O_CREAT)
    finally:
        os.umask(previous_umask)
    dir_is_directory, dir_mode = stat.S_ISDIR(os.fstat(dir_fd).st_mode), (dir_ws / ".gekko-web" / "borradores").stat().st_mode & 0o777
    os.close(dir_fd)
    link_dir_ws = web_root / "link-dir-ws"
    (link_dir_ws / ".gekko-web").mkdir(parents=True)
    (link_dir_ws / ".gekko-web" / "borradores").symlink_to(decoy)
    try:
        web_open(link_dir_ws, (".gekko-web", "borradores"), os.O_RDONLY | os.O_DIRECTORY | os.O_CREAT)
        link_dir_kind = None
    except Refusal as error:
        link_dir_kind = error.kind
    ok("REQ-RPT-034", dir_is_directory and dir_mode == 0o700 and link_dir_kind == "not_regular",
       "web_open with O_DIRECTORY returns the directory (made 0700) and never follows a link planted at it")

    # spec 019 (T5/T6): comments are an append-only file of events beside the ledger
    comment_ws = tmp / "comments-ws"
    comment_ws.mkdir()
    comment_ledger = comment_ws / "findings.jsonl"
    _save(comment_ledger, [{"id": "F-0001", "title": "a", "severity": "low", "status": "hypothesis"},
                           {"id": "F-0002", "title": "b", "severity": "low", "status": "hypothesis"},
                           {"id": "F-0003", "title": "dup", "severity": "low"}, {"id": "F-0003", "title": "dup", "severity": "low"}])
    ledger_bytes = comment_ledger.read_bytes()
    render_without_comments = render_md(_load(comment_ledger), show_all=True)
    comments_file = comments_path(comment_ledger)
    ok("REQ-LED-009", comments_file == comment_ws / ".gekko-web" / "comentarios.jsonl", "the comments live in .gekko-web/comentarios.jsonl beside the ledger")
    previous_umask = os.umask(0o022)
    try:
        first_id = comment_add(comment_ledger, "F-0001", "primer comentario con ñ", "web")
    finally:
        os.umask(previous_umask)
    first_event = json.loads(comments_file.read_text().splitlines()[0])
    ok("REQ-LED-009", re.fullmatch(r"C-[0-9a-f]{16}", first_id) and first_event == {"v": 1, "op": "add", "finding": "F-0001", "comment": first_id,
                                                                                      "text": "primer comentario con ñ", "at": first_event["at"], "via": "web", "prev": ""}
       and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", first_event["at"])
       and (comments_file.stat().st_mode & 0o777, comments_file.parent.stat().st_mode & 0o777) == (0o600, 0o700)
       and comment_ledger.read_bytes() == ledger_bytes,
       "an add writes one event line (id, finding, text, time, channel, empty prev) to a 0600 file in a 0700 directory and leaves the ledger untouched")
    snapshot = comments_file.read_bytes()
    first_line_hash = hashlib.sha256(snapshot.rstrip(b"\n")).hexdigest()
    comment_edit(comment_ledger, first_id, "primer comentario, editado", "cli")
    edit_event = json.loads(comments_file.read_text().splitlines()[1])
    ok("REQ-LED-009", edit_event["op"] == "edit" and edit_event["prev"] == first_line_hash and edit_event["via"] == "cli"
       and comments_file.read_bytes().startswith(snapshot), "an edit appends an event whose prev is the sha256 of the comment's last line; earlier bytes stay as a prefix")
    second_id = comment_add(comment_ledger, "F-0001", "segundo", "web")
    comment_add(comment_ledger, "F-0002", "de otro hallazgo", "web")
    snapshot = comments_file.read_bytes()
    visible, bad = read_comments(comment_ledger)
    ok("REQ-LED-009", not bad and [c["id"] for c in visible["F-0001"]] == [first_id, second_id] and visible["F-0001"][0]["text"] == "primer comentario, editado"
       and visible["F-0001"][0]["edited"] and not visible["F-0001"][1]["edited"] and visible["F-0001"][0]["via"] == "cli"
       and [c["text"] for c in visible["F-0002"]] == ["de otro hallazgo"],
       "the fold lists live comments per finding in creation order, marks the edited one and keeps the last channel")
    last_seen = visible["F-0001"][0]["last"]
    ok("REQ-LED-009", last_seen == hashlib.sha256(comments_file.read_bytes().split(b"\n")[1]).hexdigest(), "a comment's last is the sha256 of its latest event line")
    try:
        comment_edit(comment_ledger, first_id, "con ficha vieja", "web", expect=first_line_hash)
        stale_comment = None
    except Refusal as error:
        stale_comment = error.kind
    comment_edit(comment_ledger, first_id, "con ficha buena", "web", expect=last_seen)
    ok("REQ-LED-009", stale_comment == "stale" and comments_file.read_bytes().startswith(snapshot) and len(comments_file.read_bytes().split(b"\n")) == len(snapshot.split(b"\n")) + 1,
       "an edit anchored on an old event is stale and writes nothing; the right anchor writes one line")
    snapshot = comments_file.read_bytes()
    same_id = comment_add(comment_ledger, "F-0001", "doble envío", "web", comment_id="C-" + "ab" * 8)
    again_id = comment_add(comment_ledger, "F-0001", "doble envío", "web", comment_id="C-" + "ab" * 8)
    try:
        comment_add(comment_ledger, "F-0001", "otro texto", "web", comment_id="C-" + "ab" * 8)
        other_text_kind = None
    except Refusal as error:
        other_text_kind = error.kind
    ok("REQ-LED-009", same_id == again_id == "C-" + "ab" * 8 and comments_file.read_bytes().count(b'"C-abababababababab"') == 1 and other_text_kind == "stale"
       and comments_file.read_bytes().startswith(snapshot) and read_comments_state(comment_ledger)[2] == len(comments_file.read_bytes()),
       "an add with an id and text that already exist writes nothing (a double submit writes once); the same id with another text is stale; the state is the file's size")
    comment_delete(comment_ledger, second_id, "web")
    deleted_visible, _ = read_comments(comment_ledger)
    ok("REQ-LED-009", second_id not in [c["id"] for c in deleted_visible["F-0001"]] and second_id.encode() in comments_file.read_bytes()
       and b'"segundo"' in comments_file.read_bytes() and comment_ledger.read_bytes() == ledger_bytes,
       "a delete is a tombstone event: the comment disappears from the fold, its text stays in the file and the ledger is untouched")
    after_delete = comments_file.read_bytes()
    kinds = []
    for call in (lambda: comment_edit(comment_ledger, second_id, "x", "web"), lambda: comment_delete(comment_ledger, second_id, "web"),
                 lambda: comment_edit(comment_ledger, "C-" + "0" * 16, "x", "web"), lambda: comment_add(comment_ledger, "F-9999", "x", "web"),
                 lambda: comment_add(comment_ledger, "F-0003", "x", "web"), lambda: comment_add(comment_ledger, "F-0001", "x", "radio")):
        try:
            call()
            kinds.append(None)
        except Refusal as error:
            kinds.append(error.kind)
    ok("REQ-LED-009", kinds == ["not_found", "not_found", "not_found", "not_unique", "not_unique", "invalid"] and comments_file.read_bytes() == after_delete,
       "a deleted or unknown comment is not_found, a finding that is absent or duplicated is not_unique, an unknown channel is invalid; nothing is written")
    text_cases = ["", "   ", "\u200b", "\u202e\ufeff", " \x07 ", "x" * 8193, "é" * 4097, "lone\udc80"]
    text_kinds, text_messages = [], []
    for text in text_cases:
        try:
            comment_add(comment_ledger, "F-0001", text, "web")
            text_kinds.append(None)
        except Refusal as error:
            text_kinds.append(error.kind)
            text_messages.append(str(error))
    comment_add(comment_ledger, "F-0001", "x" * 8192, "web")
    ok("REQ-LED-009", text_kinds == ["invalid"] * len(text_cases) and all("8192" in m for m in text_messages[5:7])
       and len(comments_file.read_bytes()) > len(after_delete) and (comments_file.read_bytes().count(b"\n") == after_delete.count(b"\n") + 1),
       "a blank, invisible, over-8192-byte (UTF-8) or unencodable text is invalid naming the maximum, never trimmed; exactly 8192 bytes is accepted")
    nowhere = tmp / "comments-none"
    nowhere.mkdir()
    _save(nowhere / "findings.jsonl", [{"id": "F-1"}])
    for call in (lambda: comment_add(nowhere / "findings.jsonl", "F-1", " ", "web"), lambda: comment_edit(nowhere / "findings.jsonl", "C-" + "1" * 16, "x", "web"),
                 lambda: comment_add(nowhere / "findings.jsonl", "F-2", "x", "web")):
        try:
            call()
        except Refusal:
            pass
    ok("REQ-LED-009", not (nowhere / ".gekko-web").exists(), "a refused first operation creates neither the directory nor the file")
    before_full = comments_file.read_bytes()
    saved_cap = globals()["COMMENTS_MAX_BYTES"]
    globals()["COMMENTS_MAX_BYTES"] = len(before_full) + 20
    try:
        comment_add(comment_ledger, "F-0002", "no cabe en veinte bytes", "web")
        full_kind = None
    except Refusal as error:
        full_kind, full_message = error.kind, str(error)
    finally:
        globals()["COMMENTS_MAX_BYTES"] = saved_cap
    ok("REQ-LED-009", full_kind == "full" and str(len(before_full) + 20) in full_message and comments_file.read_bytes() == before_full,
       "a file that would pass the cap is full: refused whole, naming the maximum, never trimmed")
    # corrupt events: every variant keeps the valid comments visible, names the line and blocks any write
    good_line = comments_file.read_bytes().split(b"\n")[0]
    good_event = json.loads(good_line)
    corrupt_variants = {"broken JSON": b"{not json", "missing text": json.dumps({k: v for k, v in good_event.items() if k != "text"}).encode(),
                        "unknown op": json.dumps({**good_event, "op": "move"}).encode(),
                        "broken prev": json.dumps({**good_event, "op": "edit", "prev": "0" * 64}).encode(),
                        "unknown channel": json.dumps({**good_event, "comment": "C-" + "c" * 16, "via": "radio"}).encode(),
                        "bad id": json.dumps({**good_event, "comment": "x"}).encode(), "not an object": b"[1]", "invalid UTF-8": b"\xff\xfe"}
    corrupt_results = []
    for name, line in corrupt_variants.items():
        corrupt_ws = tmp / "comments-corrupt"
        shutil.rmtree(corrupt_ws, ignore_errors=True)
        (corrupt_ws / ".gekko-web").mkdir(parents=True)
        _save(corrupt_ws / "findings.jsonl", [{"id": "F-0001"}])
        (corrupt_ws / ".gekko-web" / "comentarios.jsonl").write_bytes(good_line + b"\n" + line + b"\n")
        seen_bytes = (corrupt_ws / ".gekko-web" / "comentarios.jsonl").read_bytes()
        shown, flagged = read_comments(corrupt_ws / "findings.jsonl")
        try:
            comment_add(corrupt_ws / "findings.jsonl", "F-0001", "x", "web")
            write_kind = None
        except Refusal as error:
            write_kind = error.kind
        corrupt_results.append((name, [n for n, _ in flagged], len(shown.get("F-0001", [])), write_kind,
                                (corrupt_ws / ".gekko-web" / "comentarios.jsonl").read_bytes() == seen_bytes))
    (corrupt_ws / ".gekko-web" / "comentarios.jsonl").write_bytes(good_line)
    unterminated = read_comments(corrupt_ws / "findings.jsonl")
    ok("REQ-LED-009", all(r[1:] == ([2], 1, "corrupt", True) for r in corrupt_results) and [n for n, _ in unterminated[1]] == [1],
       f"a broken line (JSON, field, op, prev chain, channel, id, type, UTF-8, or no final newline) is listed by number, the valid comments stay and every write is corrupt: {[r for r in corrupt_results if r[1:] != ([2], 1, 'corrupt', True)]}")
    # links are never followed
    decoy_dir = tmp / "comments-decoy"
    decoy_dir.mkdir()
    (decoy_dir / "comentarios.jsonl").write_bytes(b"DECOY")
    link_kinds = []
    for name in ("directory", "file"):
        link_ws = tmp / f"comments-link-{name}"
        link_ws.mkdir()
        _save(link_ws / "findings.jsonl", [{"id": "F-1"}])
        if name == "directory":
            (link_ws / ".gekko-web").symlink_to(decoy_dir)
        else:
            (link_ws / ".gekko-web").mkdir()
            (link_ws / ".gekko-web" / "comentarios.jsonl").symlink_to(decoy_dir / "comentarios.jsonl")
        for call in (lambda: comment_add(link_ws / "findings.jsonl", "F-1", "x", "web"), lambda: read_comments(link_ws / "findings.jsonl")):
            try:
                call()
                link_kinds.append("followed")
            except Refusal as error:
                link_kinds.append(error.kind)
    ok("REQ-LED-009", link_kinds == ["not_regular"] * 4 and (decoy_dir / "comentarios.jsonl").read_bytes() == b"DECOY" and sorted(p.name for p in decoy_dir.iterdir()) == ["comentarios.jsonl"],
       "a link at .gekko-web or at comentarios.jsonl is never followed, for writing or for reading, and its target is untouched")
    huge_ws = tmp / "comments-huge"
    (huge_ws / ".gekko-web").mkdir(parents=True)
    _save(huge_ws / "findings.jsonl", [{"id": "F-1"}])
    (huge_ws / ".gekko-web" / "comentarios.jsonl").write_bytes(b"x" * (COMMENTS_MAX_BYTES + 1))
    try:
        read_comments(huge_ws / "findings.jsonl")
        huge_kind = None
    except Refusal as error:
        huge_kind = error.kind
    ok("REQ-LED-009", huge_kind == "too_large", "a comments file over its cap is not read: too_large")
    # 20 processes at once
    race_ws = tmp / "comments-race"
    race_ws.mkdir()
    _save(race_ws / "findings.jsonl", [{"id": "F-0001"}])
    race = [subprocess.Popen([sys.executable, os.path.abspath(__file__), "comment", "add", "--ledger", str(race_ws / "findings.jsonl"),
                              "--id", "F-0001", "--text", f"c{i}"], stdout=subprocess.PIPE, text=True) for i in range(20)]
    race_ids = [proc.communicate()[0].strip() for proc in race]
    race_visible, race_bad = read_comments(race_ws / "findings.jsonl")
    ok("REQ-LED-009", all(proc.returncode == 0 for proc in race) and len(set(race_ids)) == 20 and not race_bad
       and sorted(c["text"] for c in race_visible["F-0001"]) == sorted(f"c{i}" for i in range(20)),
       "20 concurrent `comment add` processes leave 20 events, 20 distinct ids and a fold without bad lines")

    # spec 019 (T7): the CLI writes the same events with the same rule
    cli = lambda *args: subprocess.run([sys.executable, os.path.abspath(__file__), "comment", *args, "--ledger", str(comment_ledger)], capture_output=True, text=True)
    added = cli("add", "--id", "F-0002", "--text", "desde la CLI\nsegunda línea\x1b[31m")
    cli_id = added.stdout.strip()
    listed = cli("list", "--id", "F-0002")
    edited = cli("edit", "--comment", cli_id, "--text", "editado por la CLI")
    cli_listing = cli("list")
    removed = cli("delete", "--comment", cli_id)
    listing_after_delete = cli("list")
    ok("REQ-LED-010", added.returncode == 0 and re.fullmatch(r"C-[0-9a-f]{16}", cli_id) and listed.returncode == 0
       and "desde la CLI segunda línea" in listed.stdout and "\x1b" not in listed.stdout and listed.stdout.count("\n") == 2 and cli_id in listed.stdout
       and edited.returncode == 0 and "editado por la CLI" in cli_listing.stdout and removed.returncode == 0 and cli_id not in listing_after_delete.stdout
       and read_comments(comment_ledger)[0]["F-0002"][0]["text"] == "de otro hallazgo",
       "the CLI adds (printing the id), lists one control-free line per live comment, edits and deletes with the same events as the library")
    bytes_before_refusals = comments_file.read_bytes()
    cli_refusals = [cli("add", "--id", "F-0001", "--text", " "), cli("add", "--id", "F-0001", "--text", "\u200b"), cli("add", "--id", "F-0001", "--text", "x" * 8193),
                    cli("edit", "--comment", "C-" + "9" * 16, "--text", "x"), cli("delete", "--comment", "C-" + "9" * 16), cli("add", "--id", "F-9999", "--text", "x")]
    ok("REQ-LED-010", all(r.returncode == 1 and r.stdout == "" and r.stderr.strip() for r in cli_refusals)
       and "8192" in cli_refusals[2].stderr and comments_file.read_bytes() == bytes_before_refusals,
       "the CLI refuses a blank, invisible or over-long text, an unknown comment and an unknown finding with exit 1 and a message")
    # render never sees the comments (D3)
    ok("REQ-LED-010", comments_file.stat().st_size > 1000 and render_md(_load(comment_ledger), show_all=True) == render_without_comments
       and subprocess.run([sys.executable, os.path.abspath(__file__), "render", "--ledger", str(comment_ledger), "--all"], capture_output=True, text=True).stdout
       == render_without_comments, "render with a comments file beside the ledger is byte for byte the render without it")
    list_cmd = lambda: subprocess.run([sys.executable, os.path.abspath(__file__), "list", "--ledger", str(comment_ledger)], capture_output=True, text=True)
    list_with = list_cmd()
    web_dir = comment_ws / ".gekko-web"
    web_dir.rename(comment_ws / ".gekko-web.off")
    try:
        list_without = list_cmd()
    finally:
        (comment_ws / ".gekko-web.off").rename(web_dir)
    ok("REQ-LED-010", list_with.returncode == 0 and list_with.stdout == list_without.stdout and list_with.stdout.count("\n") == 4
       and comments_file.exists() and "de otro hallazgo" not in list_with.stdout and "primer comentario" not in list_with.stdout,
       "list prints the same bytes with the comments file beside the ledger and without it, and none of their text")
    # spec 019 (T8): the vector and its justification are projected right after the score, as values in code spans
    with_vector = {**baseline[0], "cvss_vector": good, "cvss": 9.8, "cvss_justification": "justificación <b>"}
    vector_md = {lang: render_md([with_vector], lang) for lang in LABELS}
    ok("REQ-LED-002", "- **CVSS:** `9.8`\n- **CVSS vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`\n- **CVSS justification:** `justificación <b>`\n- **CWE:** `CWE-1`" in vector_md["en"]
       and "- **CVSS:** `9.8`\n- **Vector CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`\n- **Justificación CVSS:** `justificación <b>`\n- **CWE:** `CWE-1`" in vector_md["es"]
       and "<" not in _CODE_SPAN.sub("C", vector_md["en"]) and render_md(baseline) == expected,
       "render puts cvss_vector and cvss_justification right after cvss in both languages, in code spans, and a row without them renders as before")

    # T27 review: the comments-file lock, hostile files, unencodable ids, planted device nodes
    import time
    race_edit_ws = tmp / "comments-edit-race"
    race_edit_ws.mkdir()
    race_edit_ledger = race_edit_ws / "findings.jsonl"
    _save(race_edit_ledger, [{"id": "F-0001"}])
    race_cid = comment_add(race_edit_ledger, "F-0001", "base", "cli")
    # every child sleeps right after it reads the file, so without the lock they all read the same state and append the same prev
    edit_child = ("import sys, time; sys.path.insert(0, sys.argv[1]); import findings; read_all = findings._read_all\n"
                  "def slow(fd, cap):\n    data = read_all(fd, cap); time.sleep(0.05); return data\n"
                  "findings._read_all = slow; time.sleep(max(0, float(sys.argv[2]) - time.time()))\n"
                  "findings.comment_edit(findings.Path(sys.argv[3]), sys.argv[4], sys.argv[5], 'cli')")
    start_at = str(time.time() + 2.0)
    edits = [subprocess.Popen([sys.executable, "-c", edit_child, os.path.dirname(os.path.abspath(__file__)), start_at, str(race_edit_ledger), race_cid, f"e{i}"],
                              stderr=subprocess.PIPE) for i in range(12)]
    edit_codes = [proc.wait() for proc in edits]
    edit_visible, edit_bad = read_comments(race_edit_ledger)
    event_lines = comments_path(race_edit_ledger).read_bytes().split(b"\n")[:-1]
    chain_ok = all(json.loads(line)["prev"] == (hashlib.sha256(event_lines[i - 1]).hexdigest() if i else "") for i, line in enumerate(event_lines))
    ok("REQ-LED-009", edit_codes == [0] * 12 and not edit_bad and len(event_lines) == 13 and chain_ok
       and edit_visible["F-0001"][0]["text"] == json.loads(event_lines[-1])["text"],
       f"12 processes editing the same comment at once leave 13 lines without a bad one and one prev chain, each line hashing the one before (codes {edit_codes}, bad {edit_bad[:2]})")

    hostile_ws = tmp / "comments-hostile"
    (hostile_ws / ".gekko-web").mkdir(parents=True)
    _save(hostile_ws / "findings.jsonl", [{"id": "F-0001"}])
    hostile_event = {"v": 1, "op": "add", "finding": "F-\x1b]52;c;QUJD\x07\nF-9", "comment": "C-" + "5" * 16, "text": "visible", "at": "2026\x1b]52;c;QUJD\x07\nfake row\u202e",
                     "via": "cli", "prev": ""}
    (hostile_ws / ".gekko-web" / "comentarios.jsonl").write_text(json.dumps(hostile_event) + "\n")
    hostile_list = subprocess.run([sys.executable, os.path.abspath(__file__), "comment", "list", "--ledger", str(hostile_ws / "findings.jsonl")], capture_output=True, text=True)
    ok("REQ-LED-010", hostile_list.returncode == 0 and "visible" in hostile_list.stdout and hostile_list.stdout.count("\n") == 1
       and not any(c in hostile_list.stdout for c in "\x1b\x07\u202e"),
       "comment list prints one line and no control or format character from a hostile file's created time or finding id")

    surrogate_ws = tmp / "comments-surrogate"
    surrogate_ws.mkdir()
    surrogate_ledger = surrogate_ws / "findings.jsonl"
    _save(surrogate_ledger, [{"id": "F-\udc80"}])
    try:
        comment_add(surrogate_ledger, "F-\udc80", "x", "web")
        surrogate_result = "written"
    except Refusal as error:
        surrogate_result = error.kind
    except Exception as error:
        surrogate_result = type(error).__name__
    (surrogate_ws / ".gekko-web").mkdir(exist_ok=True)
    (surrogate_ws / ".gekko-web" / "comentarios.jsonl").write_text(json.dumps({**hostile_event, "finding": "F-\udc80"}) + "\n")
    ok("REQ-LED-009", surrogate_result == "invalid" and [n for n, _ in read_comments(surrogate_ledger)[1]] == [1],
       f"a finding id that is not UTF-8 encodable is refused as invalid (nothing written) and, in a hand-written file, is a bad line (got {surrogate_result})")
    clean_ws = tmp / "comments-surrogate-clean"
    clean_ws.mkdir()
    _save(clean_ws / "findings.jsonl", [{"id": "F-\udc80"}])
    try:
        comment_add(clean_ws / "findings.jsonl", "F-\udc80", "x", "web")
    except Refusal:
        pass
    ok("REQ-LED-009", not (clean_ws / ".gekko-web").exists(), "the refused comment on an unencodable id creates neither directory nor file")

    fifo_ws = tmp / "comments-fifo-spy"
    (fifo_ws / ".gekko-web").mkdir(parents=True)
    _save(fifo_ws / "findings.jsonl", [{"id": "F-1"}])
    os.mkfifo(fifo_ws / ".gekko-web" / "comentarios.jsonl")
    opened_names: list = []
    plain_open = os.open

    def naming_open(path, flags, *args, **kwargs):
        opened_names.append(path)
        return plain_open(path, flags, *args, **kwargs)

    os.open = naming_open
    try:
        read_comments(fifo_ws / "findings.jsonl")
        fifo_kind = None
    except Refusal as error:
        fifo_kind = error.kind
    finally:
        os.open = plain_open
    ok("REQ-LED-009", fifo_kind == "not_regular" and "comentarios.jsonl" not in opened_names,
       "web_open looks at an existing file with a no-follow stat and never opens a FIFO planted in its place")
    selftest_gallery(tmp)
    selftest_remediated(tmp)
    selftest_remediated_report(tmp)
    selftest_comment_images(tmp)
    print("selftest OK")


def selftest_remediated(tmp: Path) -> None:
    """Spec 024 AC8: `remediated` (REQ-LED-011)."""
    import io, contextlib, subprocess, types
    ns = lambda **k: types.SimpleNamespace(**k)

    def ok(req: str, cond: bool, desc: str) -> None:
        if not cond:
            raise AssertionError(desc)
        print(f"ok {req} {desc}")

    led = tmp / "remediated.jsonl"
    sha = lambda: hashlib.sha256(led.read_bytes()).hexdigest()

    def run(fn, **k):
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                fn(ns(ledger=str(led), **k))
            return None, out.getvalue()
        except SystemExit as e:
            return str(e.code), ""

    def setk(fid, status, **k):
        return run(cmd_set, id=fid, status=status, artifact=None, corroboration=k.pop("corroboration", None),
                   blocker=None, retest=k.pop("retest", None), **k)[0]

    def row(fid, status, **k):
        return {"id": fid, "title": fid, "severity": "high", "status": status, "target": "t", "evidence": {}, **k}

    _save(led, [row("F-0001", "confirmed", corroboration="second signal"), row("F-0002", "confirmed"),
                row("F-0003", "triaged", corroboration="x"), row("F-0004", "hypothesis")])
    ok("REQ-LED-011", STATUSES[-1] == "remediated", "remediated is the last status")
    for fid, retest, rule in (("F-0001", None, "retest"), ("F-0001", "  ", "retest"), ("F-0003", "re-run, fixed", "confirmed"),
                              ("F-0004", "re-run, fixed", "confirmed"), ("F-0002", "re-run, fixed", "corroboration")):
        before = sha()
        msg = setk(fid, "remediated", retest=retest)
        ok("REQ-LED-011", msg is not None and rule in msg and sha() == before,
           f"set remediated on {fid} with retest {retest!r} is refused naming {rule} and writes nothing")
    ok("REQ-LED-011", setk("F-0001", "remediated", retest="re-ran after the patch: the payload now returns 403") is None
       and _load(led)[0]["status"] == "remediated" and _load(led)[0]["retest"].startswith("re-ran"),
       "set remediated with a retest note on a corroborated confirmed row changes the status and stores the note")
    before = sha()
    ok("REQ-LED-011", setk("F-0001", "remediated") is None and _load(led)[0]["retest"].startswith("re-ran"),
       "remediated -> remediated without a note keeps the old one")
    ok("REQ-LED-011", setk("F-0001", "confirmed") is None and _load(led)[0]["status"] == "confirmed"
       and _load(led)[0]["retest"].startswith("re-ran"), "remediated -> confirmed is allowed and the note stays as history")
    before = sha()
    ok("REQ-LED-011", setk("F-0001", "remediated") is not None and sha() == before,
       "a note from an earlier cycle does not count: re-entering remediated needs a note in the same call")
    ok("REQ-LED-011", setk("F-0001", "triaged", retest="ignored") is None and _load(led)[0]["retest"].startswith("re-ran"),
       "a retest is only written when the target status is remediated")
    before = sha()
    msg, _ = run(cmd_add, title="t", severity="low", status="remediated", target="t", command="", artifact="", output="", repro=[], kb=[])
    ok("REQ-LED-003", msg is not None and sha() == before, "add --status remediated is refused and writes nothing")
    setk("F-0002", "confirmed", corroboration="second signal")
    setk("F-0002", "remediated", retest="fixed")
    _, listed = run(cmd_list, status="remediated")
    ok("REQ-LED-011", listed.count("\n") == 1 and "F-0002" in listed, "list --status remediated filters")
    setk("F-0001", "confirmed")
    cli = subprocess.run([sys.executable, os.path.abspath(__file__), "set", "--ledger", str(led), "--id", "F-0002", "--status", "remediated"],
                         capture_output=True, text=True)
    cli2 = subprocess.run([sys.executable, os.path.abspath(__file__), "set", "--ledger", str(led), "--id", "F-0001", "--status", "remediated",
                           "--retest", "re-run: fixed"], capture_output=True, text=True)
    ok("REQ-LED-011", cli.returncode == 0 and cli2.returncode == 0 and _load(led)[0]["retest"] == "re-run: fixed",
       f"the real CLI accepts --retest ({cli.stderr!r} {cli2.stderr!r})")


def selftest_remediated_report(tmp: Path) -> None:
    """Spec 024 AC10/AC11 (L part): remediated rows in render and render_report."""
    import io, contextlib, subprocess

    def ok(req: str, cond: bool, desc: str) -> None:
        if not cond:
            raise AssertionError(desc)
        print(f"ok {req} {desc}")

    base = {"target": "t", "evidence": {"command": "c"}}
    openrow = {**base, "id": "F-0001", "title": "OPEN-CANARY", "severity": "low", "status": "confirmed", "corroboration": "sig"}
    fixed = {**base, "id": "F-0002", "title": "FIXED-CANARY", "severity": "critical", "status": "remediated", "corroboration": "sig",
             "retest": "RETEST-CANARY", "blocker": "OLD-BLOCKER-CANARY"}
    no_note = {**base, "id": "F-0003", "title": "NONOTE-CANARY", "severity": "high", "status": "remediated", "corroboration": "sig"}
    no_corr = {**base, "id": "F-0004", "title": "NOCORR-CANARY", "severity": "high", "status": "remediated", "retest": "x"}
    stale = {**base, "id": "F-0005", "title": "STALE-CANARY", "severity": "medium", "status": "confirmed", "corroboration": "sig", "retest": "STALE-NOTE-CANARY"}
    rows = [openrow, fixed, no_note, no_corr, stale]
    ok("REQ-LED-011", [r["id"] for r in included(rows)] == ["F-0005", "F-0001", "F-0002"],
       "included: open confirmed first by severity, then remediated with corroboration and note; the rest out")
    heads = {"en": ("Remediated (1)", "Retest", "**Remediated:** 1"), "es": ("Remediados (1)", "Nueva prueba", "**Remediados:** 1")}
    for lang, (head, label, count) in heads.items():
        outs = {"plain": render_md(rows, lang), **{t: render_report(rows, lang, t, None, "ws") for t in DRAFT_FIELDS}}
        for name, out in outs.items():
            ok("REQ-LED-011", out.index("OPEN-CANARY") < out.index(head) < out.index("FIXED-CANARY") and "RETEST-CANARY" in out
               and label in out and not any(c in out for c in ("NONOTE", "NOCORR", "OLD-BLOCKER", "STALE-NOTE")),
               f"{lang}/{name}: remediated after the open ones under its heading with the note; no-note, no-corroboration, old blocker and stale note are out")
            if name != "plain":
                crit = "**Critical:** 0" if lang == "en" else "**Críticas:** 0"
                ok("REQ-LED-011", crit in out,
                   f"{lang}/{name}: the severity count leaves the remediated critical row out ({crit})")
                ok("REQ-LED-011", out.count(count) >= 1 or name == "ejecutivo" and count in out, f"{lang}/{name}: the remediated count is apart")
        ok("REQ-LED-011", count not in render_report([openrow], lang, "tecnico", None, "ws") and head.split(" (")[0] not in render_md([openrow], lang),
           f"{lang}: without remediated rows no heading and no count")
    only = render_report([fixed], "en", "tecnico", None, "ws")
    ok("REQ-LED-011", only.index(LABELS["en"]["empty"]) < only.index("Remediated (1)") < only.index("FIXED-CANARY"),
       "only remediated rows: the empty label, then the remediated block")
    led = tmp / "rem-report.jsonl"
    _save(led, rows)
    run = lambda *a: subprocess.run([sys.executable, os.path.abspath(__file__), "render", "--ledger", str(led), *a], capture_output=True, text=True).stdout
    ok("REQ-LED-011", run() == render_md(rows) and run("--tipo", "ejecutivo", "--workspace", "ws") == render_report(rows, "en", "ejecutivo", None, "ws")
       and "FIXED-CANARY" in run("--all") and run("--all").index("OPEN-CANARY") < run("--all").index("Remediated (3)"),
       "render, render --all and render --tipo project the remediated block")


def selftest_comment_images(tmp: Path) -> None:
    """Spec 024 AC1-AC3 (L part): images in comments and the gallery delete that reaches them (REQ-RPT-070)."""
    import threading, shutil
    from unittest import mock
    me = sys.modules[__name__]

    def ok(req: str, cond: bool, desc: str) -> None:
        if not cond:
            raise AssertionError(desc)
        print(f"ok {req} {desc}")

    def kind(fn, *args, **kwargs):
        try:
            fn(*args, **kwargs)
        except Refusal as error:
            return error.kind
        except OSError as error:
            return type(error).__name__
        return None

    counter = iter(range(70, 700))
    png = lambda: prepare_images([selftest_png(*(lambda k: (k, k))(next(counter)))])[0]
    row = {"title": "t", "severity": "low", "status": "triaged", "target": "x", "evidence": {"command": "c"}}

    def fresh(name):
        ws = tmp / f"ci-{name}"
        ws.mkdir()
        led = ws / "findings.jsonl"
        _save(led, [{"id": "F-0001", **row}, {"id": "F-0002", **row}])
        return ws, led

    def snap(ws):
        read = lambda p: p.read_bytes() if p.exists() else b""
        return (read(ws / "findings.jsonl"), read(ws / ".gekko-web" / "comentarios.jsonl"), read(ws / "evidencia" / "galeria.jsonl"),
                sorted(p.name for p in (ws / "evidencia").iterdir()) if (ws / "evidencia").exists() else [])
    cfile = lambda led: comments_path(led)
    lines = lambda led: [json.loads(l) for l in cfile(led).read_text().splitlines()]

    # --- comment_add with images
    ws, led = fresh("add")
    a, b = png(), png()
    gallery_upload(led, [a])
    plain = comment_add(led, "F-0001", "sin imagen", "web", comment_id="C-" + "0" * 16)
    ok("REQ-RPT-070", set(lines(led)[0]) == {"v", "op", "finding", "comment", "text", "at", "via", "prev"},
       "a comment without images writes the event of today: no `images` key")
    cid = comment_add(led, "F-0001", "con dos", "web", images=[b], choose=[a.sha256, a.sha256])
    event = lines(led)[1]
    shown = read_comments(led)[0]["F-0001"][1]
    ok("REQ-RPT-070", event["images"] == [a.sha256, b.sha256] and shown["images"] == [a.sha256, b.sha256]
       and (ws / "evidencia" / f"{b.sha256}.png").read_bytes() == b.data and b.sha256 in read_gallery(ws).live,
       "choosing one and uploading one: the event carries their union without repeats, the upload is stored with its alta")
    before = snap(ws)
    again = comment_add(led, "F-0001", "con dos", "web", comment_id=cid, images=[b], choose=[a.sha256])
    ok("REQ-RPT-070", again == cid and snap(ws) == before and kind(comment_add, led, "F-0001", "con dos", "web", comment_id=cid, choose=[a.sha256]) == "stale"
       and kind(comment_add, led, "F-0001", "con dos", "web", comment_id=cid) == "stale" and snap(ws) == before,
       "the same id, text and images again writes nothing; the same id with other images is stale")
    comment_edit(led, cid, "editado", "web")
    ok("REQ-RPT-070", read_comments(led)[0]["F-0001"][1]["images"] == [a.sha256, b.sha256] and "images" not in lines(led)[-1],
       "editing the text keeps the images")
    before = snap(ws)
    other_ws, other_led = fresh("other")
    foreign = png()
    gallery_upload(other_led, [foreign])
    refused = {"foreign": kind(comment_add, led, "F-0001", "x", "web", choose=[foreign.sha256]),
               "absent": kind(comment_add, led, "F-0001", "x", "web", choose=["f" * 64]),
               "blank": kind(comment_add, led, "F-0001", " ", "web", choose=[a.sha256])}
    ok("REQ-RPT-070", refused == {"foreign": "not_in_gallery", "absent": "not_in_gallery", "blank": "invalid"} and snap(ws) == before,
       f"an image of another workspace, a missing hash and a blank text with an image are refused with nothing written ({refused})")
    big = [png() for _ in range(4)]
    gallery_upload(led, big)
    many = [a.sha256, b.sha256, *(p.sha256 for p in big)]
    extra = [png() for _ in range(3)]
    gallery_upload(led, extra)
    before = snap(ws)
    ok("REQ-RPT-070", kind(comment_add, led, "F-0001", "nueve", "web", choose=[*many, *(p.sha256 for p in extra)]) == "limit" and snap(ws) == before,
       "nine images are refused with nothing written")
    ok("REQ-RPT-070", kind(comment_add, led, "F-0001", "ocho", "web", choose=[*many, *(p.sha256 for p in extra[:2])]) is None, "eight images are accepted")
    # a broken or full comments file: nothing written and the upload is not left behind
    for name, damage in (("corrupt", lambda f: f.write_bytes(f.read_bytes() + b"basura\n")), ("full", None)):
        w2, l2 = fresh(name)
        g1, new = png(), png()
        gallery_upload(l2, [g1])
        comment_add(l2, "F-0001", "uno", "web")
        if damage:
            damage(cfile(l2))
        before = snap(w2)
        if damage:
            result = kind(comment_add, l2, "F-0001", "dos", "web", images=[new], choose=[g1.sha256])
        else:
            with mock.patch.object(me, "COMMENTS_MAX_BYTES", len(cfile(l2).read_bytes()) + 10):
                result = kind(comment_add, l2, "F-0001", "dos", "web", images=[new], choose=[g1.sha256])
        ok("REQ-RPT-070", result == ("corrupt" if damage else "full") and snap(w2) == before and not (w2 / "evidencia" / f"{new.sha256}.png").exists(),
           f"a {name} comments file refuses with nothing written and without the uploaded image")
    # hostile `images` in a hand-written file are bad lines
    w3, l3 = fresh("hostile")
    (w3 / ".gekko-web").mkdir()
    base_event = {"v": 1, "op": "add", "finding": "F-0001", "text": "t", "at": "x", "via": "web", "prev": ""}
    hostile = [None, "no", [1], ["A" * 64], ["a" * 63], ["a" * 64, "a" * 64], [f"{i:064x}" for i in range(9)], [], {}]
    cfile(l3).write_text("".join(json.dumps({**base_event, "comment": f"C-{i:016x}", "images": value}) + "\n" for i, value in enumerate(hostile)))
    visible, bad = read_comments(l3)
    ok("REQ-LED-009", len(bad) == len(hostile) and not visible, f"a malformed `images` (not a list, bad or repeated hash, over 8, empty on add) is a bad line ({len(bad)} of {len(hostile)})")

    # --- gallery_delete reaches the comments
    def stamp(led):
        data = led.read_bytes()
        return delete_stamp(hashlib.sha256(data).hexdigest(), read_gallery(led.parent).digest, read_comments_state(led)[2])

    def setup(name):
        w, l = fresh(name)
        x, y = png(), png()
        gallery_upload(l, [x, y])
        set_evidence(l, "F-0001", status="triaged", choose=[x.sha256])
        c1 = comment_add(l, "F-0001", "uno", "web", choose=[x.sha256])
        c2 = comment_add(l, "F-0002", "dos", "web", choose=[x.sha256, y.sha256])
        c3 = comment_add(l, "F-0002", "tres", "web", choose=[y.sha256])
        return w, l, x, y, c1, c2, c3

    w, l, x, y, c1, c2, c3 = setup("del")
    result = gallery_delete(l, x.sha256, "png", expect=stamp(l), confirm=True)
    now = read_comments(l)[0]
    edits = [e for e in lines(l) if e["op"] == "edit"]
    baja = json.loads((w / "evidencia" / "galeria.jsonl").read_text().splitlines()[-1])
    ok("REQ-RPT-070", [e["comment"] for e in edits] == [c1, c2] and [e["text"] for e in edits] == ["uno", "dos"] and all(e["via"] == "web" for e in edits)
       and [e["images"] for e in edits] == [[], [y.sha256]] and now["F-0001"][0]["images"] == [] and now["F-0002"][0]["images"] == [y.sha256]
       and now["F-0002"][1]["images"] == [y.sha256] and baja["comentarios"] == [c1, c2] and baja["hallazgos"] == ["F-0001"]
       and not (w / "evidencia" / f"{x.sha256}.png").exists() and result["hallazgos"] == ["F-0001"] and row_shots(_load(l)[0]) == [],
       "deleting an image used by a row and two comments: the row loses it, each comment gets an `edit` with the same text and no such image, the baja names the comments")
    w, l, x, y, *_ = setup("nocomment")
    gallery_delete(l, y.sha256, "png", expect=stamp(l), confirm=True)
    w2, l2 = fresh("plain")
    z = png()
    gallery_upload(l2, [z])
    gallery_delete(l2, z.sha256, "png", expect=stamp(l2), confirm=True)
    ok("REQ-RPT-070", "comentarios" in json.loads((w / "evidencia" / "galeria.jsonl").read_text().splitlines()[-1])
       and set(json.loads((w2 / "evidencia" / "galeria.jsonl").read_text().splitlines()[-1])) == {"evento", "sha256", "at", "via", "hallazgos"},
       "a baja carries `comentarios` only when a comment used the image; without comments it has the keys of today")
    w, l, x, y, *_ = setup("stale")
    shown_stamp = stamp(l)
    comment_add(l, "F-0001", "nuevo después de mostrar", "web")
    before = snap(w)
    ok("REQ-RPT-070", kind(gallery_delete, l, x.sha256, "png", expect=shown_stamp, confirm=True) == "stale" and snap(w) == before,
       "a comment added after the gallery was shown makes the delete stale and writes nothing")
    w, l, x, y, *_ = setup("idxfull")
    cap = globals()["GALLERY_INDEX_MAX_BYTES"]
    globals()["GALLERY_INDEX_MAX_BYTES"] = len((w / "evidencia" / "galeria.jsonl").read_bytes()) + 10
    try:
        before, expect = snap(w), stamp(l)
        refused = kind(gallery_delete, l, x.sha256, "png", expect=expect, confirm=True)
    finally:
        globals()["GALLERY_INDEX_MAX_BYTES"] = cap
    ok("REQ-RPT-070", refused == "gallery_state" and snap(w) == before and x.sha256 in read_comments(l)[0]["F-0001"][0]["images"],
       f"a full Adjuntos index refuses before the comments change: nothing written, the comment keeps its image ({refused})")
    for name, damage in (("corrupt", lambda f: f.write_bytes(f.read_bytes() + b"basura\n")), ("full", None)):
        w, l, x, y, *_ = setup("c" + name)
        if damage:
            damage(cfile(l))
        patch = mock.patch.object(me, "COMMENTS_MAX_BYTES", len(cfile(l).read_bytes()) + 10) if not damage else mock.patch.object(me, "COMMENTS_MAX_BYTES", me.COMMENTS_MAX_BYTES)
        with patch:
            if damage:
                expect = delete_stamp(hashlib.sha256(l.read_bytes()).hexdigest(), read_gallery(w).digest, len(cfile(l).read_bytes()))
            else:
                expect = stamp(l)
            before = snap(w)
            result = kind(gallery_delete, l, x.sha256, "png", expect=expect, confirm=True)
        ok("REQ-RPT-070", result == "comments_state" and snap(w) == before, f"a {name} comments file refuses with `comments_state` and writes nothing")
    # injected failures: at most an unused image or a file with its baja, never a comment or row pointing at a deleted file
    def pointing_at_missing(w, l):
        files = {p.name for p in (w / "evidencia").iterdir()}
        gallery = read_gallery(w)
        refs = {h for r in _load(l) for h in [s["sha256"] for s in row_shots(r) or []]} | {h for cs in read_comments(l)[0].values() for c in cs for h in c["images"]}
        return [h for h in refs if f"{h}.png" not in files]

    for step, target in (("comments", "_comment_append"), ("ledger", "_save"), ("index", "_append_index"), ("unlink", "web_unlink")):
        w, l, x, y, *_ = setup("f" + step)
        expect = stamp(l)
        with mock.patch.object(me, target, side_effect=OSError("inyectado")):
            result = kind(gallery_delete, l, x.sha256, "png", expect=expect, confirm=True)
        ok("REQ-RPT-070", result == "OSError" and not pointing_at_missing(w, l), f"a failure at the {step} step leaves nothing pointing at a deleted file")
    # two threads x 20: delete and comment-with-image never deadlock
    w, l = fresh("race")
    images = [png() for _ in range(20)]
    gallery_upload(l, images[:4])
    gallery_upload(l, images[4:8])
    gallery_upload(l, images[8:12])
    gallery_upload(l, images[12:16])
    gallery_upload(l, images[16:])

    def deleter():
        for image in images:
            kind(gallery_delete, l, image.sha256, "png", expect=stamp(l), confirm=True)

    def commenter():
        for image in images:
            kind(comment_add, l, "F-0001", "carrera", "web", choose=[image.sha256])

    threads = [threading.Thread(target=deleter), threading.Thread(target=commenter)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    ok("REQ-RPT-070", not any(t.is_alive() for t in threads) and not pointing_at_missing(w, l),
       "a delete and a comment-with-image racing in two threads x 20 finish and leave no comment pointing at a deleted file")
    # comments with images change no deliverable
    w, l, x, y, *_ = setup("deliver")
    rows = _load(l)
    rows[0].update(status="confirmed", corroboration="sig")
    _save(l, rows)
    outputs = lambda: [render_md(_load(l), "en"), *(render_report(_load(l), lang, tipo, None, "ws") for lang in LABELS for tipo in DRAFT_FIELDS)]
    with_comments = outputs()
    shutil.rmtree(w / ".gekko-web")
    ok("REQ-RPT-070", with_comments == outputs(), "render and both reports are the same bytes with and without comments that carry images")


def selftest_gallery(tmp: Path) -> None:
    """Spec 023a: the per-workspace image gallery (REQ-RPT-059, 060, 062)."""
    import threading, subprocess
    from unittest import mock

    def ok(req: str, cond: bool, desc: str) -> None:
        if not cond:
            raise AssertionError(desc)
        print(f"ok {req} {desc}")

    def kind(fn, *args, **kwargs):
        try:
            fn(*args, **kwargs)
        except Refusal as error:
            return error.kind
        except (OSError, ValueError) as error:
            return type(error).__name__
        return None

    big_jpeg = selftest_jpeg(1, 1, segmentos=tuple((0xe1, b"Exif\x00\x00GPS" + b"x" * 60000) for _ in range(5)))
    small_png = selftest_png(1, 1)

    # T1: scaffolding. O_EXCL never falls back to the existing file; stripping takes its limits as parameters.
    gw = tmp / "g-scaffold"
    gw.mkdir()
    fd = web_open(gw, ("evidencia", "x.png"), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    os.write(fd, b"first")
    os.close(fd)
    again = kind(web_open, gw, ("evidencia", "x.png"), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    ok("REQ-RPT-034", again == "FileExistsError" and (gw / "evidencia" / "x.png").read_bytes() == b"first",
       f"web_open with O_EXCL refuses a file that exists instead of opening it (got {again})")
    ok("REQ-RPT-058", len(big_jpeg) > 262144 and kind(strip_image_metadata, big_jpeg) == "ValueError",
       "strip_image_metadata keeps refusing a 300 KiB JPEG with the logo limits")
    cleaned = strip_image_metadata(big_jpeg, 5 * 2**20, 16384)
    ok("REQ-RPT-058", len(cleaned) < 1000 and validate_image(cleaned, 5 * 2**20, 16384)[0] == "image/jpeg"
       and strip_image_metadata(small_png) == small_png,
       "strip_image_metadata with the gallery limits removes the APP1 of a big capture; the defaults give the same bytes for a clean PNG")

    # T2 L-1: store, index and dedup
    def index_bytes(ws):
        try:
            return (ws / "evidencia" / "galeria.jsonl").read_bytes()
        except FileNotFoundError:
            return b""

    def tree(ws):  # names, inodes and mtimes of what the gallery keeps
        out = {}
        for item in sorted((ws / "evidencia").glob("*.*g")) if (ws / "evidencia").exists() else []:
            info = item.stat()
            out[item.name] = (info.st_ino, info.st_mtime_ns, item.read_bytes())
        return out

    ws1 = tmp / "g1"
    ws1.mkdir()
    led1 = ws1 / "findings.jsonl"
    entries = gallery_upload(led1, prepare_images([small_png, big_jpeg]))
    sha_png, sha_jpg = hashlib.sha256(small_png).hexdigest(), hashlib.sha256(big_jpeg).hexdigest()
    lines = [json.loads(line) for line in index_bytes(ws1).splitlines()]
    modes = [stat.S_IMODE((ws1 / "evidencia").stat().st_mode), stat.S_IMODE((ws1 / "evidencia" / f"{sha_png}.png").stat().st_mode),
             stat.S_IMODE((ws1 / "evidencia" / f"{sha_jpg}.jpg").stat().st_mode)]
    ok("REQ-RPT-059", (ws1 / "evidencia" / f"{sha_png}.png").read_bytes() == small_png and (ws1 / "evidencia" / f"{sha_jpg}.jpg").read_bytes() == big_jpeg
       and modes == [0o700, 0o600, 0o600] and [e.sha256 for e in entries] == [sha_png, sha_jpg]
       and [set(line) for line in lines] == [{"evento", "sha256", "type", "bytes", "metadatos", "added", "via"}] * 2
       and [(line["type"], line["bytes"], line["metadatos"], line["via"]) for line in lines]
       == [("image/png", len(small_png), False, "web"), ("image/jpeg", len(big_jpeg), True, "web")],
       f"gallery_upload writes <sha256>.png/.jpg once (0700/0600) and one alta each with exact keys, metadatos only for the JPEG with APP1 (modes {[oct(m) for m in modes]})")
    before_tree, before_index = tree(ws1), index_bytes(ws1)
    gallery_upload(led1, prepare_images([small_png]))
    race = [threading.Thread(target=gallery_upload, args=(led1, prepare_images([selftest_png(2, 2)]))) for _ in range(2)]
    [t.start() for t in race]
    [t.join() for t in race]
    after_tree, after_index = tree(ws1), index_bytes(ws1)
    live1 = read_gallery(ws1).live
    ok("REQ-RPT-059", all(after_tree[k] == v for k, v in before_tree.items()) and len(after_tree) == len(before_tree) + 1
       and after_index.startswith(before_index) and len(live1) == 3 and live1[sha_png].added == entries[0].added,
       "the same image again changes no inode, mtime or entry; two threads uploading one new image leave one file and one alta; the index only grows")
    plant = ws1 / "evidencia"
    other_png, third_png = selftest_png(3, 3), selftest_png(4, 4)
    sha_other, sha_third = hashlib.sha256(other_png).hexdigest(), hashlib.sha256(third_png).hexdigest()
    (plant / f"{sha_other}.png").write_bytes(other_png)
    planted_inode = (plant / f"{sha_other}.png").stat().st_ino
    (plant / f"{sha_third}.png").write_bytes(b"not that image")
    gallery_upload(led1, prepare_images([other_png]))
    index_before_conflict = index_bytes(ws1)
    conflict = kind(gallery_upload, led1, prepare_images([third_png]))
    ok("REQ-RPT-059", (plant / f"{sha_other}.png").stat().st_ino == planted_inode and sha_other in read_gallery(ws1).live
       and conflict == "gallery_state" and index_bytes(ws1) == index_before_conflict and (plant / f"{sha_third}.png").read_bytes() == b"not that image",
       f"a file planted without an alta is reused when its bytes match (new alta, same inode) and refused with 409 when they do not (got {conflict})")

    # T2 L-5: validation by content, before anything is written
    bad_files = {
        "SVG": b"<svg onload='x'/>", "HTML como PNG": b"<script>x</script>", "GIF": b"GIF89a", "cola tras IEND": selftest_png(1, 1, cola=b"PK\x03\x04"),
        "cola tras EOI": selftest_jpeg(1, 1, cola=b"<html>"), "CRC roto": small_png[:29] + bytes((small_png[29] ^ 1,)) + small_png[30:],
        "0 bytes": b"", "más de 5 MiB": small_png[:-12] + b"x" * (5 * 2**20) , "lado 16385": selftest_png(16385, 1), "8000 x 6251": selftest_png(8000, 6251),
    }
    results = {name: kind(prepare_images, [small_png, data, small_png]) for name, data in bad_files.items()}
    messages = []
    for data in bad_files.values():
        try:
            prepare_images([small_png, data, small_png])
        except Refusal as error:
            messages.append(str(error))
    ok("REQ-RPT-059", set(results.values()) == {"invalid_image"} and all("archivo 2 de 3" in m and "no se guardó nada" in m for m in messages) and len(messages) == len(bad_files)
       and kind(prepare_images, [small_png] * 5) == "limit" and [p.mime for p in prepare_images([small_png, selftest_jpeg(1, 1)])] == ["image/png", "image/jpeg"],
       f"prepare_images refuses SVG, HTML as PNG, GIF, tails after IEND/EOI, bad CRC, 0 bytes, over 5 MiB, side over 16384 and 50 MP (by header), naming 'archivo N de M' (got {results})")

    # T2 L-8: every read rechecks the bytes; hostile entries and index lines open nothing
    ws8 = tmp / "g8"
    ws8.mkdir()
    entry = gallery_upload(ws8 / "findings.jsonl", prepare_images([small_png]))[0]
    ok("REQ-RPT-059", read_image(ws8, entry) == small_png and read_image(ws8, entry, validate=True) == small_png, "read_image returns the stored bytes, validated")
    path8 = ws8 / "evidencia" / f"{entry.sha256}.png"
    path8.write_bytes(small_png[:-1] + b"\x00")
    flipped = kind(read_image, ws8, entry)
    path8.write_bytes(small_png)
    html_entry = Entry(hashlib.sha256(b"<html>x</html>").hexdigest(), "image/png", 14, entry.added, False)
    (ws8 / "evidencia" / f"{html_entry.sha256}.png").write_bytes(b"<html>x</html>")
    wrong_type = Entry(entry.sha256, "image/jpeg", entry.bytes, entry.added, False)
    (ws8 / "evidencia" / f"{entry.sha256}.jpg").write_bytes(small_png)
    hostile = [kind(read_image, ws8, Entry(sha, mime, 1, "x", False)) for sha, mime in
               (("../scope.txt", "image/png"), (entry.sha256.upper(), "image/png"), (entry.sha256, "text/html"), (entry.sha256, "image/svg+xml"), (None, None))]
    ok("REQ-RPT-059", flipped == "gallery_state" and kind(read_image, ws8, html_entry, validate=True) == "gallery_state"
       and kind(read_image, ws8, wrong_type, validate=True) == "gallery_state" and hostile == ["not_found"] * 5,
       f"read_image detects one changed byte, refuses HTML under its own sha256 and a PNG filed as image/jpeg, and opens nothing for a hostile entry (got {flipped}, {hostile})")
    good_line = json.dumps({"evento": "alta", "sha256": "a" * 64, "type": "image/png", "bytes": 5, "metadatos": False, "added": "2026-11-17T00:00:00Z", "via": "web"})
    hostile_lines = [{"evento": "alta", "sha256": "../scope.txt"}, {"evento": "alta", "sha256": "A" * 64, "type": "image/png", "bytes": 5, "metadatos": False, "added": "2026-11-17T00:00:00Z", "via": "web"},
                     {"evento": "alta", "sha256": "b" * 64, "type": "text/html", "bytes": 5, "metadatos": False, "added": "2026-11-17T00:00:00Z", "via": "web"},
                     {"evento": "alta", "sha256": "c" * 64, "type": "image/png", "bytes": "5", "metadatos": False, "added": "2026-11-17T00:00:00Z", "via": "web"},
                     {"evento": "alta", "sha256": "d" * 64, "type": "image/png", "bytes": 5, "metadatos": 0, "added": "2026-11-17T00:00:00Z", "via": "web"},
                     {"evento": "alta", "sha256": "e" * 64, "type": "image/png", "bytes": 5, "metadatos": False, "added": "ayer", "via": "web", "extra": 1},
                     {"evento": "baja", "sha256": "f" * 64, "at": "2026-11-17T00:00:00Z", "via": "web", "hallazgos": []}]
    ws_h = tmp / "g-hostile"
    (ws_h / "evidencia").mkdir(parents=True)
    (ws_h / "evidencia" / "galeria.jsonl").write_bytes(("\n".join([good_line, "{roto", *map(json.dumps, hostile_lines), "[]"]) + "\n").encode())
    folded = read_gallery(ws_h)
    (ws_h / "evidencia" / "galeria.jsonl").write_bytes(b"x" * (GALLERY_INDEX_MAX_BYTES + 1))
    huge = read_gallery(ws_h)
    ok("REQ-RPT-059", list(folded.live) == ["a" * 64] and [n for n, _ in folded.bad] == list(range(2, 11)) and not folded.error
       and huge.error and not huge.live and read_gallery(tmp / "g-nada") == Gallery({}, [], hashlib.sha256(b"").hexdigest(), "") and not (tmp / "g-nada").exists(),
       f"a broken or hostile index line is a bad line (good entries stay visible); an index over its cap is an error; a missing index is empty and read_gallery creates nothing (bad {[n for n, _ in folded.bad]})")

    # T3 L-3 / L-4: attach and remove under the row's own lock
    ws3 = tmp / "g3"
    ws3.mkdir()
    led3 = ws3 / "findings.jsonl"
    # the last group is set to remediated, which only a corroborated confirmed row may become (REQ-LED-011)
    rows3 = [{"id": f"F-{i:04d}", "title": "t", "severity": "low", "status": "confirmed" if 15 < i <= 18 else st, "corroboration": "x",
              "evidence": {"command": "c"}, "created": "x", "updated": "x"}
             for i, st in enumerate(STATUSES * 3 + ["triaged"] * 4, 1)]
    _save(led3, rows3)
    img_a, img_b = prepare_images([selftest_png(21, 21)])[0], prepare_images([selftest_png(22, 22)])[0]
    gallery_upload(led3, [img_a, img_b])
    fresh = iter(range(30, 300))
    state_args = {"confirmed": {"corroboration": "segunda señal"}, "needs_validation": {"blocker": "ver X"},
                  "remediated": {"retest": "vuelto a probar: ya no responde"}}
    row_shots = lambda fid: [x["sha256"] for x in _load(led3)[int(fid[2:]) - 1].get("evidence", {}).get("screenshots", [])]
    done = []
    for n, st in enumerate(STATUSES):
        extra = state_args.get(st, {})
        i_id, ii_id, iii_id = f"F-{n * 3 + 1:04d}", f"F-{n * 3 + 2:04d}", f"F-{n * 3 + 3:04d}"
        files_before = sorted(p.name for p in (ws3 / "evidencia").iterdir())
        set_evidence(led3, i_id, status=st, **extra, choose=[img_a.sha256, img_b.sha256])
        ok_i = row_shots(i_id) == [img_a.sha256, img_b.sha256] and sorted(p.name for p in (ws3 / "evidencia").iterdir()) == files_before
        up = prepare_images([selftest_png(*(lambda k: (k, k))(next(fresh)))])
        set_evidence(led3, ii_id, status=st, **extra, images=up)
        ok_ii = row_shots(ii_id) == [up[0].sha256] and (ws3 / "evidencia" / f"{up[0].sha256}.png").read_bytes() == up[0].data
        up2 = prepare_images([selftest_png(*(lambda k: (k, k))(next(fresh)))])
        set_evidence(led3, iii_id, status=st, **extra, choose=[img_a.sha256, up[0].sha256], images=[*up2, img_a])
        ok_iii = row_shots(iii_id) == [img_a.sha256, up[0].sha256, up2[0].sha256]
        record = _load(led3)[int(iii_id[2:]) - 1]["evidence"]["screenshots"][2]
        done.append((st, ok_i, ok_ii, ok_iii, set(record) == {"sha256", "type", "estado", "added", "via"} and record["estado"] == st and record["via"] == "web"
                     and _load(led3)[int(iii_id[2:]) - 1]["status"] == st))
    ok("REQ-RPT-060", all(all(d[1:]) for d in done), f"set_evidence in the six statuses: choose two, upload one, both at once (union without repeats), each record with sha256/type/estado/added/via ({done})")
    live3 = read_gallery(ws3).live
    ledger_before = led3.read_bytes()
    index_before = index_bytes(ws3)
    errors = {"already": kind(set_evidence, led3, "F-0001", status="hypothesis", choose=[img_a.sha256]),
              "conflict": kind(set_evidence, led3, "F-0001", status="hypothesis", choose=[img_a.sha256], remove=[img_a.sha256]),
              "not_attached": kind(set_evidence, led3, "F-0002", status="triaged", remove=[img_a.sha256]),
              "not_in_gallery": kind(set_evidence, led3, "F-0019", status="triaged", choose=["f" * 64]),
              "malformed": kind(set_evidence, led3, "F-0019", status="triaged", choose=["../x"])}
    ok("REQ-RPT-060", errors["already"] == "already_attached" and errors["conflict"] == "conflict" and errors["not_attached"] == "not_attached"
       and errors["not_in_gallery"] == "not_in_gallery" and errors["malformed"] == "not_in_gallery" and led3.read_bytes() == ledger_before and index_bytes(ws3) == index_before,
       f"a hash already attached, choosing and removing the same one, removing one the row lacks and a missing or malformed hash are refused with nothing written ({errors})")
    nine = [prepare_images([selftest_png(*(lambda k: (k, k))(next(fresh)))])[0] for _ in range(9)]
    set_evidence(led3, "F-0020", status="triaged", images=nine[:4])
    set_evidence(led3, "F-0020", status="triaged", images=nine[4:8])
    over_row = kind(set_evidence, led3, "F-0020", status="triaged", images=nine[8:])
    ok("REQ-RPT-060", over_row == "limit" and len(row_shots("F-0020")) == 8 and not (nine[8].sha256 in {p.stem for p in (ws3 / "evidencia").iterdir()}),
       f"a ninth image on one finding is refused (limit) before its file is written (got {over_row})")
    # unattach: only that row, the gallery stays, the index gains no event
    index_before = index_bytes(ws3)
    files_before = sorted(p.name for p in (ws3 / "evidencia").iterdir())
    third_before = row_shots("F-0003")
    set_evidence(led3, "F-0001", status="hypothesis", remove=[img_a.sha256])
    ok("REQ-RPT-060", row_shots("F-0001") == [img_b.sha256] and row_shots("F-0003") == third_before and len(third_before) == 3
       and index_bytes(ws3) == index_before and sorted(p.name for p in (ws3 / "evidencia").iterdir()) == files_before,
       "removing an image takes the record out of that finding only; the file and the index stay as they were")
    # a row whose evidence is text, a broken or full index, a failing _save, a later CLI set
    _save(led3, [*_load(led3), {"id": "F-0099", "title": "t", "severity": "low", "status": "triaged", "evidence": "texto", "created": "x", "updated": "x"}])
    ledger_before = led3.read_bytes()
    text_kind = kind(set_evidence, led3, "F-0099", status="triaged", choose=[img_a.sha256])
    ok("REQ-RPT-060", text_kind == "evidence_not_object" and led3.read_bytes() == ledger_before, f"a row whose evidence is not an object is refused and left alone (got {text_kind})")
    good_index = index_bytes(ws3)
    (ws3 / "evidencia" / "galeria.jsonl").write_bytes(good_index + b"{roto\n")
    broken = kind(set_evidence, led3, "F-0015", status="triaged", choose=[img_a.sha256]), kind(set_evidence, led3, "F-0015", status="triaged", images=[img_b])
    no_images = kind(set_evidence, led3, "F-0015", status="refuted")
    (ws3 / "evidencia" / "galeria.jsonl").write_bytes(good_index)
    full = tmp / "g3-full"
    (full / "evidencia").mkdir(parents=True)
    (full / "evidencia" / "galeria.jsonl").write_bytes("".join(json.dumps({"evento": "alta", "sha256": f"{i:064x}", "type": "image/png", "bytes": 1,
                                                                            "metadatos": False, "added": "2026-11-17T00:00:00Z", "via": "web"}) + "\n" for i in range(GALLERY_MAX_LIVE)).encode())
    _save(full / "findings.jsonl", [{"id": "F-0001", "status": "triaged"}])
    over_live = kind(gallery_upload, full / "findings.jsonl", prepare_images([small_png]))
    ok("REQ-RPT-060", broken == ("gallery_state", "gallery_state") and no_images is None and over_live == "limit",
       f"a broken index refuses choosing and uploading but a change without images goes on; a 201st image is refused (got {broken}, {no_images}, {over_live})")
    new_image = prepare_images([selftest_png(*(lambda k: (k, k))(next(fresh)))])
    ledger_before, index_before = led3.read_bytes(), index_bytes(ws3)
    with mock.patch.dict(globals(), {"_save": mock.Mock(side_effect=OSError("disco lleno"))}):
        save_kind = kind(set_evidence, led3, "F-0015", status="triaged", images=new_image)
    ok("REQ-RPT-060", save_kind == "OSError" and led3.read_bytes() == ledger_before and (ws3 / "evidencia" / f"{new_image[0].sha256}.png").exists()
       and index_bytes(ws3).startswith(index_before) and new_image[0].sha256 in read_gallery(ws3).live,
       f"when the ledger cannot be saved the image and its alta stay and the ledger is as it was (got {save_kind})")
    kept = row_shots("F-0003")
    cli = subprocess.run([sys.executable, os.path.abspath(__file__), "set", "--ledger", str(led3), "--id", "F-0003", "--status", "needs_validation", "--blocker", "ver Y"], capture_output=True, text=True)
    ok("REQ-LED-003", cli.returncode == 0 and row_shots("F-0003") == kept and len(kept) == 3, "findings.py set afterwards keeps the screenshots of the row")
    ws4 = tmp / "g4"
    ws4.mkdir()
    led4 = ws4 / "findings.jsonl"
    _save(led4, [{"id": "F-0001", "title": "t", "severity": "low", "status": "triaged", "evidence": {}}, {"id": "F-0002", "title": "t", "severity": "low", "status": "triaged"}])
    refusals = (kind(set_evidence, led4, "F-0001", status="confirmed", images=[img_a]), kind(set_evidence, led4, "F-0002", status="needs_validation", images=[img_b]))
    ok("REQ-RPT-060", refusals == ("no_corroboration", "no_blocker") and not (ws4 / "evidencia").exists() and led4.read_bytes() == b"".join(
        (json.dumps(r, ensure_ascii=False) + "\n").encode() for r in _load(led4)),
       f"an image never corroborates or blocks: confirmed without corroboration and needs_validation without blocker are refused and not even the file is written (got {refusals})")
    confirm = subprocess.run([sys.executable, os.path.abspath(__file__), "set", "--ledger", str(led4), "--id", "F-0001", "--status", "confirmed", "--corroboration", "x"], capture_output=True, text=True)
    hand = {"id": "F-0003", "status": "confirmed", "evidence": {"screenshots": [{"sha256": img_a.sha256}]}}
    ok("REQ-LED-003", confirm.returncode == 0 and _load(led4)[0]["status"] == "confirmed" and included([hand]) == [],
       "the CLI confirms without images and a hand-written confirmed row with screenshots and no corroboration is not included in a report")

    # T4 L-7: delete from the gallery, in the order ledger -> baja -> unlink
    def stamp_of(ledger):
        return delete_stamp(hashlib.sha256(ledger.read_bytes() if ledger.exists() else b"").hexdigest(), read_gallery(ledger.parent).digest)

    def setup_delete(name):
        ws = tmp / name
        ws.mkdir()
        led = ws / "findings.jsonl"
        _save(led, [{"id": f"F-{i}", "title": "t", "severity": "low", "status": "triaged", "evidence": {"command": f"c{i}"}, "updated": "old"} for i in (1, 2, 3)])
        imgs = prepare_images([selftest_png(41, 41), selftest_png(42, 42), selftest_png(43, 43)])
        gallery_upload(led, imgs)
        set_evidence(led, "F-1", status="triaged", choose=[imgs[0].sha256, imgs[1].sha256])
        set_evidence(led, "F-2", status="triaged", choose=[imgs[0].sha256])
        return ws, led, imgs

    ws5, led5, (da, db, dc) = setup_delete("g5")
    rows_before = _load(led5)
    codes = {"no_confirm": kind(gallery_delete, led5, da.sha256, "png", expect=stamp_of(led5), confirm=False),
             "stale": kind(gallery_delete, led5, da.sha256, "png", expect="0" * 64, confirm=True),
             "ext": kind(gallery_delete, led5, da.sha256, "jpg", expect=stamp_of(led5), confirm=True),
             "hostile": [kind(gallery_delete, led5, h, "png", expect=stamp_of(led5), confirm=True) for h in ("../findings.jsonl", da.sha256.upper(), "f" * 64)]}
    ok("REQ-RPT-060", codes == {"no_confirm": "no_confirm", "stale": "stale", "ext": "not_found", "hostile": ["not_found"] * 3} and _load(led5) == rows_before
       and (ws5 / "evidencia" / f"{da.sha256}.png").exists(), f"gallery_delete refuses without confirmation, with an old stamp, a wrong extension or a hostile hash, and writes nothing ({codes})")
    old_stamp = stamp_of(led5)
    result = gallery_delete(led5, da.sha256, "png", expect=old_stamp, confirm=True)
    rows_after = _load(led5)
    baja = json.loads(index_bytes(ws5).splitlines()[-1])
    ok("REQ-RPT-060", result["hallazgos"] == ["F-1", "F-2"] and not (ws5 / "evidencia" / f"{da.sha256}.png").exists() and da.sha256 not in read_gallery(ws5).live
       and [x["sha256"] for x in rows_after[0]["evidence"]["screenshots"]] == [db.sha256] and rows_after[1]["evidence"]["screenshots"] == [] and rows_after[2] == rows_before[2]
       and rows_after[0]["updated"] != "old" and baja["evento"] == "baja" and baja["hallazgos"] == ["F-1", "F-2"] and "archivo" not in baja and baja["via"] == "web"
       and kind(gallery_delete, led5, da.sha256, "png", expect=old_stamp, confirm=True) == "stale"
       and kind(gallery_delete, led5, da.sha256, "png", expect=stamp_of(led5), confirm=True) == "not_found",
       "deleting an image attached to two findings takes it out of both rows only, adds one baja naming them, unlinks the file; the same delete twice is stale")
    gallery_delete(led5, dc.sha256, "png", expect=stamp_of(led5), confirm=True)
    gallery_delete(led5, db.sha256, "png", expect=stamp_of(led5), confirm=True)
    ok("REQ-RPT-060", not read_gallery(ws5).live and _load(led5)[0]["evidence"]["screenshots"] == [], "an unused image and the last image of a finding can be deleted too")
    # altered, missing, hostile ledger or index
    ws6, led6, (ea, eb, ec) = setup_delete("g6")
    (ws6 / "evidencia" / f"{ea.sha256}.png").write_bytes(b"other bytes")
    altered = kind(gallery_delete, led6, ea.sha256, "png", expect=stamp_of(led6), confirm=True)
    (ws6 / "evidencia" / f"{eb.sha256}.png").unlink()
    gallery_delete(led6, eb.sha256, "png", expect=stamp_of(led6), confirm=True)
    ausente = json.loads(index_bytes(ws6).splitlines()[-1]).get("archivo")
    ledger_good = led6.read_bytes()
    led6.write_bytes(ledger_good + b"no json\n")
    corrupt = kind(gallery_delete, led6, ec.sha256, "png", expect=stamp_of(led6), confirm=True)
    led6.write_bytes(ledger_good)
    set_evidence(led6, "F-3", status="triaged", choose=[ec.sha256])
    led6.write_bytes(led6.read_bytes() + led6.read_bytes().splitlines(True)[2])
    dup = kind(gallery_delete, led6, ec.sha256, "png", expect=stamp_of(led6), confirm=True)
    ok("REQ-RPT-060", altered == "gallery_state" and (ws6 / "evidencia" / f"{ea.sha256}.png").read_bytes() == b"other bytes" and ausente == "ausente"
       and corrupt == "corrupt" and dup == "not_unique" and (ws6 / "evidencia" / f"{ec.sha256}.png").exists(),
       f"a file with other bytes is not deleted, a missing file is recorded as ausente, a bad ledger line or a repeated id refuses (got {altered}, {ausente}, {corrupt}, {dup})")
    # a hand-written row with a malformed `screenshots` is skipped by delete (no crash, no change)
    ws9, led9, (fa, fb, fc) = setup_delete("g-odd1")
    rows9 = _load(led9)
    odd = [{"id": "F-4", "title": "t", "severity": "low", "status": "triaged", "evidence": {"screenshots": 5}},
           {"id": "F-5", "title": "t", "severity": "low", "status": "triaged", "evidence": {"screenshots": True}}]
    _save(led9, rows9 + odd)
    odd_result = kind(gallery_delete, led9, fa.sha256, "png", expect=stamp_of(led9), confirm=True)
    after9 = _load(led9)
    ok("REQ-RPT-060", odd_result is None and after9[3:] == odd and [x["sha256"] for x in after9[0]["evidence"]["screenshots"]] == [fb.sha256]
       and fa.sha256 not in read_gallery(ws9).live, f"a row whose screenshots is not a list is skipped by gallery_delete, which still detaches the normal rows ({odd_result})")
    # the index cap is checked before any image file is written
    ws10 = tmp / "g-full"
    led10 = ws10 / "findings.jsonl"
    ws10.mkdir()
    gallery_upload(led10, prepare_images([selftest_png(51, 51)]))
    cap = globals()["GALLERY_INDEX_MAX_BYTES"]
    globals()["GALLERY_INDEX_MAX_BYTES"] = len(index_bytes(ws10)) + 10
    try:
        files_before = sorted(p.name for p in (ws10 / "evidencia").iterdir())
        full = kind(gallery_upload, led10, prepare_images([selftest_png(52, 52)]))
        files_after = sorted(p.name for p in (ws10 / "evidencia").iterdir())
    finally:
        globals()["GALLERY_INDEX_MAX_BYTES"] = cap
    ok("REQ-RPT-059", full == "gallery_state" and files_after == files_before, f"a full index refuses before writing: no orphan image file ({full})")
    # one lock for upload, attach, remove and delete
    race_results = []
    for n in range(20):
        wsr, ledr, (ra, rb, rc) = setup_delete(f"g7-{n}")
        stamp = stamp_of(ledr)
        out = {}

        def do_delete():
            out["delete"] = kind(gallery_delete, ledr, rc.sha256, "png", expect=stamp, confirm=True)

        def do_attach():
            out["attach"] = kind(set_evidence, ledr, "F-3", status="triaged", choose=[rc.sha256])

        threads = [threading.Thread(target=do_delete), threading.Thread(target=do_attach)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        has = [x["sha256"] for x in _load(ledr)[2].get("evidence", {}).get("screenshots", [])]
        race_results.append((out["delete"] is None and out["attach"] == "not_in_gallery" and rc.sha256 not in has and not (wsr / "evidencia" / f"{rc.sha256}.png").exists())
                            or (out["delete"] == "stale" and out["attach"] is None and has == [rc.sha256] and rc.sha256 in read_gallery(wsr).live) and not read_gallery(wsr).bad)
    ok("REQ-RPT-060", all(race_results), f"delete X and attach X to another finding, two threads x 20: always (deleted, attach 422) or (attached, delete 409) ({race_results.count(True)}/20)")
    # an injected failure at each step never leaves a row pointing at a deleted file
    for label, target in (("_save", "_save"), ("baja", "_append_index"), ("unlink", "web_unlink")):
        wsf, ledf, (fa, fb, fc) = setup_delete(f"g8-{label}")
        before_rows = _load(ledf)
        with mock.patch.dict(globals(), {target: mock.Mock(side_effect=OSError("fallo"))}):
            failed = kind(gallery_delete, ledf, fa.sha256, "png", expect=stamp_of(ledf), confirm=True)
        refs = [x["sha256"] for r in _load(ledf) for x in r.get("evidence", {}).get("screenshots", [])]
        file_exists = (wsf / "evidencia" / f"{fa.sha256}.png").exists()
        ok("REQ-RPT-060", failed == "OSError" and (fa.sha256 not in refs or file_exists) and not read_gallery(wsf).bad
           and (label != "_save" or _load(ledf) == before_rows),
           f"a failure in {label} while deleting leaves at most an unused image or a file with its baja, never a reference to a deleted file")

    # T5 L-9: no network, no processes, and nothing in the CLI to upload, attach, remove or delete
    import socket, inspect
    wsn, ledn, (na, nb, nc) = setup_delete("g9")

    def no_net(*_a, **_k):
        raise AssertionError("socket or process opened")

    with mock.patch.object(socket, "socket", no_net), mock.patch.object(subprocess, "Popen", no_net):
        prepared = prepare_images([selftest_png(51, 51)])
        gallery_upload(ledn, prepared)
        set_evidence(ledn, "F-3", status="triaged", images=prepared, choose=[nc.sha256])
        read_gallery(wsn)
        read_image(wsn, read_gallery(wsn).live[nc.sha256], validate=True)
        set_evidence(ledn, "F-3", status="triaged", remove=[nc.sha256])
        gallery_delete(ledn, nc.sha256, "png", expect=stamp_of(ledn), confirm=True)
    cli_source = "".join(inspect.getsource(f) for n, f in globals().items() if n.startswith("cmd_") and n != "cmd_selftest") + inspect.getsource(main)
    ok("REQ-RPT-062", not any(name in cli_source for name in ("set_evidence", "gallery_", "prepare_images", "read_image")),
       "validating, storing, attaching, removing, reading and deleting images open no socket or process, and findings.py has no command for any of them")


def _add_optional_flags(parser: argparse.ArgumentParser) -> None:
    for name in (*TEXT_FIELDS, "cvss", "cwe", "cve", "cvss-vector", "cvss-justification"):
        parser.add_argument(f"--{name}")


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
    _add_optional_flags(a)

    s = sub.add_parser("set", help="update status/artifact of a finding")
    s.set_defaults(fn=cmd_set)
    s.add_argument("--ledger", required=True)
    s.add_argument("--id", required=True)
    s.add_argument("--status", choices=STATUSES)
    s.add_argument("--artifact")
    s.add_argument("--corroboration", help="the independent second signal that agrees; REQUIRED to set status=confirmed (style.md)")
    s.add_argument("--blocker", help="the exact fact the operator must observe; REQUIRED to set status=needs_validation")
    s.add_argument("--retest", help="what was re-tested after the fix and with what result; REQUIRED to set status=remediated")
    _add_optional_flags(s)

    l = sub.add_parser("list", help="one line per finding")
    l.set_defaults(fn=cmd_list)
    l.add_argument("--ledger", required=True)
    l.add_argument("--status", choices=STATUSES)

    r = sub.add_parser("render", help="markdown projection (confirmed only unless --all)")
    r.set_defaults(fn=cmd_render)
    r.add_argument("--ledger", required=True)
    r.add_argument("--all", action="store_true")
    r.add_argument("--lang", choices=("en", "es"), default="en")
    r.add_argument("--tipo", help="report template name (default: the plain projection)")
    r.add_argument("--workspace", help="name shown in the report eyebrow (default: the ledger's folder when it is engagements/<codename>/, else none)")
    r.add_argument("--borrador", help="operator draft JSON (needs --tipo)")

    c = sub.add_parser("comment", help="operator comments on a finding: append-only, never part of the report")
    comment_sub = c.add_subparsers(required=True)
    ca = comment_sub.add_parser("add", help="comment on a finding; prints the comment id")
    ca.set_defaults(fn=cmd_comment_add)
    ca.add_argument("--id", required=True, help="the finding id")
    ca.add_argument("--text", required=True)
    ce = comment_sub.add_parser("edit", help="replace the text of a comment")
    ce.set_defaults(fn=cmd_comment_edit)
    ce.add_argument("--comment", required=True)
    ce.add_argument("--text", required=True)
    cd = comment_sub.add_parser("delete", help="hide a comment (its text stays in the file)")
    cd.set_defaults(fn=cmd_comment_delete)
    cd.add_argument("--comment", required=True)
    cl = comment_sub.add_parser("list", help="one line per live comment")
    cl.set_defaults(fn=cmd_comment_list)
    cl.add_argument("--id")
    for comment_parser in (ca, ce, cd, cl):
        comment_parser.add_argument("--ledger", required=True)

    sub.add_parser("selftest", help="run built-in asserts").set_defaults(fn=cmd_selftest)

    args = p.parse_args()
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(errors="backslashreplace")  # a lone surrogate in a row must not crash the printer
    args.fn(args)


if __name__ == "__main__":
    main()
