#!/usr/bin/env python3
"""Gekko-Lite Codex scope guard.

Modes:
  hook    - Codex PreToolUse handler; reads one event from stdin.
  start   - starts the guarded Direct Interaction toolbox for a signed scope.
  status  - verifies that the guarded toolbox is ready for that scope.
  stop    - stops that guarded toolbox.
  exec    - validates a signed scope and runs one structured target command.

The project hook is an immediate guardrail. For a stronger boundary, install a
copy outside the workspace and combine it with the Direct Interaction toolbox firewall.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

NETWORK_TOOLS = {
    "curl", "wget", "nmap", "nc", "ncat", "netcat", "socat", "ssh", "scp",
    "sftp", "ftp", "telnet", "openssl", "ffuf", "feroxbuster", "gobuster",
    "sqlmap", "hydra", "medusa", "netexec", "nxc", "smbclient", "ldapsearch",
    "rpcclient", "evil-winrm", "responder", "impacket-smbclient", "impacket-wmiexec",
    "impacket-psexec", "docker", "podman", "git",
}
SUPPORTED_EXEC_TOOLS = {"curl", "nmap", "openssl"}
LOCAL_READ_TOOLS = {
    "cat", "cut", "diff", "file", "head", "jq", "less", "ls",
    "nl", "pwd", "readelf", "rg", "sed", "sha256sum", "sort", "stat", "strings",
    "tail", "wc",
}
PROTECTED_PATH_MARKERS = (
    ".codex/hooks", ".codex/hooks.json", ".codex/policy",
    ".claude/rules/scope.md",
)
URL_RE = re.compile(r"(?:https?|ftp)://[^\s'\"]+", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")


class PolicyError(RuntimeError):
    """A fail-closed policy decision."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime | None = None) -> str:
    return (value or utc_now()).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compact_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()[:32]


def audit_reason_code(reason: str) -> str:
    lowered = reason.lower()
    checks = (
        ("signature", "scope-signature"),
        ("mcp", "mcp-blocked"),
        ("shell", "shell-policy"),
        ("network", "network-blocked"),
        ("policy", "policy-immutable"),
        ("audit", "audit-protected"),
        ("scope", "scope-policy"),
    )
    return next((code for marker, code in checks if marker in lowered), "policy-deny")


def audit_path(scope_path: Path | None) -> Path:
    override = os.environ.get("PENA_AUDIT_FILE")
    if override:
        return Path(override)
    if scope_path:
        return scope_path.parent / "audit" / "actions.jsonl"
    return Path.cwd() / ".codex" / "audit" / "hooks.jsonl"


def append_audit(*, scope_path: Path | None, session_id: str, tool: str,
                 command: str, decision: str, reason: str) -> None:
    path = audit_path(scope_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    max_bytes = int(os.environ.get("PENA_AUDIT_MAX_BYTES", str(25 * 1024 * 1024)))
    if path.exists() and path.stat().st_size >= max_bytes:
        rotated = path.with_suffix(path.suffix + ".1")
        if rotated.exists():
            rotated.unlink()
        path.replace(rotated)
    row = {
        "ts": timestamp(),
        "sid": compact_hash(session_id)[:16] if session_id else "unknown",
        "tool": tool,
        "cmd": compact_hash(command),
        "scope": sha256_file(scope_path)[:32] if scope_path and scope_path.exists() else "none",
        "decision": decision,
        "reason": audit_reason_code(reason) if decision == "deny" else reason,
    }
    with path.open("a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.write(json.dumps(row, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def verify_signature(scope_path: Path, public_key: Path) -> None:
    signature = Path(str(scope_path) + ".sig")
    if not signature.is_file():
        raise PolicyError(f"missing scope signature: {signature}")
    if not public_key.is_file():
        raise PolicyError(f"missing operator public key: {public_key}")
    openssl = shutil.which("openssl")
    if not openssl:
        raise PolicyError("openssl is required to verify the signed scope")
    result = subprocess.run(
        [openssl, "dgst", "-sha256", "-verify", str(public_key),
         "-signature", str(signature), str(scope_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise PolicyError("scope signature verification failed")


def load_scope(scope_arg: str | None = None, public_key_arg: str | None = None) -> tuple[dict, Path]:
    raw_path = scope_arg or os.environ.get("PENA_SCOPE_FILE")
    if not raw_path:
        raise PolicyError("no active signed scope (PENA_SCOPE_FILE is unset)")
    scope_path = Path(raw_path).resolve()
    if not scope_path.is_file():
        raise PolicyError(f"scope file not found: {scope_path}")
    public_raw = public_key_arg or os.environ.get("PENA_SCOPE_PUBLIC_KEY")
    if not public_raw:
        raise PolicyError("PENA_SCOPE_PUBLIC_KEY is unset")
    public_key = Path(public_raw).resolve()
    workspace_raw = os.environ.get("PENA_WORKSPACE_ROOT")
    workspace_root = Path(workspace_raw).resolve() if workspace_raw else pena_workspace(str(Path.cwd()))
    try:
        public_key.relative_to(workspace_root or Path.cwd().resolve())
    except ValueError:
        pass
    else:
        raise PolicyError("operator public key must live outside the workspace")
    verify_signature(scope_path, public_key)
    try:
        scope = json.loads(scope_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"invalid scope JSON: {exc}") from exc
    validate_scope(scope)
    return scope, scope_path


def validate_scope(scope: dict) -> None:
    required = {"engagement", "mode", "valid_from", "valid_until", "targets", "actions", "limits", "allowed_tools"}
    missing = sorted(required - set(scope))
    if missing:
        raise PolicyError(f"scope missing required fields: {', '.join(missing)}")
    if scope["mode"] not in {"enforcement", "direct-interaction"}:
        raise PolicyError("scope mode must be enforcement or direct-interaction")
    now = utc_now()
    if now < parse_time(str(scope["valid_from"])):
        raise PolicyError("scope validity window has not started")
    if now > parse_time(str(scope["valid_until"])):
        raise PolicyError("scope has expired")
    if not isinstance(scope["targets"], list) or not scope["targets"]:
        raise PolicyError("scope has no targets")
    for target in scope["targets"]:
        try:
            parsed_host = ipaddress.ip_address(str(target["host"]))
        except (KeyError, ValueError) as exc:
            raise PolicyError("target host must be an explicit IP literal") from exc
        if parsed_host.version != 4:
            raise PolicyError("initial guard supports explicit IPv4 targets only")
        ports = target.get("ports")
        if not isinstance(ports, list) or not ports or any(not isinstance(p, int) or not 1 <= p <= 65535 for p in ports):
            raise PolicyError("each target requires explicit integer ports")
    actions = scope["actions"]
    if actions.get("dos") is not False:
        raise PolicyError("DoS must be explicitly false")
    if actions.get("state_changes") is not False:
        raise PolicyError("Codex target writes are unsupported; state_changes must be false")
    if actions.get("brute_force") is not False:
        raise PolicyError("Codex brute force is unsupported; brute_force must be false")
    limits = scope["limits"]
    try:
        rate = float(limits["requests_per_second"])
        max_actions = int(limits["max_actions"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PolicyError("scope limits must contain numeric requests_per_second and max_actions") from exc
    if rate <= 0 or max_actions <= 0:
        raise PolicyError("scope limits must be greater than zero")
    if not set(scope["allowed_tools"]).issubset(SUPPORTED_EXEC_TOOLS):
        raise PolicyError("scope contains unsupported target tools")


def deny(reason: str, *, event: dict, command: str = "", scope_path: Path | None = None) -> int:
    try:
        append_audit(
            scope_path=scope_path,
            session_id=str(event.get("session_id", "")),
            tool=str(event.get("tool_name", "unknown")),
            command=command,
            decision="deny",
            reason=reason,
        )
    except OSError:
        pass
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"Gekko-Lite: {reason}",
        }
    }))
    return 0


def shell_tokens(command: str) -> list[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        raise PolicyError(f"ambiguous shell syntax: {exc}") from exc
    controls = {"|", "||", "&&", ";", "&", ">", ">>", "<", "<<", "<<<"}
    if any(token in controls for token in tokens) or "$(" in command or "`" in command:
        raise PolicyError("network commands may not use shell composition or substitution")
    return tokens


def pena_workspace(cwd: str) -> Path | None:
    current = Path(cwd or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "CLAUDE.md").is_file() and (candidate / ".claude" / "rules" / "scope.md").is_file() and (candidate / ".codex" / "policy" / "scope.schema.json").is_file():
            return candidate
    return None


def trusted_guard_mode(tokens: list[str]) -> str | None:
    if len(tokens) >= 3 and Path(tokens[0]).name.startswith("python"):
        path_index, mode_index = 1, 2
    elif len(tokens) >= 2 and Path(tokens[0]).name == "pena_guard.py":
        path_index, mode_index = 0, 1
    else:
        return None
    try:
        guard_path = Path(tokens[path_index]).expanduser().resolve(strict=True)
    except OSError:
        return None
    trusted_guards = {
        Path(__file__).resolve(),
        Path("~/.codex/pena-hooks/pena_guard.py").expanduser().resolve(),
    }
    if os.environ.get("PENA_GUARD_PATH"):
        trusted_guards.add(Path(os.environ["PENA_GUARD_PATH"]).expanduser().resolve())
    return tokens[mode_index] if guard_path in trusted_guards else None


def is_guard_exec(tokens: list[str]) -> bool:
    return trusted_guard_mode(tokens) == "exec"


def looks_network_capable(command: str, tokens: list[str]) -> bool:
    basenames = {Path(token).name for token in tokens}
    if tokens and Path(tokens[0]).name in LOCAL_READ_TOOLS:
        return False
    if tokens and Path(tokens[0]).name == "git":
        network_git = {"push", "fetch", "pull", "clone", "ls-remote", "submodule", "lfs", "svn"}
        return (len(tokens) < 2 or tokens[1] in network_git or tokens[1].startswith("-")
                or any(token.startswith("--remote") for token in tokens[2:]))
    if tokens and Path(tokens[0]).name in {"bash", "sh", "zsh", "python", "python3", "node", "perl", "ruby", "pwsh", "powershell"}:
        nested = " ".join(tokens[1:])
        tool_pattern = r"(?:^|[^A-Za-z0-9_-])(" + "|".join(re.escape(x) for x in sorted(NETWORK_TOOLS)) + r")(?:$|[^A-Za-z0-9_-])"
        if re.search(tool_pattern, nested) or URL_RE.search(nested) or IPV4_RE.search(nested):
            return True
    if basenames & NETWORK_TOOLS:
        return True
    lowered = command.lower()
    if URL_RE.search(command) or IPV4_RE.search(command):
        return True
    return any(marker in lowered for marker in ("/dev/tcp/", "socket.connect", "requests.get(", "requests.post("))


def protected_write(tool_input: object, scope_path: Path | None) -> bool:
    rendered = json.dumps(tool_input, ensure_ascii=False) if not isinstance(tool_input, str) else tool_input
    markers = list(PROTECTED_PATH_MARKERS)
    if scope_path:
        markers.append(str(scope_path))
        markers.append(str(scope_path) + ".sig")
        markers.append(str(scope_path.parent / "audit"))
        try:
            relative_scope = scope_path.relative_to(Path.cwd().resolve())
            markers.append(str(relative_scope))
            markers.append(str(relative_scope) + ".sig")
            markers.append(str(relative_scope.parent / "audit"))
        except ValueError:
            pass
    return any(marker in rendered for marker in markers)


def looks_like_shell_write(command: str) -> bool:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    write_tools = {"cp", "mv", "rm", "tee", "truncate", "dd", "install", "touch", "chmod", "chown"}
    basenames = {Path(token).name for token in tokens}
    return bool(basenames & write_tools) or any(marker in command for marker in (">", "sed -i", "sed --in-place"))


def hook_main() -> int:
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError) as exc:
        return deny(f"invalid hook input: {exc}", event={})
    tool = str(event.get("tool_name", ""))
    if pena_workspace(str(event.get("cwd", Path.cwd()))) is None:
        return 0
    tool_input = event.get("tool_input", {})
    command = str(tool_input.get("command", "")) if isinstance(tool_input, dict) else ""
    scope_path = Path(os.environ["PENA_SCOPE_FILE"]).resolve() if os.environ.get("PENA_SCOPE_FILE") else None

    if tool in {"apply_patch", "Edit", "Write"} and protected_write(tool_input, scope_path):
        return deny("policy, hook, or signed-scope files are immutable during an agent session", event=event, command=command, scope_path=scope_path)
    if tool.startswith("mcp__") and scope_path:
        return deny("MCP/connectors are disabled while engagement scope is active", event=event, scope_path=scope_path)
    if tool != "Bash":
        return 0
    if protected_write(command, scope_path):
        try:
            preliminary_tokens = shlex.split(command, posix=True)
        except ValueError:
            preliminary_tokens = []
        safe_read = preliminary_tokens and Path(preliminary_tokens[0]).name in LOCAL_READ_TOOLS and not looks_like_shell_write(command)
        if not is_guard_exec(preliminary_tokens) and not safe_read:
            return deny("non-read shell access to policy, hook, scope, or audit paths is blocked", event=event, command=command, scope_path=scope_path)
    try:
        tokens = shell_tokens(command)
    except PolicyError as exc:
        rough_tokens = re.findall(r"[A-Za-z0-9_./-]+", command)
        rough_basenames = {Path(token).name for token in rough_tokens}
        if rough_basenames & NETWORK_TOOLS or URL_RE.search(command) or IPV4_RE.search(command):
            return deny(str(exc), event=event, command=command, scope_path=scope_path)
        return 0
    guard_mode = trusted_guard_mode(tokens)
    if guard_mode and guard_mode != "exec":
        return deny("only pena_guard.py exec is available to Codex; toolbox lifecycle is operator-controlled", event=event, command=command, scope_path=scope_path)
    if is_guard_exec(tokens):
        try:
            load_scope()
        except PolicyError as exc:
            return deny(str(exc), event=event, command=command, scope_path=scope_path)
        return 0
    if not looks_network_capable(command, tokens):
        return 0
    reason = "direct network-capable commands are blocked; use pena_guard.py exec with a signed scope"
    return deny(reason, event=event, command=command, scope_path=scope_path)


def authorized_target(scope: dict, host: str, port: int, protocol: str) -> bool:
    return any(
        str(item.get("host")) == host
        and str(item.get("protocol", "tcp")) == protocol
        and port in item.get("ports", [])
        for item in scope["targets"]
    )


def docker() -> str:
    executable = shutil.which("docker")
    if not executable:
        raise PolicyError("docker is required for Direct Interaction Mode")
    return executable


def expected_container_name(scope: dict, scope_path: Path) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(scope["engagement"]).lower()).strip("-")[:32]
    if not slug:
        raise PolicyError("engagement name cannot produce a safe container name")
    return f"pena-{slug}-{sha256_file(scope_path)[:8]}"


def inspect_container(container: str, scope_path: Path) -> None:
    if not re.fullmatch(r"pena-[a-z0-9-]{1,48}-[0-9a-f]{8}", container):
        raise PolicyError("invalid Gekko-Lite toolbox container name")
    result = subprocess.run(
        [docker(), "inspect", "--format", "{{json .Config.Labels}}", container],
        text=True, capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise PolicyError("guarded toolbox container is unavailable")
    try:
        labels = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise PolicyError("guarded toolbox labels are invalid") from exc
    if labels.get("pena.mode") != "direct-interaction":
        raise PolicyError("container is not a Direct Interaction toolbox")
    if labels.get("pena.scope_sha256") != sha256_file(scope_path):
        raise PolicyError("container scope label does not match the active signed scope")
    ready = subprocess.run(
        [docker(), "exec", container, "sh", "-c", "test -f /run/pena/ready && cat /run/pena/scope.sha256"],
        text=True, capture_output=True, check=False,
    )
    if ready.returncode != 0 or ready.stdout.strip() != sha256_file(scope_path):
        raise PolicyError("guarded toolbox VPN/firewall is not ready for this scope")


def scope_engagement_directory(scope: dict, scope_path: Path) -> tuple[Path, Path]:
    """Require a named engagement scope without enumerating any engagements."""
    workspace_raw = os.environ.get("PENA_WORKSPACE_ROOT")
    workspace = Path(workspace_raw).resolve() if workspace_raw else pena_workspace(str(scope_path.parent))
    if workspace is None:
        raise PolicyError("Gekko-Lite workspace root is unavailable")
    engagements = workspace / "engagements"
    try:
        relative = scope_path.relative_to(engagements)
    except ValueError as exc:
        raise PolicyError("Direct Interaction Mode requires a scope under engagements/NAME/") from exc
    if len(relative.parts) != 2 or relative.name != "scope.json" or relative.parent.name != str(scope["engagement"]):
        raise PolicyError("scope must be engagements/<engagement>/scope.json and match its engagement field")
    return workspace, scope_path.parent


def start_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="pena_guard.py start")
    parser.add_argument("--scope", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--ovpn", required=True)
    parser.add_argument("--image", default="pena-toolbox:latest")
    args = parser.parse_args(argv)
    scope, scope_path = load_scope(args.scope, args.public_key)
    if scope["mode"] != "direct-interaction":
        raise PolicyError("scope mode must be direct-interaction to start the toolbox")
    workspace, _ = scope_engagement_directory(scope, scope_path)
    ovpn = Path(args.ovpn).expanduser().resolve()
    if not ovpn.is_file():
        raise PolicyError(f"OpenVPN profile not found: {ovpn}")
    try:
        ovpn.relative_to(workspace)
    except ValueError:
        pass
    else:
        raise PolicyError("OpenVPN profile must live outside the workspace")
    container = expected_container_name(scope, scope_path)
    existing = subprocess.run([docker(), "ps", "-aq", "--filter", f"name=^{container}$"],
                              text=True, capture_output=True, check=False)
    if existing.returncode == 0 and existing.stdout.strip():
        inspect_container(container, scope_path)
        print(container)
        return 0
    scope_hash = sha256_file(scope_path)
    command = [
        docker(), "run", "-d", "--name", container,
        "--label", "pena.mode=direct-interaction",
        "--label", f"pena.scope_sha256={scope_hash}",
        "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
        "--device", "/dev/net/tun", "--security-opt", "no-new-privileges",
        "--read-only", "--pids-limit", "512", "--memory", "4g", "--cpus", "2",
        "--tmpfs", "/run:rw,nosuid,nodev,noexec,size=32m",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
        "--tmpfs", "/root:rw,nosuid,nodev,size=64m",
        "-v", f"{ovpn}:/vpn/target.ovpn:ro",
        "-v", f"{scope_path}:/scope/scope.json:ro",
        "-v", f"{workspace}:/work:ro", "-w", "/work",
        args.image, "/usr/local/sbin/pena-guarded-entrypoint",
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise PolicyError("unable to start guarded Direct Interaction toolbox")
    try:
        for _ in range(35):
            try:
                inspect_container(container, scope_path)
                print(container)
                return 0
            except PolicyError:
                import time
                time.sleep(1)
        raise PolicyError("guarded toolbox did not become ready within 35 seconds")
    except PolicyError:
        subprocess.run([docker(), "stop", "--time", "2", container], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)
        raise


def status_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="pena_guard.py status")
    parser.add_argument("--scope", required=True)
    parser.add_argument("--public-key", required=True)
    args = parser.parse_args(argv)
    scope, scope_path = load_scope(args.scope, args.public_key)
    if scope["mode"] != "direct-interaction":
        raise PolicyError("scope mode is not direct-interaction")
    inspect_container(expected_container_name(scope, scope_path), scope_path)
    print("ready")
    return 0


def stop_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="pena_guard.py stop")
    parser.add_argument("--scope", required=True)
    parser.add_argument("--public-key", required=True)
    args = parser.parse_args(argv)
    scope, scope_path = load_scope(args.scope, args.public_key)
    if scope["mode"] != "direct-interaction":
        raise PolicyError("scope mode is not direct-interaction")
    container = expected_container_name(scope, scope_path)
    inspect_container(container, scope_path)
    result = subprocess.run([docker(), "stop", "--time", "10", container], check=False)
    if result.returncode != 0:
        raise PolicyError("unable to stop guarded toolbox")
    return 0


def reserve_action(scope: dict, scope_path: Path, *, tool: str, command: str,
                   action: str) -> None:
    """Atomically enforce wrapper-invocation count/rate and append the allow event.

    These limits count wrapper actions, not packets generated internally by a
    scanner. Packet-level enforcement belongs in the toolbox firewall.
    """
    path = audit_path(scope_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    max_bytes = int(os.environ.get("PENA_AUDIT_MAX_BYTES", str(25 * 1024 * 1024)))
    if path.exists() and path.stat().st_size >= max_bytes:
        rotated = path.with_suffix(path.suffix + ".1")
        if rotated.exists():
            rotated.unlink()
        path.replace(rotated)
    now = utc_now()
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.seek(0)
        rows = []
        for line in handle:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                raise PolicyError("audit log is corrupt; refusing target action")
        allowed = [row for row in rows if row.get("decision") == "allow"]
        max_actions = int(scope["limits"]["max_actions"])
        if len(allowed) >= max_actions:
            raise PolicyError("signed scope action limit reached")
        rate = float(scope["limits"]["requests_per_second"])
        if allowed:
            last = parse_time(str(allowed[-1]["ts"]))
            if (now - last).total_seconds() < 1.0 / rate:
                raise PolicyError("signed scope rate limit exceeded")
        row = {
            "ts": timestamp(now),
            "sid": compact_hash(os.environ.get("CODEX_THREAD_ID", "operator"))[:16],
            "tool": tool,
            "cmd": compact_hash(command),
            "scope": sha256_file(scope_path)[:32],
            "decision": "allow",
            "reason": action,
        }
        handle.seek(0, os.SEEK_END)
        handle.write(json.dumps(row, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def validate_command(argv: list[str], *, tool: str, host: str, port: int,
                     protocol: str, action: str) -> list[str]:
    if not argv:
        raise PolicyError("missing target command")
    if Path(argv[0]).name != tool:
        raise PolicyError("declared tool does not match command executable")
    rendered = []
    saw_host = saw_port = False
    for arg in argv:
        saw_host = saw_host or "{HOST}" in arg
        saw_port = saw_port or "{PORT}" in arg
        rendered.append(arg.replace("{HOST}", host).replace("{PORT}", str(port)))
    if not saw_host or not saw_port:
        raise PolicyError("command must use both {HOST} and {PORT} placeholders")
    for arg in rendered:
        for candidate in IPV4_RE.findall(arg):
            try:
                if str(ipaddress.ip_address(candidate)) != host:
                    raise PolicyError(f"command contains out-of-scope IP: {candidate}")
            except ValueError as exc:
                raise PolicyError(f"invalid IP literal in command: {candidate}") from exc
        for raw_url in URL_RE.findall(arg):
            parsed = urlsplit(raw_url)
            effective_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if parsed.hostname != host or effective_port != port:
                raise PolicyError("command URL does not match the authorized host and port")
    if tool == "curl":
        forbidden = {
            "-L", "--location", "--location-trusted", "-x", "--proxy",
            "--preproxy", "--proxy-header", "--connect-to", "--resolve",
            "-K", "--config", "--url", "--unix-socket", "--abstract-unix-socket",
            "--next", "-n", "--netrc", "--netrc-file", "--netrc-optional",
        }
        if forbidden.intersection(rendered):
            raise PolicyError("curl redirects, proxies, alternate routing, and config files are blocked")
        write_long = ("--data", "--data-raw", "--data-binary", "--data-urlencode", "--json", "--form", "--form-string", "--upload-file")
        write_short = ("-d", "-F", "-T")
        has_write_flag = any(
            arg in write_long or any(arg.startswith(flag + "=") for flag in write_long)
            or arg in write_short or any(arg.startswith(flag) and arg != flag for flag in write_short)
            or arg.upper() in {"POST", "PUT", "PATCH", "DELETE"}
            or arg.upper().startswith("-XPOST") or arg.upper().startswith("-XPUT")
            or arg.upper().startswith("-XPATCH") or arg.upper().startswith("-XDELETE")
            for arg in rendered
        )
        if action == "read" and has_write_flag:
            raise PolicyError("state-changing curl options require action=write")
        url_args = [arg for arg in rendered if URL_RE.fullmatch(arg)]
        if len(url_args) != 1:
            raise PolicyError("curl requires exactly one explicit HTTP(S) URL")
        domain_re = re.compile(r"(?i)(?:^|[^A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d+)?(?:$|[^A-Za-z0-9-])")
        if any(domain_re.search(arg) for arg in rendered if arg != url_args[0]):
            raise PolicyError("curl contains a secondary hostname or virtual host")
        if any("host:" in arg.lower() or ":authority:" in arg.lower() for arg in rendered):
            raise PolicyError("alternate HTTP Host/:authority values are blocked")
        rendered[1:1] = ["-q", "--proto", "=http,https", "--max-redirs", "0"]
    if tool == "nmap" and action != "scan":
        raise PolicyError("nmap requires action=scan")
    if tool == "nmap":
        allowed_no_value = {"-Pn", "-sT", "-sV", "-sU", "-n", "--open"}
        allowed_with_value = {"-p", "--version-intensity", "--host-timeout", "--max-retries", "--scan-delay"}
        index = 1
        positional = []
        while index < len(rendered):
            token = rendered[index]
            if token in allowed_no_value:
                index += 1
            elif token in allowed_with_value:
                if index + 1 >= len(rendered):
                    raise PolicyError(f"nmap option requires a value: {token}")
                index += 2
            elif token == host:
                positional.append(token)
                index += 1
            else:
                raise PolicyError(f"nmap option or target is not in the restricted allowlist: {token}")
        if positional != [host] or rendered.count("-p") != 1 or rendered[rendered.index("-p") + 1] != str(port):
            raise PolicyError("nmap must contain exactly one target and '-p {PORT}'")
        if "-n" not in rendered:
            raise PolicyError("nmap requires -n to prevent out-of-scope reverse DNS")
        if protocol == "udp" and "-sU" not in rendered:
            raise PolicyError("UDP scope requires nmap -sU")
        if protocol == "tcp" and "-sU" in rendered:
            raise PolicyError("nmap -sU is outside a TCP scope")
    if tool == "openssl":
        if action != "read":
            raise PolicyError("openssl target checks require action=read")
        if len(rendered) < 4 or rendered[1] != "s_client" or rendered.count("-connect") != 1:
            raise PolicyError("only openssl s_client -connect is supported")
        if rendered[rendered.index("-connect") + 1] != f"{host}:{port}":
            raise PolicyError("openssl -connect must match {HOST}:{PORT}")
        if any(flag in rendered for flag in ("-proxy", "-proxy_user", "-proxy_pass", "-servername")):
            raise PolicyError("openssl proxy options are blocked")
        domain_re = re.compile(r"(?i)(?:^|[^A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d+)?(?:$|[^A-Za-z0-9-])")
        if any(domain_re.search(arg) for arg in rendered):
            raise PolicyError("openssl contains a secondary hostname")
    return rendered


def exec_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="pena_guard.py exec")
    parser.add_argument("--scope")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--protocol", default="tcp", choices=("tcp", "udp"))
    parser.add_argument("--action", required=True, choices=("read", "scan"))
    parser.add_argument("--tool", required=True, choices=sorted(SUPPORTED_EXEC_TOOLS))
    parser.add_argument("--container", default=os.environ.get("PENA_TOOLBOX_CONTAINER"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    scope, scope_path = load_scope(args.scope)
    if not authorized_target(scope, args.host, args.port, args.protocol):
        raise PolicyError("target host/port/protocol is outside the signed scope")
    action_key = "state_changes" if args.action == "write" else args.action
    if not bool(scope["actions"].get(action_key, False)):
        raise PolicyError(f"action is not authorized by signed scope: {args.action}")
    if args.tool not in scope["allowed_tools"]:
        raise PolicyError(f"tool is not authorized by signed scope: {args.tool}")
    rendered = validate_command(command, tool=args.tool, host=args.host, port=args.port,
                                protocol=args.protocol, action=args.action)
    printable = shlex.join(rendered)
    if args.dry_run:
        print(printable)
        return 0
    if not args.container:
        raise PolicyError("target execution requires a ready Direct Interaction toolbox container")
    if scope["mode"] != "direct-interaction":
        raise PolicyError("target execution requires a direct-interaction scope")
    if args.container != expected_container_name(scope, scope_path):
        raise PolicyError("container does not match the active signed scope")
    inspect_container(args.container, scope_path)
    reserve_action(scope, scope_path, tool=args.tool, command=printable, action=args.action)
    return subprocess.run(
        [docker(), "exec", "--workdir", "/work", args.container, *rendered],
        check=False,
    ).returncode


def main() -> int:
    modes = {"hook", "start", "status", "stop", "exec"}
    if len(sys.argv) < 2 or sys.argv[1] not in modes:
        print("usage: pena_guard.py hook|start|status|stop|exec ...", file=sys.stderr)
        return 2
    try:
        selected = sys.argv[1]
        if selected == "hook":
            return hook_main()
        if selected == "start":
            return start_main(sys.argv[2:])
        if selected == "status":
            return status_main(sys.argv[2:])
        if selected == "stop":
            return stop_main(sys.argv[2:])
        return exec_main(sys.argv[2:])
    except PolicyError as exc:
        print(f"Gekko-Lite: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
