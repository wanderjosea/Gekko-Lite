#!/usr/bin/env python3
"""Validate an OpenVPN profile, pin its single remote to IPv4, and copy it."""
from __future__ import annotations

import argparse
import ipaddress
import json
import shlex
import socket
from pathlib import Path

FORBIDDEN = {
    "up", "down", "route-up", "route-pre-down", "ipchange", "learn-address",
    "client-connect", "client-disconnect", "plugin", "management", "management-client",
    "script-security", "tls-verify", "auth-user-pass-verify", "iproute", "dev-node",
    "log", "log-append", "status", "writepid", "cd", "chroot",
}
INLINE_OR_FORBID = {"ca", "cert", "key", "tls-auth", "tls-crypt", "auth-user-pass"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--metadata", required=True)
    args = parser.parse_args()
    lines = Path(args.input).read_text(encoding="utf-8").splitlines()
    remotes: list[tuple[int, list[str]]] = []
    global_proto = "udp"
    inline_blocks: set[str] = set()
    active_inline: str | None = None

    for number, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith("<") and stripped.endswith(">"):
            tag = stripped[1:-1].strip().lower()
            if tag.startswith("/"):
                active_inline = None
            else:
                active_inline = tag
                inline_blocks.add(tag)
            continue
        if active_inline or not stripped or stripped.startswith(("#", ";")):
            continue
        tokens = shlex.split(stripped, comments=True, posix=True)
        if not tokens:
            continue
        directive = tokens[0].lower()
        if directive in FORBIDDEN:
            raise SystemExit(f"forbidden OpenVPN directive at line {number + 1}: {directive}")
        if directive == "remote":
            remotes.append((number, tokens))
        elif directive == "proto" and len(tokens) >= 2:
            global_proto = tokens[1].lower()
        elif directive in INLINE_OR_FORBID and directive not in inline_blocks:
            if len(tokens) > 1 and tokens[1] not in {"[inline]", "stdin"}:
                raise SystemExit(f"external OpenVPN file reference is unsupported: {directive}")

    if len(remotes) != 1:
        raise SystemExit("OpenVPN profile must contain exactly one remote directive")
    number, remote = remotes[0]
    if len(remote) < 2 or len(remote) > 4:
        raise SystemExit("invalid OpenVPN remote directive")
    remote_host = remote[1]
    remote_port = int(remote[2]) if len(remote) >= 3 else 1194
    proto_raw = remote[3].lower() if len(remote) == 4 else global_proto
    protocol = "tcp" if proto_raw.startswith("tcp") else "udp" if proto_raw.startswith("udp") else ""
    if not protocol or not 1 <= remote_port <= 65535:
        raise SystemExit("OpenVPN remote protocol/port is unsupported")
    try:
        remote_ip = str(ipaddress.IPv4Address(remote_host))
    except ipaddress.AddressValueError:
        socket_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
        answers = socket.getaddrinfo(remote_host, remote_port, socket.AF_INET, socket_type)
        if not answers:
            raise SystemExit("OpenVPN remote did not resolve to IPv4")
        remote_ip = answers[0][4][0]

    sanitized = list(lines)
    sanitized[number] = f"remote {remote_ip} {remote_port} {protocol}"
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(sanitized) + "\n", encoding="utf-8")
    output.chmod(0o600)
    Path(args.metadata).write_text(json.dumps({"ip": remote_ip, "port": remote_port, "protocol": protocol}), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
