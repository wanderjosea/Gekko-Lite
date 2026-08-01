#!/usr/bin/env python3
"""Apply default-drop IPv4/IPv6 firewall rules for a scoped toolbox."""
from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess
from pathlib import Path


def run(*args: str) -> None:
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", required=True)
    parser.add_argument("--vpn-metadata", required=True)
    args = parser.parse_args()
    scope = json.loads(Path(args.scope).read_text(encoding="utf-8"))
    vpn = json.loads(Path(args.vpn_metadata).read_text(encoding="utf-8"))
    vpn_ip = str(ipaddress.IPv4Address(vpn["ip"]))
    vpn_port = int(vpn["port"])
    vpn_proto = vpn["protocol"]
    if vpn_proto not in {"tcp", "udp"} or not 1 <= vpn_port <= 65535:
        raise SystemExit("invalid pinned VPN endpoint")

    for family in ("iptables", "ip6tables"):
        run(family, "-F")
        run(family, "-X")
        run(family, "-P", "INPUT", "DROP")
        run(family, "-P", "OUTPUT", "DROP")
        run(family, "-P", "FORWARD", "DROP")
        run(family, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT")
        run(family, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
        run(family, "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
        run(family, "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")

    run("iptables", "-A", "OUTPUT", "-o", "eth0", "-p", vpn_proto,
        "-d", vpn_ip, "--dport", str(vpn_port), "-j", "ACCEPT")
    for target in scope["targets"]:
        host = str(ipaddress.IPv4Address(target["host"]))
        protocol = target.get("protocol", "tcp")
        if protocol not in {"tcp", "udp"}:
            raise SystemExit("invalid target protocol")
        for raw_port in target["ports"]:
            port = int(raw_port)
            if not 1 <= port <= 65535:
                raise SystemExit("invalid target port")
            run("iptables", "-A", "OUTPUT", "-o", "tun0", "-p", protocol,
                "-d", host, "--dport", str(port), "-j", "ACCEPT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
