# PenA red-team toolbox — Kali headless + the tools the KB actually references.
# Target-agnostic on purpose: the engagement target varies per session and is
# passed at runtime, never baked in. Hybrid model — see README.
# Base image pinned by digest for reproducibility (was :latest). Re-pin
# deliberately: docker pull kalilinux/kali-rolling:latest && \
#   docker inspect --format '{{index .RepoDigests 0}}' kalilinux/kali-rolling:latest
# latest @ 2026-07-26.
FROM kalilinux/kali-rolling@sha256:dea2bdf0e8c0ca1deb51b7a6253f481acae3ca9c2f1e2371077e6af55e5b2721

ENV DEBIAN_FRONTEND=noninteractive \
    TERM=xterm-256color

# Core suite (kali-linux-headless) + the specific KB tools not guaranteed by it.
# Every name below was verified present in the Kali repo before building.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      kali-linux-headless \
      metasploit-framework netexec impacket-scripts bloodhound.py \
      evil-winrm responder seclists chisel ligolo-ng \
      ffuf feroxbuster gobuster wpscan sqlmap hydra \
      nmap john hashcat smbclient ldap-utils \
      python3-pip pipx curl ca-certificates openvpn iptables iproute2 \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# kerbrute: not packaged in Kali. Pinned static binary for reproducibility.
ARG KERBRUTE_VERSION=v1.0.3
RUN curl -fsSL -o /usr/local/bin/kerbrute \
      "https://github.com/ropnop/kerbrute/releases/download/${KERBRUTE_VERSION}/kerbrute_linux_amd64" \
 && chmod +x /usr/local/bin/kerbrute

# medusa (AI-first SAST, heavily used in the KB) — pip-only, isolated via pipx.
ENV PIPX_BIN_DIR=/usr/local/bin
RUN pipx install medusa-security

# Manifest of what actually shipped — auditable/reproducible engagements.
RUN { echo "# built: $(date -u +%FT%TZ)"; \
      echo "# base:  kalilinux/kali-rolling"; \
      dpkg -l | awk '/^ii/{print $2"="$3}'; } > /opt/tool-versions.txt

COPY prepare_openvpn.py /usr/local/lib/pena/prepare_openvpn.py
COPY scope_firewall.py /usr/local/lib/pena/scope_firewall.py
COPY guarded-entrypoint.sh /usr/local/sbin/pena-guarded-entrypoint
RUN chmod 0555 /usr/local/lib/pena/*.py /usr/local/sbin/pena-guarded-entrypoint

WORKDIR /work
CMD ["/bin/bash"]
