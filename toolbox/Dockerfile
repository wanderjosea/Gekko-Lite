# Gekko red-team toolbox — Kali headless + the tools the KB actually references.
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
      mosquitto-clients regripper \
      python3-pip pipx curl ca-certificates libcap2-bin iputils-ping openssh-server \
 && pip install --break-system-packages paho-mqtt \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Gekko governed runner drops ALL caps (cap-drop=ALL). Kali ships nmap with a
# file capability (cap_net_raw) so exec of the capability-bearing binary EPERMs
# under an empty bounding set — even a plain -sT connect scan can't start. A
# contained runner never needs raw sockets, so strip the file cap; connect scans
# then run as the unprivileged exec user. (SYN/OS-detect are unavailable, which
# is fine inside an egress-allowlisted netns.)
RUN setcap -r /usr/lib/nmap/nmap || true

# kerbrute: not packaged in Kali. Pinned static binary for reproducibility.
ARG KERBRUTE_VERSION=v1.0.3
RUN curl -fsSL -o /usr/local/bin/kerbrute \
      "https://github.com/ropnop/kerbrute/releases/download/${KERBRUTE_VERSION}/kerbrute_linux_amd64" \
 && chmod +x /usr/local/bin/kerbrute

# medusa (AI-first SAST, heavily used in the KB) — pip-only, isolated via pipx.
ENV PIPX_BIN_DIR=/usr/local/bin
RUN pipx install medusa-security

# coercer: authentication-coercion multitool (PetitPotam/PrinterBug/DFSCoerce/etc.
# in one). Not packaged in Kali; impacket-scripts ships no coercion example. This
# is the missing ESC11 primitive — the ICPR relay needs a privileged account
# coerced to auth at the relay, and no run could complete AD CS ESC11 without it.
RUN pipx install coercer

# libfaketime: LD_PRELOAD shim for clock-skew workaround (Kerberos auth after
# AD CS cert relay). The container runs --cap-drop ALL so date(1) can't set the
# clock; libfaketime lets certipy-ad/impacket see the DC's time without SYS_TIME.
# pip puts the .so in site-packages; the wrapper script finds it at runtime.
RUN pip install --break-system-packages libfaketime

# impacket ADCS patch: pyOpenSSL 26+ (Kali/Python 3.14) removed X509Req()
# which impacket uses for CSR generation in ESC1/ESC11 relay attacks.
# This patch rewrites generate_csr + rpcattack key generation to use pure
# cryptography — no pyOpenSSL version dependency.
COPY patches/fix-impacket-adcs-py314.py /tmp/fix-impacket-adcs-py314.py
RUN python3 /tmp/fix-impacket-adcs-py314.py && rm /tmp/fix-impacket-adcs-py314.py

# Manifest of what actually shipped — auditable/reproducible engagements.
RUN { echo "# built: $(date -u +%FT%TZ)"; \
      echo "# base:  kalilinux/kali-rolling"; \
      dpkg -l | awk '/^ii/{print $2"="$3}'; } > /opt/tool-versions.txt

WORKDIR /work
CMD ["/bin/bash"]
