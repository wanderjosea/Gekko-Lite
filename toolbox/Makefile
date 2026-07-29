# PenA red-team toolbox. Kali headless + KB tools, one image, two contexts:
# run here for local analysis on pulled-back artifacts; run on the operator's
# box for live-target work. The target is never baked in — pass it at runtime.
IMAGE      := pena-toolbox
TAG        := $(shell date -u +%Y%m%d)
REPO_ROOT  := $(shell git rev-parse --show-toplevel)
RUN        := docker run --rm -it -v $(REPO_ROOT):/work -w /work $(IMAGE):latest

.PHONY: build shell run vpn versions save help

build:     ## Build the image (tags :latest and :YYYYMMDD)
	docker build -t $(IMAGE):latest -t $(IMAGE):$(TAG) .

shell:     ## Interactive shell with the repo mounted at /work
	$(RUN)

run:       ## Run one tool: make run CMD='nmap -sV 10.10.10.10'
	$(RUN) bash -lc '$(CMD)'

vpn:       ## Restricted VPN: shell with the .ovpn up inside the container (make vpn OVPN=~/x.ovpn)
	@test -n "$(OVPN)" || { echo "set OVPN=/path/to.ovpn"; exit 1; }
	docker run --rm -it --cap-add=NET_ADMIN --device=/dev/net/tun \
	  -v $(abspath $(OVPN)):/vpn/target.ovpn:ro -v $(REPO_ROOT):/work -w /work $(IMAGE):latest \
	  bash -c 'openvpn --config /vpn/target.ovpn --daemon --log /vpn/openvpn.log; sleep 4; \
	           ip -4 addr show tun0 | grep -q inet && echo "[+] tun0 up" || echo "[!] check /vpn/openvpn.log"; exec bash'

versions:  ## Print the shipped tool/package manifest
	docker run --rm $(IMAGE):latest cat /opt/tool-versions.txt

save:      ## Export the image to carry to the operator's machine
	docker save $(IMAGE):latest | gzip > pena-toolbox.tar.gz

help:
	@grep -E '^[a-z]+:.*##' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/'
