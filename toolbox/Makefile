# Gekko-Lite red-team toolbox. Kali headless + KB tools, one image, two contexts:
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

vpn:       ## Direct Interaction Mode: guarded VPN toolbox (make vpn SCOPE=... PUBKEY=... OVPN=...)
	@test -n "$(SCOPE)" || { echo "set SCOPE=engagements/NAME/scope.json"; exit 1; }
	@test -n "$(PUBKEY)" || { echo "set PUBKEY=/SAFE/operator-scope-public.pem"; exit 1; }
	@test -n "$(OVPN)" || { echo "set OVPN=/SAFE/target.ovpn"; exit 1; }
	python3 $(REPO_ROOT)/.codex/hooks/pena_guard.py start --scope $(SCOPE) --public-key $(PUBKEY) --ovpn $(OVPN) --image $(IMAGE):latest

versions:  ## Print the shipped tool/package manifest
	docker run --rm $(IMAGE):latest cat /opt/tool-versions.txt

save:      ## Export the image to carry to the operator's machine
	docker save $(IMAGE):latest | gzip > pena-toolbox.tar.gz

help:
	@grep -E '^[a-z]+:.*##' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/'
