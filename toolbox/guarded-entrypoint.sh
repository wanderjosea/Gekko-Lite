#!/usr/bin/env bash
set -euo pipefail

scope=/scope/scope.json
profile=/vpn/target.ovpn
runtime=/run/pena
mkdir -p "$runtime"

python3 /usr/local/lib/pena/prepare_openvpn.py \
  --input "$profile" \
  --output "$runtime/target.ovpn" \
  --metadata "$runtime/vpn.json"

python3 /usr/local/lib/pena/scope_firewall.py \
  --scope "$scope" \
  --vpn-metadata "$runtime/vpn.json"

scope_hash=$(sha256sum "$scope" | cut -d' ' -f1)
printf '%s\n' "$scope_hash" > "$runtime/scope.sha256"

openvpn --config "$runtime/target.ovpn" \
  --writepid "$runtime/openvpn.pid" \
  --log "$runtime/openvpn.log" &
vpn_pid=$!
trap 'rm -f /run/pena/ready; kill "$vpn_pid" 2>/dev/null || true; wait "$vpn_pid" 2>/dev/null || true' EXIT INT TERM

for _ in $(seq 1 30); do
  if ip -4 addr show tun0 2>/dev/null | grep -q 'inet '; then
    touch "$runtime/ready"
    wait "$vpn_pid"
    exit $?
  fi
  if ! kill -0 "$vpn_pid" 2>/dev/null; then
    tail -n 20 "$runtime/openvpn.log" >&2 || true
    exit 1
  fi
  sleep 1
done

echo "tun0 did not become ready within 30 seconds" >&2
tail -n 20 "$runtime/openvpn.log" >&2 || true
exit 1
