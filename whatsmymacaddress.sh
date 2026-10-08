#!/usr/bin/env bash
# ==============================================================================
# whatsmymacaddress.sh — Universal Sovereign MAC Address Resolver
# One-Job-Principle: Detects and outputs the active hardware MAC address.
# ==============================================================================
set -euo pipefail

is_virtual() {
  local i="$1"
  [[ "$i" == "lo" ]] && return 0
  [[ -d "/sys/devices/virtual/net/$i" ]] && return 0
  [[ "$i" =~ ^(docker|veth|br|virbr|vboxnet|vmnet|tailscale|wg|tun|tap|zt|cni|flannel|cilium|podman|nm-|br-).* ]] && return 0
  return 1
}

primary_iface() {
  local i
  i=$(ip -o route show default 2>/dev/null | awk '{for (n=1;n<=NF;n++) if ($n=="dev") {print $(n+1); exit}}' | head -n1 || true)
  [[ -n "${i:-}" && ! $(is_virtual "$i") ]] && { echo "$i"; return; }
  i=$(ip -6 -o route show default 2>/dev/null | awk '{for (n=1;n<=NF;n++) if ($n=="dev") {print $(n+1); exit}}' | head -n1 || true)
  [[ -n "${i:-}" && ! $(is_virtual "$i") ]] && { echo "$i"; return; }
  for i in $(ip -o link show | awk -F': ' '{print $2}'); do
    is_virtual "$i" || { echo "$i"; return; }
  done
}

iface="$(primary_iface || true)"
[[ -z "${iface:-}" ]] && { echo "Error: No usable network interface found." >&2; exit 1; }

# Prefer sysfs address directly
if [[ -r "/sys/class/net/$iface/address" ]]; then
  mac="$(cat "/sys/class/net/$iface/address")"
else
  mac="$(ip -o link show dev "$iface" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="link/ether") {print $(i+1); exit}}')"
fi

if [[ -n "${mac:-}" ]]; then
  echo "$mac"
  exit 0
else
  echo "Error: Could not determine MAC for interface '$iface'." >&2
  exit 1
fi
