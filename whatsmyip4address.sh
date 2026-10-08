#!/usr/bin/env bash
# ==============================================================================
# whatsmyip4address.sh — Universal Sovereign IPv4 Resolver
# One-Job-Principle: Detects and outputs the active outbound IPv4 address.
# Zero dependencies beyond standard Linux iproute2 (ip) and awk.
# ==============================================================================
set -euo pipefail

resolve_ip4() {
    local ip

    # 1. Query Linux kernel FIB route table for outbound route (zero wire traffic)
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
    if [[ -n "${ip:-}" ]]; then
        echo "$ip"
        return 0
    fi

    # 2. Offline / local-only fallback: default gateway route interface
    ip=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
    if [[ -n "${ip:-}" ]]; then
        echo "$ip"
        return 0
    fi

    # 3. LAN fallback: first non-loopback, non-virtual global IPv4 address
    ip=$(ip -4 -o addr show scope global 2>/dev/null \
        | grep -v -E '(docker|veth|br-|virbr|tun|tap)' \
        | awk '{print $4}' | cut -d/ -f1 | head -n1)
    if [[ -n "${ip:-}" ]]; then
        echo "$ip"
        return 0
    fi

    return 1
}

if ! ip4=$(resolve_ip4); then
    echo "Error: No usable IPv4 address found on this system." >&2
    exit 1
fi

echo "$ip4"
