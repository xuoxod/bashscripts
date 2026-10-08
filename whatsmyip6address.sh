#!/usr/bin/env bash
# ==============================================================================
# whatsmyip6address.sh — Universal Sovereign IPv6 Resolver
# One-Job-Principle: Detects and outputs the active outbound IPv6 address.
# Zero dependencies beyond standard Linux iproute2 (ip) and awk.
# ==============================================================================
set -euo pipefail

resolve_ip6() {
    local ip dev

    # 1. Query Linux kernel FIB route table for outbound route (zero wire traffic)
    ip=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
    if [[ -n "${ip:-}" ]]; then
        echo "$ip"
        return 0
    fi

    # 2. Default route fallback: query default IPv6 device interface
    dev=$(ip -6 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' | head -n1)
    if [[ -n "${dev:-}" ]]; then
        ip=$(ip -6 -o addr show dev "$dev" scope global 2>/dev/null \
            | grep -v -E '(temporary|deprecated|tentative|dadfailed)' \
            | awk '{print $4}' | cut -d/ -f1 | head -n1)
        if [[ -n "${ip:-}" ]]; then
            echo "$ip"
            return 0
        fi
    fi

    # 3. LAN fallback: first non-loopback, non-virtual, non-linklocal global IPv6
    ip=$(ip -6 -o addr show scope global 2>/dev/null \
        | grep -v -E '(docker|veth|br-|virbr|tun|tap|temporary|deprecated|tentative|dadfailed)' \
        | awk '{print $4}' | cut -d/ -f1 | head -n1)
    if [[ -n "${ip:-}" ]]; then
        echo "$ip"
        return 0
    fi

    return 1
}

if ! ip6=$(resolve_ip6); then
    echo "Error: No usable IPv6 address found on this system." >&2
    exit 1
fi

echo "$ip6"
