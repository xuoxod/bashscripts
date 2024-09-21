#!/usr/bin/env bash

# Network Interface Promiscuous Mode Utility

set -e
set -u
set -o pipefail

declare interface=""

# Function to display a help message
usage() {
    echo "Usage: $0 [OPTIONS] <interface>"
    echo "Options:"
    echo "  -h, --help               Display this help message"
    echo "  -l, --list              List available network interfaces"
    echo "  -e, --enable            Enable promiscuous mode on the specified interface"
    echo "  -d, --disable           Disable promiscuous mode on the specified interface"
    echo "  -s, --status            Check the promiscuous mode status of the specified interface"
    exit 1
}

# Function to list available network interfaces
list_interfaces() {
    ip link show | grep -Eo '^[0-9]+:\s+[^:]+' | awk '{print $2}'
}

# Function to enable promiscuous mode
enable_promiscuous() {
    if [[ ${EUID} -ne 0 ]]; then
        echo "Error: This operation requires root privileges."
        exit 1
    fi

    local interface="$1"
    if ! ip link show "${interface}" >/dev/null 2>&1; then
        echo "Error: Interface '${interface}' not found."
        exit 1
    fi

    if ip link set "${interface}" promisc on >/dev/null 2>&1; then
        echo "Promiscuous mode enabled on interface '${interface}'."
    else
        echo "Error: Failed to enable promiscuous mode on interface '${interface}'."
        exit 1
    fi
}

# Function to disable promiscuous mode
disable_promiscuous() {
    if [[ ${EUID} -ne 0 ]]; then
        echo "Error: This operation requires root privileges."
        exit 1
    fi

    local interface="$1"
    if ! ip link show "${interface}" >/dev/null 2>&1; then
        echo "Error: Interface '${interface}' not found."
        exit 1
    fi

    if ip link set "${interface}" promisc off >/dev/null 2>&1; then
        echo "Promiscuous mode disabled on interface '${interface}'."
    else
        echo "Error: Failed to disable promiscuous mode on interface '${interface}'."
        exit 1
    fi
}

# Function to check promiscuous mode status
check_status() {
    local interface="$1"
    if ! ip link show "${interface}" >/dev/null 2>&1; then
        echo "Error: Interface '${interface}' not found."
        exit 1
    fi

    if ip link show "${interface}" | grep -q "promisc on"; then
        echo "Promiscuous mode is enabled on interface '${interface}'."
    else
        echo "Promiscuous mode is disabled on interface '${interface}'."
    fi
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
    -h | --help)
        usage
        ;;
    -l | --list)
        list_interfaces
        exit 0
        ;;
    -e | --enable)
        shift
        enable_promiscuous "$1"
        exit 0
        ;;
    -d | --disable)
        shift
        disable_promiscuous "$1"
        exit 0
        ;;
    -s | --status)
        shift
        check_status "$1"
        exit 0
        ;;
    *)
        if [[ -z "${interface}" ]]; then
            interface="$1"
        else
            usage
        fi
        ;;
    esac
    shift
done

# Check if an interface was specified
if [[ -z "${interface}" ]]; then
    usage
fi

# Default action: check status
check_status "${interface}"
