#!/usr/bin/env bash
# list-all-interfaces.sh - Lists all interface names
set -euo pipefail
ip -o link show | awk -F': ' '{print $2}'
