#!/usr/bin/env bash
# Lists active (UP), non-loopback, non-virtual network interfaces.
# Replaces the old, fragile netfaces.sh logic.

set -euo pipefail

ip -o link show | \
  grep 'state UP' | \
  grep -v 'LOOPBACK' | \
  awk -F': ' '{print $2}' | \
  grep -vE '^(veth|docker|virbr|br-)'

exit 0
