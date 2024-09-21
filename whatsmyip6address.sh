#! /usr/bin/bash
# ip -6 addr show "$(netface)" | grep -E "inet6 (([a-zA-Z0-9])::?)*" | awk '{print $2}' | awk -F / '{print $1}'
ip -6 addr show "$(netface)" | grep -E "inet6 (([a-zA-Z0-9])::?)*" | awk '{print $2}' | awk -F / '{print $1}'
