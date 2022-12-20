#! /usr/bin/bash
ip -4 addr show "$(netface)" | grep -E "inet (([0-9])\.){4}*" | awk '{print $2}' | awk -F "/" '{print $1}'
