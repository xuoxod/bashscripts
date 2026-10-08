#!/bin/bash
set -e
set -u
set -o pipefail

clearVars() {
    unset $@
}

gracefulExit() {
    clearVars
    exit 0
}

trap "gracefulExit" INT TERM QUIT PWR

if [ $# -gt 0 ]; then
    echo "$@"
fi
