#!/bin/bash

clearVars() {
    unset TEMP W
}

gracefulExit() {
    clearVars
    exit 0
}

trap "gracefulExit" INT TERM PWR

if [[ $# -gt 0 ]]; then
    for W in "$@"; do
        TEMP+="${W} "
    done
    echo -e "\e[28;5;24m${TEMP}\e[m\n"
    gracefulExit
fi
