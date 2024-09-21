#!/usr/bin/env bash
<<COMMENT
    Helper script
COMMENT

set -e          # Exit if any command has a non-zero exit status
set -u          # Set variables before using them
set -o pipefail # Prevent pipeline errors from being masked
set -m          # enable job control
# set -x Prints command to the console

source constants.sh
IP4_PATTERN='^([1-9]{1,3}\.)([1-9][0-9]{1,2}[1-9]{1}))'

ARG=""
clearVars() {
    unset ARG
}

gracefulExit() {
    clearVars
    exit "$EXIT_PROG"
}

exitProg() {
    gracefulExit
}

test() {
    clear
    printf "\n\n\t\t\t Initializing Test Environment ...\n\n\n"
    sleep 1

    if [[ "${IP4_PATTERN}" =~ "$ARG" ]]; then
        printf "\n\t\tGood IP4\n\n"
    else
        printf "\nI don't know what $ARG is\n\n"
    fi
}

trap "gracefulExit" INT TERM QUIT PWR STOP KILL

if [[ $# -eq 1 ]]; then
    ARG="$1"
    test
fi
