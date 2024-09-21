#!/usr/bin/env bash
# shellcheck disable=SC2116,SC2086
# trunk-ignore(shellcheck/SC2188)
<<COMMENT
    Helper script
COMMENT

set -e          # Exit if any command has a non-zero exit status
set -u          # Set variables before using them
set -o pipefail # Prevent pipeline errors from being masked
set -m          # enable job control
# set -x Prints command to the console
source constants.sh
source patterns.sh
source ./actions.sh

# ARG=""
# MSG=""
SCRIPT=""

clearVars() {
    unset ARG MSG SCRIPT ARG_COUNT
}

gracefulExit() {
    clearVars
    exit "${EXIT_PROG}"
}

exitProg() {
    gracefulExit
}

nSynopsis() {
    printf " \nSynopsis:%15s <[OPTION]> [ARGUMENT]\n\n" "$0"
}

trap "gracefulExit" INT TERM QUIT PWR

SCRIPT=$0

optspec=":sp-"
while getopts "${optspec}" OPTION; do
    case "${OPTION}" in
    p)
        printf "Script:%19s\n" "${SCRIPT}"
        printf "Args: %19d\n\n" $#
        ;;

    s)
        printf "Script:%19s\n" "${SCRIPT}"
        printf "Args: %19d\n\n" $#
        ;;

    *)
        nSynopsis
        ;;
    esac
done

# if [ ! -z "$pflag" ]; then

shift "$((OPTIND - 1))"

printf "Remaining vars: %19d\n\n" $#

exitProg
