#!/usr/bin/env bash
# shellcheck disable=SC2116,SC2086
# trunk-ignore(shellcheck/SC2188)
<<COMMENT
    Command helper
COMMENT
# declare -r EXIT_PROG=0
# declare -r ROOT_UID=0
# declare -r NON_ROOT=121
# declare -r EXIT_UNKNOWN_USER=120
# declare -r EXIT_UNKNOWN_GROUP=119
# declare -r PROG=""
# declare -r DESC="Administrative helper script use for confirming and/or manipulating paths"

# set -e          # Exit if any command has a non-zero exit status
# set -u          # Set variables before using them
# set -o pipefail # Prevent pipeline errors from being masked
# set -m
# # set -x Prints command to the console
# source patterns.sh

# MSG=""
# ARG1=""

clearVars() {
    unset ARG1 MSG
}

gracefulExit() {
    clearVars
    exit 0
}

exitProg() {
    gracefulExit
}

generatePronounceblePassword() {
    color -w '\n\tGenerating pronouncable string ...\n'
    sleep 2
    apg -a 0 -M Sncl -m 17 -n 1 -E +\<\>\;:\|\\^\'\",\.\\={}*\\-[]\`\~\)\(\\/
    gracefulExit
}

generateNonpronounceblePassword() {
    color -w '\n\tGenerating non-pronouncable string ...\n'
    sleep 2
    apg -a 1 -M Sncl -m 17 -n 1 -E +\<\>\;:\|\\^\'\",\.\\={}*\\-[]\`\~\)\(\\/
    gracefulExit
}

gpp() {
    generatePronounceblePassword
}

gnp() {
    generateNonpronounceblePassword
}

usage() {
    printf "\nUsage:\t %s -<[ps]> [off]\n  Notice optional argument is without a dash or double dash\n\n" "$0"
    exitProg
}

randomStringGeneratorSynopsis() {
    printf " \nSynopsis:\t %s <[OPTION]> [ARGUMENT]\n\n" "$0"
    printf "Usage:\t %s - <[ps]> [argument]\n\n\n" "$0"
    printf "Options:\n\n"
    printf "\t-p:   Generate a random non-pronouncable string.\n"
    printf "\n\t          Example:\n"
    printf "\n\t               %s -p off\n\n" "$0"
    exitProg
}

endProg() {
    printf "%s\n" "${MSG}"
    gracefulExit
}

# Display network cards
displayNCards() {
    sudo lshw -class network
}

displayNCardsShort() {
    sudo lshw -class network -short
}

displayEth() {
    # sudo apt install ethtool -y
    for N in $(netfaces); do
        sudo ethtool "${N}"
        printf "\n\n"
    done
}
