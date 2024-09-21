#!/usr/bin/env bash
<<COMMENT
    Administrative helper script use for:
        - Adding user to sudo group
        - Adding user to given group
        - Removing user from sudo group
        - Listing user's group(s)
        - Locking user account
        - Unlocking user account
COMMENT
declare -r PATH_TEMPLATE='^((/)?([a-zA-Z]+)(/[a-zA-Z]+/?)?$|/)'
declare -r EXIT_PROG=0
declare -r ROOT_UID=0
declare -r NON_ROOT=121
declare -r EXIT_UNKNOWN_USER=120
declare -r EXIT_UNKNOWN_GROUP=119
declare -r PATHERPROGNAME="Path Finder"
declare PATHER="$PATHERPROGNAME"
declare -r PATHERDESCRIPTION="Administrative helper script use for confirming and/or manipulating paths"
declare PATHDESC="$PATHERDESCRIPTION"

set -e          # Exit if any command has a non-zero exit status
set -u          # Set variables before using them
set -o pipefail # Prevent pipeline errors from being masked
# set -x Prints command to the console
source colortext.sh

clearVars() {
    unset $@ arg
}

gracefulExit() {
    clearVars
    exit "$EXIT_PROG"
}

exitProg() {
    gracefulExit
}

synopsis() {
    text=$(printf "\t\t\t\t $PATHER\n")
    white
    printf "$text\n"
    text=$(printf -- '%.0s-' {1..73})
    green
    printf "$text\n"
    text=$(printf "$PATHERDESC\n")
    white
    printf "$text\n\n"
}

trap "gracefulExit" INT PWR QUIT TERM

checkPath() {
    arg="$1"
    if [[ "$arg" =~ $PATH_TEMPLATE ]]; then
        if [ -e "$arg" ]; then
            printf "Path [$arg] exists\n"
            if [ -f "$arg" ]; then
                printf "Path [$arg] is a file\n"
                # Check file is readable
                if [ -r "$arg" ]; then
                    printf "File [$arg] is readable\n"
                else
                    text=$(printf "File [$arg] is not readable\n")
                    red
                    printf "$text\n"
                fi
                # Check file is writable
                if [ -w "$arg" ]; then
                    printf "File [$arg] is writable\n"
                else
                    text=$(printf "File [$arg] is not writable\n")
                    red
                    printf "$text\n"
                fi
            elif [ -c "$arg" ]; then
                printf "Path [$arg] is a character file\n"
                # Check file is readable
                if [ -r "$arg" ]; then
                    printf "File [$arg] is readable\n"
                else
                    text=$(printf "File [$arg] is not readable\n")
                    red
                    printf "$text\n"
                fi
                # Check file is writable
                if [ -w "$arg" ]; then
                    printf "File [$arg] is writable\n"
                else
                    text=$(printf "File [$arg] is not writable\n")
                    red
                    printf "$text\n"
                fi
            elif [ -b "$arg" ]; then
                printf "Path [$arg] is a block special file\n"
                # Check file is readable
                if [ -r "$arg" ]; then
                    printf "File [$arg] is readable\n"
                else
                    text=$(printf "File [$arg] is not readable\n")
                    red
                    printf "$text\n"
                fi
                # Check file is writable
                if [ -w "$arg" ]; then
                    printf "File [$arg] is writable\n"
                else
                    text=$(printf "File [$arg] is not writable\n")
                    red
                    printf "$text\n"
                fi
            elif [ -L "$arg" ]; then
                printf "Path [$arg] is a symbolic link\n"
                # Check file is readable
                if [ -r "$arg" ]; then
                    printf "File [$arg] is readable\n"
                else
                    text=$(printf "File [$arg] is not readable\n")
                    red
                    printf "$text\n"
                fi
                # Check file is writable
                if [ -w "$arg" ]; then
                    printf "File [$arg] is writable\n"
                else
                    text=$(printf "File [$arg] is not writable\n")
                    red
                    printf "$text\n"
                fi
            elif [ -S "$arg" ]; then
                printf "Path [$arg] is a socket\n"
                # Check file is readable
                if [ -r "$arg" ]; then
                    printf "File [$arg] is readable\n"
                else
                    text=$(printf "File [$arg] is not readable\n")
                    red
                    printf "$text\n"
                fi
                # Check file is writable
                if [ -w "$arg" ]; then
                    printf "File [$arg] is writable\n"
                else
                    text=$(printf "File [$arg] is not writable\n")
                    red
                    printf "$text\n"
                fi
            elif [ -d "$arg" ]; then
                printf "Path [$arg] is a directory\n"
                # Check file is readable
                if [ -r "$arg" ]; then
                    printf "Directory [$arg] is readable\n"
                else
                    text=$(printf "Directory [$arg] is not readable\n")
                    red
                    printf "$text\n"
                fi
                # Check file is writable
                if [ -w "$arg" ]; then
                    printf "Directory [$arg] is writable\n"
                else
                    text=$(printf "Directory [$arg] is not writable\n")
                    red
                    printf "$text\n"
                fi
            else
                text=$(printf "Path [$arg] is not a regular, character, block, link, socket file nor is it a directory\n")
                red
                printf "$text\n"
            fi
        else
            text=$(printf "Path [$arg] does not exist\n")
            red
            printf "$text\n"
        fi
    else
        text=$(printf "[${arg^^}] is not a valid path\n")
        red
        printf "$text\n"
    fi
    gracefulExit
}

lib-export() {
    export -f checkPath
}
