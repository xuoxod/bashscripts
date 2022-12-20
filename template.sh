#!/usr/bin/bash

gracefulExit() {
    exit 0
}

exitProg() {
    gracefulExit
}

synopsis() {
    printf "\n%s%s%s%s" "$(color -o "Synopsis: ")" "$(white "${0}")" " $(white "<-aul?>")" " $(white "<argument>")"
    printf "\n%s\n\t%s\n\t%s\n\t%s\n\t%s\n" "$(color -o "Options: ")" "$(color -w "?:\tPrints this message")" \
        "$(color -w "a:\tAdd user account to the sudo group")" \
        "$(color -w "l:\tLock user acount")" \
        "$(color -w "u:\tUnlock user accunt")"
}

trap "gracefulExit" INT TERM QUIT

while getopts ':?l:u:a:' OPTION; do
    case ${OPTION} in
    a)
        printf "%s parameter\n" "${OPTION}"
        printf "%d arguments\n\n" $#
        ;;

    l)
        printf "%s parameter\n" "${OPTION}"
        printf "%d arguments\n\n" $#
        ;;

    u)
        printf "%s parameter\n" "${OPTION}"
        printf "%d arguments\n\n" $#
        ;;

    \?)
        synopsis
        ;;
    esac
done
shift "$(($OPTIND - 1))"
