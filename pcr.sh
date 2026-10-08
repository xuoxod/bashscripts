#!/usr/bin/bash
declare -r PROG="Print Color Range"
declare -r DESC="Prints sentences vertically in the color matching that color range"

# for N in {1..255};do color -x $N "Color value is $N!";done

synopsis() {
    printf "\n\t%s" "$(color -w "${PROG}")"
    printf "\n%s" "$(color -x 226 "${DESC}")"
    printf "\n%s\n" "$(color -x 178 "Synopsis: ${0} <?hv>")"
    printf "\nParameters:\n\t%s\n\t%s\n\t%s\n\n" \
        "$(color -w "?:\tPrints this message")" \
        "$(color -w "h:\tPrints color range horizontally")" \
        "$(color -w "v:\tPrints color range vertically")"
    exit 0
}

printRangeVertically() {
    for N in {1..255}; do
        line="$(color -x "$N" "Color value is $N!")"
        printf "\t%s\n" "$line"
    done
    exit 0
}

printRangeHorizontally() {
    for N in {1..255}; do
        line="$(color -x "$N" "Color $N!")"
        printf "%s\t" "$line"
    done
    printf "\n\n"
    exit 0
}

trap "gracefulExit" INT TERM QUIT PWR

while getopts ':?hv' OPTION; do
    case ${OPTION} in
    v)
        printRangeVertically
        ;;

    h)
        printRangeHorizontally
        ;;

    \?)
        synopsis
        ;;
    esac
done
shift "$(($OPTIND - 1))"
