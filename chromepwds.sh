#!/bin/bash
declare -r SRC="$HOME/Documents/information/chromepasswords/"
declare -r SRC_DEFAULT="$HOME/Documents/information/chromepasswords/ChromePasswords_.csv"

clearVars() {
    unset count res TERM FILE_NAME FILE_PATH
}

gracefulExit() {
    clearVars
    exit 0
}

cleanExit() {
    clearVars
    exit 0
}

exitProg() {
    clearVars
    exit 121
}

synopsis() {
    clear
    local count
    count="$(find ~/Documents/information/chromepasswords/ -type f -iname "*.csv" | sed -n "$=")"
    printf "\n%s%s\n\n" "$(color -x 179 "${0}")" "$(color -w " lives at $HOME/bin")"
    printf "%s\n\t%s\n\t%s\n\t%s\n\n" \
        "$(color -x 167 "Synopsis:")" \
        "$(color -w "${0} <c> <1-$count> <search-term>")" \
        "$(color -w "${0} <o> <search-term>")" \
        "$(color -w "${0} <?l>")"
    printf "%s\n" "$(color -x 167 "Examples:")"
    printf "\t%s\n" "$(color -w "${0} -?\tPrints this help")"
    printf "\t%s\n" "$(color -w "${0} -l\tPrints home directory of the source files and lists them")"
    printf "\t%s\n" "$(color -w "${0} -c\t<1-$count> google")"
    printf "\t%s\n" "$(color -w "${0} -o\tgoogle")"
    cleanExit
}

trap "gracefulExit" INT TERM QUIT PWR

while getopts ':?lc:o:' OPTION; do
    case ${OPTION} in
    l)
        # list all CSV files in the $SRC directory
        printf "\nThe CSV files live at: %s\n" "$SRC"
        ls -sh "$HOME/Documents/information/chromepasswords/"
        cleanExit
        ;;

    o)
        # Search term within the latest CSV file
        # 2nd param = search term
        if [[ $# -lt 2 ]]; then
            exitProg
        else
            TERM=$2
            # printf '\tSearch Term: %s\n' ${TERM^^}
            res=$(sed -n '2,$p' "$SRC_DEFAULT" | grep -E "\b($TERM)\b" | awk '{gsub(/[ \t]/,",");print}' | awk -F ',' '{print "URL:",$1, " Username:",$2, " Password:", $3;}')

            if [ -n "$res" ]; then
                printf '\tSearch Term: %s\n' "${TERM^^}"
                printf '%s\n' "${res}"
            fi
        fi
        cleanExit
        ;;

    c)
        # Search term within given CSV file
        # 2nd param = file name last character e.g. (0 - N and _)
        # 3rd param = search term
        if [[ $# -eq 3 ]]; then
            FILE_NAME="ChromePasswords${2}.csv"
            FILE_PATH="$SRC$FILE_NAME"
            TERM=$3
            # printf 'parameters: %s %s\nfile name: %s\nfile path: %s\n' $2, $3, $FILE_NAME, $FILE_PATH
            # ls -lhmnogs $FILE_PATH

            res=$(sed -n '2,$p' "$FILE_PATH" | grep -E "\b($TERM)\b" | awk '{gsub(/[ \t]/,",");print}' | awk -F ',' '{print "URL:",$1, " Username:",$2, " Password:", $3;}')
            if [[ -n "$res" ]]; then
                printf '\tSearch Term: %s\n' "${TERM^^}"
                printf '%s\n' "${res}"
                exitProg
            else
                exitProg
            fi
        else
            exitProg
        fi
        cleanExit
        ;;

    :)
        exitProg
        ;;

    \?)
        synopsis
        ;;
    esac
done
shift "$(($OPTIND - 1))"

if [ $# -gt 0 ]; then
    unset "$@"
fi
