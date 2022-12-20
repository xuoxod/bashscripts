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

usage() {
    echo -e "\033[1;97mUsage: \033[0m" $(echo -e '\033[1;94mcolor <option> <"Quoted  Text">\033[0m')
    # For using one of the 256 colors on the foreground (text color), the control sequence is “<Esc>[38;5;ColorNumberm”
    #  where ColorNumber is one of the following colors:
    # For using one of the 256 colors on the background, the control sequence is “<Esc>[48;5;ColorNumberm”
    # where ColorNumber is one of the following colors:

    echo -e "\e[38;5;149mOptions:"
    echo -e "\t\e[97mB: \e[38;5;234m Black"
    echo -e "\t\e[38;5;224mb: \e[38;5;39m Blue"
    echo -e "\t\e[38;5;224mc: \e[38;5;87m Cyan"
    echo -e "\t\e[38;5;224mg: \e[38;5;119m Green"
    echo -e "\t\e[38;5;224mm: \e[38;5;200m Magenta"
    echo -e "\t\e[38;5;224mo: \e[38;5;208m Orange"
    echo -e "\t\e[38;5;224mP: \e[38;5;211m Pink"
    echo -e "\t\e[38;5;224mp: \e[38;5;129m Purple"
    echo -e "\t\e[38;5;224mr: \e[38;5;196m Red"
    echo -e "\t\e[38;5;224mw: \e[38;5;224m White"
    echo -e "\t\e[38;5;224mx: \e[38;5;224m Range from 1 to 255"
    echo -e "\t\e[38;5;224my: \e[38;5;226m Yellow"
}

synopsis() {
    echo -e "\e[38;5;209m\n\t\tColor Usage Detail\e[m"
    color -w "Synopsis: color <-BbcgmoPprwxy> <'Quoted Text'> [-h Display usage] [-? Display this information]"
    color -w 'By default, the color intensity is configured high'
    echo -e "\e[38;5;234m     Black = B\e[m"
    echo -e "\e[38;5;39m     Blue = b\e[m"
    echo -e "\e[38;5;87m     Cyan = c\e[m"
    echo -e "\e[38;5;119m     Green = g\e[m"
    echo -e "\e[38;5;200m     Magenta = m\e[m"
    echo -e "\e[38;5;208m     Orange = o\e[m"
    echo -e "\e[38;5;211m     Pink = P\e[m"
    echo -e "\e[38;5;129m     Purple = p\e[m"
    echo -e "\e[38;5;196m     Red = r\e[m"
    echo -e "\e[38;5;224m     Range from 1 to 255 = x\e[m"
    echo -e "\e[38;5;224m     White = w\e[m"
    echo -e "\e[38;5;226m     Yellow = y\e[m"
    printf "\n"
    gracefulExit
}

while getopts ':B:b:c:g:m:o:p:P:r:w:x:y:h' OPTION; do
    case "$OPTION" in
    B)
        # printf 'Option %s chosen\n' "${OPTION}"
        echo -e "\e[38;5;234m${OPTARG}\e[m"
        ;;

    b)
        # printf 'Option %s chosen\n' "${OPTION}"
        echo -e "\e[38;5;39m${OPTARG}\e[m"
        ;;

    c)
        # printf 'Option %s chosen\n' "${OPTION}"
        echo -e "\e[38;5;87m${OPTARG}\e[m"
        ;;

    g)
        # printf 'Option %s chosen\n' "${OPTION}"
        echo -e "\e[38;5;83m${OPTARG}\e[m"
        ;;

    h)
        usage
        ;;

    m)
        # printf 'Option %s chosen\n' "${OPTION}"
        echo -e "\e[38;5;200m${OPTARG}\e[m"
        ;;

    o)
        echo -e "\e[38;5;208m${OPTARG}\e[m"
        ;;

    p)
        # printf 'Option %s chosen\n' "${OPTION}"
        echo -e "\e[38;5;170m${OPTARG}\e[m"
        ;;

    P)
        # printf 'Option %s chosen\n' "${OPTION}"
        echo -e "\e[38;5;211m${OPTARG}\e[m"
        ;;

    r)
        # printf 'Option %s chosen\n' "${OPTION}"
        echo -e "\e[38;5;196m${OPTARG}\e[m"
        ;;

    w)
        # printf 'Option %s chosen\n' "${OPTION}"
        echo -e "\e[38;5;224m${OPTARG}\e[m"
        ;;

    x)
        # Color given text with given color code
        # 2nd param = color code
        # 3rd param = text or quoted text with spaces
        if [[ $# -ne 3 ]]; then
            printf 'Option %s requires two arguments.\n' "${1}"
            nfy "Option ${1} requires two arguments.\n"
            usage
            exit 2
        else
            echo -e "\e[38;5;${OPTARG}m${3}\e[m"
        fi
        ;;

    y)
        # printf 'Option %s chosen\n' "${OPTION}"
        echo -e "\e[38;5;226m${OPTARG}\e[m"
        ;;

    \?)
        synopsis
        ;;

    :)
        if [[ ${OPTARG} == "x" ]]; then
            printf 'Option %s requires two arguments.\n' "-${OPTARG}"
            usage
        else
            printf 'Option %s requires an argument.\n' "-$OPTARG"
            usage
        fi
        exit 1
        ;;
    esac
done
shift "$(($OPTIND - 1))"
