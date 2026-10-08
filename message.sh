#!/usr/bin/bash
DIALOG=${DIALOG=zenity}
declare -r title="Attention"

gracefulExit() {
    exit 0
}

usage() {
    color -w "Usage: $(color -o "message <QuotedText>")"
}

trap "gracefulExit" INT PWR QUIT TERM

case $# in
1)
    $DIALOG --info \
        --title ${title^^} \
        --width 217 \
        --height 110 \
        --text "${1}" \
        --ellipsize \
        --icon-name=emblem-shared
    gracefulExit
    ;;

*)
    usage
    gracefulExit
    ;;
esac
