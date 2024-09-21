#!/usr/bin/env bash

generatePronounceblePassword() {
    color -w '\n\tGenerating password ...\n'
    sleep 2
    apg -a 0 -M Sncl -m 17 -n 1 -E +\<\>\;:\|\\\^\'\",\.\={}*\-[]\`\~\)\(\/
    gracefulExit
}

generateNonpronounceblePassword() {
    color -w '\n\tGenerating password ...\n'
    sleep 2
    apg -a 1 -M Sncl -m 17 -n 1 -E +\<\>\;:\|\\\^\'\",\.\={}*\-[]\`\~\)\(\/
    gracefulExit
}

gpp() {
    generatePronounceblePassword
}

gnp() {
    generateNonpronounceblePassword
}

generatePassword() {
    mode="$1"
    case "$mode" in
    p)
        gpp
        ;;

    *)
        gnp
        ;;

    esac
}

lib-export() {
    export -f generatePassword
}
