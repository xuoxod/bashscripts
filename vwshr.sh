#!/bin/bash

clearVars() {
    unset HOST USER
}

gracefulExit() {
    clearVars
    exit 0
}

synopsis() {
    printf "\n%s\n%s\n\n" \
        "$(color -P "View objects shared by host")" \
        "$(color -w "Synopsis: vwshrs <Hostname|IP> <Username>")"
}

usage() {
    color -w "Usage: $(color -o "vwshr <HostnameOrIP> <UserName>")"
}

# smbclient -L $HOST -U $USER
trap "gracefulExit" INT TERM PWR QUIT

case $# in
0)
    synopsis
    ;;

2)
    if [ -z "$(which smbclient)" ]; then
        printf "%s\n" "$(color -w "Missing the Samba package")"
    else
        HOST="$1"
        USER="$2"
        smbclient -L "$HOST" -U "$USER"
        if [[ -n $? ]]; then
            usage
        else
            gracefulExit
        fi
    fi
    ;;

*)
    usage
    ;;
esac
