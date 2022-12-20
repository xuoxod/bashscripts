#!/bin/bash

DIALOG=${DIALOG=gdialog}

clearVars() {
 unset $@
}

gracefulExit() {
 clearVars
 exit 0
}

usage() {
 green "Usage: " `cyan "question <QuotedText>"`
 gracefulExit
}

trap "gracefulExit" INT PWR QUIT TERM

if [[ $# -gt 1 ]];
then
    red "Error: " `white "Too many arguments"`
    usage    
elif [[ $# -lt 1 ]] || [[ $1 == $str ]];
then
    red "Error: " `white "Missing argument"`
    usage
else
    $DIALOG --title "Question" --yesno "${1}" 58 81 --clear
    case $? in
     0) echo "yes">ans.txt;;

     1) echo "no">ans.txt;;
    esac
    gracefulExit
fi


