#!/bin/bash

DIALOG=${DIALOG=gdialog}

$DIALOG --title "Question" --yesno "${1}" 58 81 --clear
    case $? in
     0) echo "yes">question-answer.txt;;

     1) echo "no">question-answer.txt;;
    esac


