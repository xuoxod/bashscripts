#!/bin/bash
# set -e
# set -u
set -o pipefail
DIALOG=${DIALOG=zenity}

function customMessage() {
    n1=$1
    n2=$2
    w1=$3
    m=$(echo -e "\033[38;$n1;$n2m${w1} \e[m")
}

function clearVars() {
    unset $@
}

function gracefulExit() {
    clearVars
    exit 0
}

function usage() {
    usage=$(echo -e "\e[38;5;83mUsage Example:\e[m")
    example1=$(echo -e "\e[38;5;224m${0} ${arg1} <File Path> <Search Word>\e[m")

    printf "${usage}\n"
    printf "\t${example1}\n"
}

function missingArgErr() {
    a1=$OPTARG
    header="Error: "
    body="option $a1 expects a file path argument"
    mHeader=$(echo -e "\e[38;5;196m${header}\e[m")
    mBody=$(echo -e "\e[38;5;224m${body}\e[m")

    eMsg="${mHeader^}${mBody,,}"
    printf "${eMsg}\n"
    gracefulExit
}

function missingFullArgErr() {
    a1=${opt1}
    header="Error: "
    body="option $a1 expects file path and search word arguments respectively"
    mHeader=$(echo -e "\e[38;5;196m${header}\e[m")
    mBody=$(echo -e "\e[38;5;224m${body}\e[m")

    eMsg="${mHeader^}${mBody,,}"
    printf "${eMsg}\n"

    usage
    gracefulExit
}

function fileExistErr() {
    a1=$OPTARG
    header="Error: "
    body="file $a1 does not exist"
    mHeader=$(echo -e "\e[38;5;196m${header}\e[m")
    mBody=$(echo -e "\e[38;5;224m${body}\e[m")

    eMsg="${mHeader^}${mBody,,}"
    printf "${eMsg}\n"
    gracefulExit
}

function notAFileErr() {
    a1=$OPTARG
    header="Error: "
    body="path $a1 is not file"
    mHeader=$(echo -e "\e[38;5;196m${header}\e[m")
    mBody=$(echo -e "\e[38;5;224m${body}\e[m")

    eMsg="${mHeader^}${mBody,,}"
    printf "${eMsg}\n"
    gracefulExit
}

function fileTypeErr() {
    header="Error: "
    body="Expecting a csv file but received a .${fileext} file"
    mHeader=$(echo -e "\e[38;5;196m${header}\e[m")
    mBody=$(echo -e "\e[38;5;224m${body}\e[m")

    eMsg="${mHeader^}${mBody,,}"
    printf "${eMsg}\n"
    gracefulExit
}

function notReadableErr() {
    a1=$OPTARG
    header="Error: "
    body="file $a1 is not readable"
    mHeader=$(echo -e "\e[38;5;196m${header}\e[m")
    mBody=$(echo -e "\e[38;5;224m${body}\e[m")

    eMsg="${mHeader^}${mBody,,}"
    printf "${eMsg}\n"
    gracefulExit
}

function noOptionErr() {
    a1=${OPTARG}
    header="Error: "
    body="Option $a1 is not available"
    mHeader=$(echo -e "\e[38;5;196m${header}\e[m")
    mBody=$(echo -e "\e[38;5;224m${body}\e[m")

    eMsg="${mHeader^}${mBody,,}"
    printf "${eMsg}\n"
    gracefulExit
}

function colorOptargWhite() {
    OPTARG=$(echo -e "\e[38;5;224m${OPTARG}\e[m")
}

function colorTextWhite() {
    TEXT=$(echo -e "\e[38;5;224m${TEXT}\e[m")
}

trap "gracefulExit" INT TERM QUIT PWR STOP KILL

while getopts ':hs:' OPTION; do
    case "${OPTION}" in
    s)
        if [[ $# -ne 3 ]]; then
            opt1=${1}
            missingFullArgErr
        elif [[ $OPTARG = $str ]]; then
            missingArgErr
        else
            filePath=$OPTARG

            if [[ ! -e $filePath ]]; then
                fileExistErr
            elif [[ ! -f $filePath ]]; then
                notAFileErr
            elif [[ ! -r $filePath ]]; then
                notReadableErr
            else
                filepath=${2}
                filename=$(basename $filepath)
                fileext=${filename#*.}

                if [[ "$fileext" != "csv" ]]; then
                    fileTypeErr
                fi

                searchword=${3}
                declare -a found

                TEXT="File Path: ${OPTARG}\nFile Name: ${filename}\nFile Ext: ${fileext}\nSearch file ${filename} for ${searchword}"
                colorTextWhite
                printf "${TEXT}\n\nSearching ...\n\n"

                for line in $(cat $filepath); do
                    if [[ $line =~ "$searchword" ]]; then
                        readarray -d "," newarr <<<$line
                        count=${#newarr[@]}
                        if [[ count -eq 3 ]]; then
                            username=$(echo ${newarr[1]} | awk -F "," '{printf $1}')
                            url=$(echo ${newarr[0]} | awk -F "," '{printf $1}')
                            password=$(echo -e ${newarr[2]} | awk -F "," '{printf $1}')

                            echo "URL: ${url,,}"
                            echo "Username: ${username,,}"
                            echo "Password: ${password}"
                            printf "\n\n"
                        fi
                    fi
                done
            fi
        fi
        ;;

    h)
        usage
        ;;

    ?)
        noOptionErr
        ;;
    esac
done
shift "$(($OPTIND - 1))"
