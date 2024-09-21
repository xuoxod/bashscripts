#!/usr/bin/env bash

set -e
set -u
set -o pipefail
# set -x
source colortext.sh

clearVars() {
    unset parentDir filebase filename suffix fullpath howManyBackups dirExists dirName dirPath newBackup
}

gracefulExit() {
    clearVars
    exit 0
}

trap "gracefulExit" INT PWR QUIT TERM

case $# in
0)
    tem="/path/to/enlightenment/"
    tem2="/path/to/enlightenment"

    if [[ "$tem" =~ .*/$ ]]; then
        printf "Has trailing forward slash\n"
    else
        printf "No forward slash\n"
    fi

    if [[ "$tem2" =~ .*/$ ]]; then
        printf "Has trailing forward slash\n"
    else
        printf "No forward slash\n"
    fi

    ;;

2)
    dirPath="$1"
    dirName="$2"
    if [ -e "$dirPath" ] && [ -r "$dirPath" ] && [ -d "$dirPath" ]; then
        printf "Directory to check:\t$dirPath\n"
        printf "Checking for backups to:\t$dirName\n\n"
        howManyBackups=0
        dirExists=false

        for file in $(ls "$dirPath"); do
            filebase=$(basename "$file")
            filename=${filebase%-*}
            suffix=${filebase##*-}
            fullpath="$dirPath$filebase"
            parentDir="$(dirname "$fullpath")"

            if [ "$filename" = "$dirName" ]; then
                dirExists=true
                if [ "$suffix" != "$dirName" ]; then
                    if [[ "$suffix" =~ bak([0-9]+)? ]]; then
                        printf "\nFound $fullpath\n"
                        printf "Base $filebase\n"
                        printf "Name $filename\n"
                        printf "Suffix $suffix\n"
                        printf "Parent $parentDir\n"
                        printf -- '%.0s-' {1..55}
                        printf "\n"
                        howManyBackups=$(echo $(($howManyBackups + 1)))
                    fi
                fi
            fi
        done

        if [ "$dirExists" = true ]; then
            printf "\nHow many backups do $dirName have? $howManyBackups\n"

            if [[ "$dirPath" =~ .*/$ ]]; then
                printf ""
            else
                dirPath="$dirPath/"
            fi

            if [ "$howManyBackups" -eq 0 ]; then
                newBackup="$dirPath$dirName-bak"
                printf "Making new backup $newBackup\n"
            elif [ "$howManyBackups" -gt 0 ]; then
                howManyBackups=$(echo $(($howManyBackups + 1)))
                newBackup="$dirPath$dirName-bak$howManyBackups"
                printf "Adding new backup $newBackup\n"
            else
                gracefulExit
            fi
        else
            text="Directory $dirName does not exists"
            white
            printf "$text\n"
        fi
    else
        text="Directory $dirPath does not exists"
        white
        printf "$text\n"
    fi
    ;;
esac
