#!/usr/bin/env bash

set -e
set -u
set -o pipefail
# set -x
source colortext.sh

clearVars() {
    unset text filebase filename suffix dirPath
}

gracefulExit() {
    clearVars
    exit 0
}

createNewBackup() {
    printf "How many $dirPath backups? $i\n"
    i=$(echo $(($i + 1)))
    newbackup="$parentPath/$filename-bak$i"
    printf "Add another backup $newbackup\n"
    gracefulExit
}

trap "gracefulExit" INT PWR QUIT TERM

case $# in
1)
    dirPath="$1"
    if [ -e "$dirPath" ] && [ -r "$dirPath" ] && [ -d "$dirPath" ]; then
        parentPath="$(dirname "$dirPath")"
        i=0

        for file in $(ls "$parentPath"); do
            filebase=$(basename "$file")
            filename=${filebase%-*}
            suffix=${filebase##*-}
            fullpath="$parentPath/$filebase"

            if [ -d "$fullpath" ]; then
                if [[ "$suffix" =~ bak([0-9]+)? ]]; then
                    i=$(echo $(($i + 1)))
                    printf "Original: $dirPath\n"
                    printf "Backup: $fullpath\n"
                    #            printf "File Name: $filename\n"
                    #            printf "Full Path: $fullpath\n"
                    printf "Parent: $parentPath\n\n"
                fi
            fi
        done
        createNewBackup
    else
        text="No such directory"
        white
        printf "$text\n"
        text="$dirPath"
        blink
        printf "$text\n"
    fi
    ;;
esac
