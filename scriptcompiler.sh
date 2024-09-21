#!/usr/bin/env bash
source colortext-lib.sh
# if [ -d "$HOME/bin" ]; then
#     cd "$HOME/bin"
#     rm ./**
#     shc -o ~/bin/blink -f ./blink.sh
#     shc -o ~/bin/chromepwds -f ./chromepwds.sh
#     shc -o ~/bin/clean -f ./clean.sh
#     shc -o ~/bin/clearcache -f ./clearcache.sh
#     shc -o ~/bin/clearentriescache -f ./clearentriescache.sh
#     shc -o ~/bin/clearpagecache -f ./clearpagecache.sh
#     shc -o ~/bin/color -f ./color.sh
#     shc -o ~/bin/message -f ./message.sh
#     shc -o ~/bin/mua -f ./mua.sh
#     shc -o ~/bin/netface -f ./netface.sh
#     shc -o ~/bin/nfy -f ./nfy.sh
#     shc -o ~/bin/pcr -f ./pcr.sh
#     shc -o ~/bin/prog -f ./prog
#     shc -o ~/bin/whatsmyip4address -f ./whatsmyip4address.sh
#     shc -o ~/bin/whatsmyip6address -f ./whatsmyip6address.sh
#     exit 0
# fi

compileScript() {
    if [ -e "$HOME/bin" ] && [ -d "$HOME/bin" ] && [ -w "$HOME/bin" ]; then
        if [ -e "$1" ] && [ -f "$1" ] && [ -r "$1" ]; then
            filepath="$1"
            # filebase=$(basename -- "$filepath")
            # filename=${filebase%-*}
            # suffix=${filebase##*-}
            # fullpath="$filepath$filebase"
            # parentDir="$(dirname "$fullpath")"
            filename=${filepath%.*}
            suffix=${filepath##*.}
            filebase=$(basename -s ".$suffix" "$filepath")
            fullpath="$filepath$filebase"
            parentDir="$(dirname $fullpath)"
            if [ -n "$filename" ] && [ -n "$suffix" ] && [ "$suffix" = "sh" ]; then
                printf "filepath:\t$filepath\n"
                printf "filebase:\t$filebase\n"
                printf "filename:\t$filename\n"
                printf "suffix:\t$suffix\n"
                printf "parent dir:\t$parentDir\n"
                # shc -Uf "$filepath" -o "$HOME/bin/$filebase"
                shc -Uf "$filepath" -o "$HOME/bin/$filebase"
                text="\n\t\t  Compile the script here\n\n"
                white
                printf "$text"
            fi
        else
            err="File path '$1' does not exist or is not a valid script file"
            text="$err"
            white
            printf "$text\n"
        fi
    else
        err="Expected a 'bin' directory in your home directory but it does not exist"
        text="$err"
        white
        printf "$text\n"
    fi
}
