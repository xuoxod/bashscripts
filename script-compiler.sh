#! /bin/bash
if [ -d "$HOME/bin" ];
then
    cd "$HOME/bin"
    rm ./**
    shc -o ~/bin/blink -f ./blink.sh ;shc -o ~/bin/chromepwds -f ./chromepwds.sh ;shc -o ~/bin/clean -f ./clean.sh ;shc -o ~/bin/clearcache -f ./clearcache.sh ;shc -o ~/bin/clearentriescache -f ./clearentriescache.sh ;shc -o ~/bin/clearpagecache -f ./clearpagecache.sh ;shc -o ~/bin/color -f ./color.sh ;shc -o ~/bin/message -f ./message.sh ;shc -o ~/bin/mua -f ./mua.sh ;shc -o ~/bin/netface -f ./netface.sh ;shc -o ~/bin/nfy -f ./nfy.sh ;shc -o ~/bin/pcr -f ./pcr.sh ;shc -o ~/bin/prog -f ./prog ;shc -o ~/bin/whatsmyip4address -f ./whatsmyip4address.sh ;shc -o ~/bin/whatsmyip6address -f ./whatsmyip6address.sh
    exit 0
fi
