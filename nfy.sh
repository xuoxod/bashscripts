#!/bin/sh

DIALOG=${DIALOG=zenity}

# ${DIALOG} --notification \
# --window-icon="info" \
# --text=$1

if [ $# -gt 0 ];
then
    line=""
    for p in $@
    do
        line="${line}${p} "
    done
    # printf '%s ' ${line}
    ${DIALOG} --notification \
    --window-icon="info" \
    --text="${line}"
fi