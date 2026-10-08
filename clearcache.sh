#!/bin/bash
sync
echo 3 >/proc/sys/vm/drop_caches
if [[ -n $? ]]; then
    printf 'Error code: %s\n' "$?"
    exit 0
else
    exit 0
fi
