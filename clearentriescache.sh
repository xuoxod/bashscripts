#!/bin/bash
sync
echo 2 >/proc/sys/vm/drop_caches
if [[ -n $? ]]; then
    printf 'error code: %s\n' "$?"
    exit 0
else
    exit 0
fi
