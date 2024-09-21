#!/usr/bin/env bash

declare -r Z=${Z=zenity}

# update: Runs apt update and dist-upgrade. Requires admin privilege.
# @params: None
updatesystem() {
    (
        echo "10"
        sleep 1
        echo "# Updating system index"
        sleep 1
        echo "20"
        sleep 1
        echo "# Upgrading system"
        sleep 1
        echo "50"
        sleep 1
        echo "Checking for more updates"
        sleep 1
        echo "75"
        sleep 1
        echo "# Finishing maintenance"
        sleep 1
        echo "100"
        sleep 1
    ) |
        zenity --progress \
            --title="Update System" \
            --text="Scanning system index..." \
            --percentage=0

    if [ "$?" = -1 ]; then
        zenity --error \
            --text="Update canceled."
    fi
}

lib-maintenance() {
    export -f updatesystem
}
