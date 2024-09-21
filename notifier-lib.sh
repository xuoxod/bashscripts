#!/usr/bin/env bash

declare -r DIALOG=${DIALOG=zenity}

# notify: creates a notification dialog
# @params text: the dialog message text. double quote text with spaces.
notify() {
    ${DIALOG} --notification --window-icon="info" --text="$1"
}

# progress: creates a progress dialog
# @params
progress() {
    (
        echo "10"
        sleep 1
        echo "# Updating mail logs"
        sleep 1
        echo "20"
        sleep 1
        echo "# Resetting cron jobs"
        sleep 1
        echo "50"
        sleep 1
        echo "This line will just be ignored"
        sleep 1
        echo "75"
        sleep 1
        echo "# Rebooting system"
        sleep 1
        echo "100"
        sleep 1
    ) |
        zenity --progress \
            --title="Update System Logs" \
            --text="Scanning mail logs..." \
            --percentage=0

    if [ "$?" = -1 ]; then
        zenity --error \
            --text="Update canceled."
    fi
}

lib-export() {
    export -f notify
    export -f progress
}
