#!/bin/bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Set variables before using them
set -o pipefail # Prevent pipeline errors from being masked
# set -x Prints command to the console

gracefulExit() {
    exit 0
}

exitProg() {
    gracefulExit
}

# Function to print the date and greet the user
start() {
    # Get the current date in full day, month, and year format
    current_date=$(date +"%A, %B %d, %Y")

    # Get the current hour
    hour=$(date +'%-H')

    # Determine the appropriate greeting based on the time of day
    if [[ ${hour} -ge 0 ]] && [[ ${hour} -lt 12 ]]; then
        greeting="Good morning"
    elif [[ ${hour} -ge 12 ]] && [[ ${hour} -lt 18 ]]; then
        greeting="Good afternoon"
    else
        greeting="Good evening"
    fi

    # Get the current username
    username=$(whoami)

    line="${greeting} ${username^}!"

    # Print the date and greeting
    printf "%45s\n\n" "${line}"
    echo "Today is: ${current_date}"
}
trap "gracefulExit" INT TERM QUIT PWR

# Continuously prompt the user for input
while true; do
    read -rp "Press Enter to continue, or type 'x', 'q', 'exit', or 'quit' to exit: " response

    # Check the user's response
    case "${response}" in
    x | q | exit | quit)
        echo "Exiting..."
        exit 0
        ;;
    *)
        clear
        start
        ;;
    esac
done
