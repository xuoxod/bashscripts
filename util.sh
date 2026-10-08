#!/usr/bin/env bash
# Basic utility script - echoes input arguments with color.

set -e
set -u
set -o pipefail # Added for safety

# Source the chosen color library relative to the script location
# shellcheck source=./colortext.sh
source "$(dirname "$0")/colortext.sh"

clearVars() {
    # Removed unused variables
    unset userInput text1 text2 text3 msg icolor text
}

gracefulExit() {
    clearVars
    exit 0
}

usage() {
    # Use printf directly for usage message
    printf "Usage: %s <arg1> [arg2] [arg3]\n" "${0##*/}" >&2
    gracefulExit
}

# Helper to print messages using colortext.sh style
print_message() {
    local color_func="$1"
    shift
    text="$*" # Set the global 'text' variable
    "$color_func" # Call the color function (e.g., red, blue, white)
    printf "%s\n" "$text" # Print the modified 'text' variable
}

trap "gracefulExit" INT PWR QUIT TERM

case $# in
1)
    userInput=$1
    if [ -z "$userInput" ]; then
        print_message white "Argument is empty" # Use helper
        usage
    else
        icolor="39" # Blue color code for custom
        msg="You entered:"
        text="$msg $userInput"
        custom # Apply custom color to global 'text'
        printf "%s\n" "$text" # Print the result
    fi
    ;;

2)
    text1=$1
    text2=$2

    if [ -z "$text1" ]; then
        print_message white "Argument 1 is empty"
        usage
    elif [ -z "$text2" ]; then
        print_message white "Argument 2 is empty"
        usage
    else
        msg="You entered:"
        print_message orange "$msg $text1 $text2" # Use helper
    fi
    ;;

3)
    text1=$1
    text2=$2
    text3=$3

    if [ -z "$text1" ]; then
        print_message white "Argument 1 is empty"
        usage
    elif [ -z "$text2" ]; then
        print_message white "Argument 2 is empty"
        usage
    elif [ -z "$text3" ]; then
        print_message white "Argument 3 is empty"
        usage
    else
        msg="You entered:"
        print_message orange "$msg $text1 $text2 $text3" # Use helper
    fi
    ;;

*)
    usage
    ;;
esac
gracefulExit
