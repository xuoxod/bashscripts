#!/usr/bin/env bash
# Uses figlet to create banner text, optionally writing to /etc/motd

set -e
set -u
set -o pipefail # Added for safety

# Source the chosen color library relative to the script location
# shellcheck source=./colortext.sh
source "$(dirname "$0")/colortext.sh"

clearVars() {
    # Removed unused variables from unset
    unset text filepath filebase filename extension icolor
}

gracefulExit() {
    clearVars
    exit 0
}

usage() {
    # Use printf directly for usage message
    printf "Usage:\n" >&2
    printf "  %s \"Quoted Text\"\n" "${0##*/}" >&2
    printf "  %s \"Quoted Text\" <Path to banner file>\n" "${0##*/}" >&2
    gracefulExit
}

# Helper to print error messages using colortext.sh style
print_error() {
    text="$*" red # Set global text, call red()
    printf "%s\n" "$text" >&2 # Print the colored text to stderr
}

trap "gracefulExit" INT PWR QUIT TERM

case $# in
1)
    input_text=$1
    if [ -z "$input_text" ]; then
        print_error "Argument is empty"
        usage
    else
        # Use figlet to format the text
        # Note: figlet might not be installed by default
        if command -v figlet > /dev/null; then
            text=$(figlet -cptW "$input_text")
            # Apply blue color using colortext.sh
            blue # Modifies the global 'text' variable
            printf "%s\n" "$text" # Print the colored text
        else
            # Fallback if figlet is not available
            text="$input_text"
            blue
            printf "%s\n" "$text"
            print_error "(Warning: figlet command not found, using plain text)"
        fi
    fi
    ;;

2)
    input_text=$1
    filepath=$2
    if [ -z "$input_text" ]; then
        print_error "The message is empty"
        usage
    elif [ ! -e "$filepath" ]; then
        print_error "$filepath does not exist"
        usage
    elif [ ! -f "$filepath" ]; then
        print_error "$filepath is not a file"
        usage
    elif [ ! -w "$filepath" ]; then
        # Check if we are root, maybe we can write anyway?
        # This is a simple check, might need more robust permission handling
        if [[ "$(id -u)" -ne 0 ]]; then
             print_error "$filepath is not writable (and not running as root)"
             usage
        fi
        # If root, proceed cautiously
        printf "Warning: %s may not be writable by user, attempting as root.\n" "$filepath" >&2

    fi

    # Validate filename and path (optional but kept from original)
    filebase=$(basename "$filepath")
    filename=${filebase%.*}
    # extension=${filebase##*.} # Extension wasn't used

    if [ "$filename" != "motd" ]; then
        print_error "Must write to the motd file"
        usage
    elif [ "$filepath" != "/etc/motd" ]; then
        print_error "This program will only write to a writable /etc/motd file"
        usage
    fi

    # Generate text with figlet (check if installed)
    if command -v figlet > /dev/null; then
         text=$(figlet -cptW "$input_text")
         blue # Apply blue color to the global 'text' variable
         # Write the colored text to the file (requires appropriate permissions)
         printf "%s\n" "$text" > "$filepath"
         printf "Banner written to %s\n" "$filepath"
    else
        # Fallback if figlet is not available
        text="$input_text"
        blue
        printf "%s\n" "$text" > "$filepath"
        printf "Plain text written to %s\n" "$filepath"
        print_error "(Warning: figlet command not found, using plain text)"
    fi
    ;;

*)
    usage
    ;;
esac
gracefulExit
