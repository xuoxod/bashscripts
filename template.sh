#!/usr/bin/env bash
# Template script demonstrating getopts and color usage.

# Add standard safety options
set -e
set -u
set -o pipefail

# Source the chosen color library relative to the script location
# shellcheck source=./colortext.sh
source "$(dirname "$0")/colortext.sh"

# --- Variables ---
# Define script-specific variables here if needed

# --- Functions ---

clearVars() {
    # Unset any global variables specific to this script
    unset text # For colortext.sh
}

gracefulExit() {
    clearVars
    exit 0
}

# No exitProg needed if it just calls gracefulExit

synopsis() {
    # Use a mix of the color tool (for orange) and the library (for white)
    local syn_part1 syn_part2 syn_part3 syn_part4
    syn_part1=$(color -o "Synopsis: ") # Use the command-line tool

    text="${0##*/}"; white; syn_part2="$text" # Use the library
    text=" <-aul?>"; white; syn_part3="$text" # Use the library
    text=" <argument>"; white; syn_part4="$text" # Use the library

    printf "\n%s%s%s%s\n" "$syn_part1" "$syn_part2" "$syn_part3" "$syn_part4" >&2

    local opt_part1 opt_part2 opt_part3 opt_part4 opt_part5
    opt_part1=$(color -o "Options: ") # Use the command-line tool

    text="?:\tPrints this message"; white; opt_part2="$text" # Use the library
    text="a:\tAdd user account to the sudo group"; white; opt_part3="$text" # Use the library
    text="l:\tLock user acount"; white; opt_part4="$text" # Use the library
    text="u:\tUnlock user accunt"; white; opt_part5="$text" # Use the library

    printf "%s\n\t%s\n\t%s\n\t%s\n\t%s\n" "$opt_part1" "$opt_part2" "$opt_part3" "$opt_part4" "$opt_part5" >&2
    gracefulExit # Exit after showing help
}

# --- Main Logic ---

trap "gracefulExit" INT TERM QUIT

# Check if no arguments were provided
if [[ $# -eq 0 ]]; then
    synopsis
fi

# --- Argument Parsing ---
while getopts ':?l:u:a:' OPTION; do
    case ${OPTION} in
    a)
        printf "'%s' parameter provided with argument: %s\n" "${OPTION}" "$OPTARG"
        # Add logic for option 'a' here
        ;;

    l)
        printf "'%s' parameter provided with argument: %s\n" "${OPTION}" "$OPTARG"
        # Add logic for option 'l' here
        ;;

    u)
        printf "'%s' parameter provided with argument: %s\n" "${OPTION}" "$OPTARG"
        # Add logic for option 'u' here
        ;;

    \?)
        synopsis # Show help for invalid option
        ;;
    :)
        # Handle missing arguments for options that require them
        printf "Error: Option '-%s' requires an argument.\n" "$OPTARG" >&2
        synopsis # Show help
        ;;
     *)
        # Should not happen with leading ':' in getopts string
        printf "Error: Unexpected error parsing option '%s'.\n" "$OPTION" >&2
        synopsis # Show help
        ;;
    esac
done

# Shift away processed options and their arguments
shift "$((OPTIND - 1))"

# Handle any remaining non-option arguments if needed
if [[ $# -gt 0 ]]; then
    printf "Remaining arguments: %s\n" "$@"
    # Add logic for non-option arguments here
fi

# --- End of Script ---
printf "Template script finished.\n"
gracefulExit
