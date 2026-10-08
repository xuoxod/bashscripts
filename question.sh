#!/usr/bin/env bash
# Asks a yes/no question using a dialog tool (gdialog/zenity)

# DIALOG variable can be overridden externally
DIALOG=${DIALOG=gdialog} # Consider zenity as a more common default?

# Source the chosen color library relative to the script location
# shellcheck source=./colortext.sh
source "$(dirname "$0")/colortext.sh"

clearVars() {
 unset text # Only 'text' is used globally by colortext.sh
}

gracefulExit() {
 clearVars
 exit 0
}

# Helper to print messages using colortext.sh style to stderr
print_error() {
    local color_func="$1"
    shift
    text="$*" # Set the global 'text' variable
    "$color_func" # Call the color function
    printf "%s\n" "$text" >&2 # Print the modified 'text' variable to stderr
}

usage() {
    # Build usage message piece by piece
    text="Usage: "; green; local usage_part="$text"
    text="${0##*/}"; cyan; local script_name_part="$text"
    text=" \"Quoted Question Text\""; white; local args_part="$text"

    printf "%s%s%s\n" "$usage_part" "$script_name_part" "$args_part" >&2
    gracefulExit
}

trap "gracefulExit" INT PWR QUIT TERM

# Check dialog command exists
if ! command -v "$DIALOG" > /dev/null; then
    print_error red "Error: Dialog command '$DIALOG' not found."
    exit 1
fi


if [[ $# -gt 1 ]]; then
    print_error red "Error: Too many arguments"
    usage
elif [[ $# -lt 1 ]] || [[ -z "$1" ]]; then # Check for empty string too
    print_error red "Error: Missing argument"
    usage
else
    # Use the specified dialog tool
    # Note: Options might vary slightly between gdialog and zenity
    # These options look more like zenity options.
    "$DIALOG" --question \
              --title="Question" \
              --text="${1}" \
              --width=400 \
              --height=100 # Adjusted size slightly

    response=$?
    # Create or overwrite ans.txt in the current directory
    case $response in
     0) echo "yes" > ans.txt ;; # Yes
     1) echo "no"  > ans.txt ;; # No
     *) echo "error" > ans.txt ;; # Closed dialog or other error
    esac
    gracefulExit
fi
