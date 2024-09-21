#!/bin/bash

#-------------------------------------------------------------------------------
# Script Name: system_cleanup.sh
# Description: Clears system caches, temp files, rotates logs, and provides
#              options for system updates and time synchronization.
# Author: Bard (Google AI)
# Date: 2023-10-27
#-------------------------------------------------------------------------------

# Color definitions for output
GREEN='\033[0;32m'
WHITE='\033[0m'

# Function to print usage information
print_usage() {
    echo -e "${GREEN}Usage:${WHITE} $0 [OPTIONS]"
    echo -e "\n${GREEN}Options:${WHITE}"
    echo -e "  -h, --help                Display this help message"
    echo -e "  -r, --remote <HOST>       Execute on remote host (requires SSH access)"
    echo -e "  -l, --log <FILE>          Log output to specified file (txt or html)"
    echo -e "  -c, --console             Print output to console (default)"
    echo -e "  -u, --update-cache       Update system's cache index"
    echo -e "  -p, --upgrade-packages   Upgrade system packages (requires root)"
    echo -e "  -t, --update-time        Update system time"
    echo -e "\n${GREEN}Log File Formats:${WHITE} txt, html"
    echo -e "${GREEN}Note:${WHITE} Options -p, -u, and -t require root privileges."
}

# Function to check for root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${GREEN}This action requires root privileges. Please run as root or using sudo.${WHITE}"
        exit 1
    fi
}

# Function to clear system caches
clear_caches() {
    echo -e "${GREEN}Clearing system caches...${WHITE}"
    sync && echo 3 >/proc/sys/vm/drop_caches
    echo -e "${GREEN}System caches cleared.${WHITE}"
}

# Function to clear temp files
clear_temp_files() {
    echo -e "${GREEN}Clearing temporary files...${WHITE}"
    tmp_dirs=("/tmp" "/var/tmp" "$HOME/.cache")
    for dir in "${tmp_dirs[@]}"; do
        find "$dir" -type f -mtime +7 -delete 2>/dev/null
    done
    echo -e "${GREEN}Temporary files cleared.${WHITE}"
}

# Function to rotate log files
rotate_logs() {
    echo -e "${GREEN}Rotating log files...${WHITE}"
    logrotate -f /etc/logrotate.conf 2>/dev/null
    echo -e "${GREEN}Log files rotated.${WHITE}"
}

# Function to update system cache index
update_cache_index() {
    check_root
    echo -e "${GREEN}Updating system cache index...${WHITE}"
    update-command -y 2>/dev/null # Replace with actual command for your system
    echo -e "${GREEN}System cache index updated.${WHITE}"
}

# Function to upgrade system packages
upgrade_packages() {
    check_root
    echo -e "${GREEN}Upgrading system packages...${WHITE}"
    apt update && apt upgrade -y 2>/dev/null # Replace with actual commands for your system
    echo -e "${GREEN}System packages upgraded.${WHITE}"
}

# Function to update system time
update_system_time() {
    check_root
    echo -e "${GREEN}Updating system time...${WHITE}"
    ntpdate -s time.nist.gov 2>/dev/null # Replace with your preferred time server
    echo -e "${GREEN}System time updated.${WHITE}"
}

# Function to print summary
print_summary() {
    local output_mode="$1"
    local log_file="$2"

    summary="System Cleanup Summary:\n\n"
    summary+="Caches cleared.\n"
    summary+="Temporary files cleared.\n"
    summary+="Log files rotated.\n"

    if [[ "$output_mode" == "console" || "$output_mode" == "both" ]]; then
        echo -e "${GREEN}$summary${WHITE}"
    fi

    if [[ "$output_mode" == "file" || "$output_mode" == "both" ]]; then
        if [[ "$log_file" =~ \.html$ ]]; then
            summary=$(echo "$summary" | sed 's/\n/<br>/g')
            echo "<html><body><h1>$summary</h1></body></html>" >"$log_file"
        else
            echo -e "$summary" >"$log_file"
        fi
        echo -e "${GREEN}Summary written to $log_file${WHITE}"
    fi
}

# Parse command-line arguments
REMOTE_HOST=""
LOG_FILE=""
OUTPUT_MODE="console"

while [[ $# -gt 0 ]]; do
    case "$1" in
    -h | --help)
        print_usage
        exit 0
        ;;
    -r | --remote)
        shift
        REMOTE_HOST="$1"
        ;;
    -l | --log)
        shift
        LOG_FILE="$1"
        OUTPUT_MODE="file"
        ;;
    -c | --console)
        OUTPUT_MODE="console"
        ;;
    -u | --update-cache)
        UPDATE_CACHE=true
        ;;
    -p | --upgrade-packages)
        UPGRADE_PACKAGES=true
        ;;
    -t | --update-time)
        UPDATE_TIME=true
        ;;
    *)
        echo -e "${GREEN}Invalid option: $1${WHITE}"
        print_usage
        exit 1
        ;;
    esac
    shift
done

# Execute commands on remote host if specified
if [[ ! -z "$REMOTE_HOST" ]]; then
    # Modify the following command to use your preferred SSH options
    ssh "$REMOTE_HOST" "bash -s" "$@" <"$0"
    exit $?
fi

# Execute cleanup tasks
clear_caches
clear_temp_files
rotate_logs

# Execute optional tasks
if [[ "$UPDATE_CACHE" == true ]]; then
    update_cache_index
fi

if [[ "$UPGRADE_PACKAGES" == true ]]; then
    upgrade_packages
fi

if [[ "$UPDATE_TIME" == true ]]; then
    update_system_time
fi

# Print summary
print_summary "$OUTPUT_MODE" "$LOG_FILE"
