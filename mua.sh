#!/usr/bin/bash
<<COMMENT
    Administrative helper script use for:
        - Adding user to sudo group
        - Adding user to given group
        - Removing user from sudo group
        - Listing user's group(s)
        - Locking user account
        - Unlocking user account
COMMENT
declare -r EXIT_PROG=0
declare -r ROOT_UID=0
declare -r NON_ROOT=121
declare -r EXIT_UNKNOWN_USER=120
declare -r EXIT_UNKNOWN_GROUP=119
declare -r PROG="Manage User Account"
declare -r DESC="Administrative helper script use for: Adding user to sudo group, Removing user from sudo group,
Listing user's group(s), Locking user account and Unlocking user account."
userName=""
groupName=""

clearVars() {
    unset userName
}

gracefulExit() {
    clearVars
    exit 0
}

exitProg() {
    gracefulExit
}

synopsis() {
    printf "\n\t%s\n" "$(color -w "${PROG^^}")"
    printf "\n%s\n" "$(color -w "$DESC")"
    printf "\n%s%s%s%s" "$(color -o "Synopsis: ")" "$(color -w "${0}")" " $(color -w "<aAlLRru?>")" " $(color -w "<username>")"
    printf "\n%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n" \
        "$(color -o "Parameters: ")" \
        "$(color -w "?:\tPrints this message")" \
        "$(color -w "a:\tAdd user to the sudo group")" \
        "$(color -w "A:\tAdd user to the group - Synopsis: ${0} -A <user-name> <group-name>")" \
        "$(color -w "l:\tLock user acount")" \
        "$(color -w "L:\tList user's groups")" \
        "$(color -w "r:\tRemove user from the sudo group")" \
        "$(color -w "R:\tRemove user from group")" \
        "$(color -w "u:\tUnlock user account")"
}

addUserToGroup() {
    if [ $UID -ne "$ROOT_UID" ]; then
        printf "\n\t%s\n\n" "$(color -x 179 "$(blink "Must run this script with root privilege")")"
        exit $NON_ROOT
    else
        usermod -aG "$groupName" "$userName"
        # printf "\n\t%s\n\n" "$(color -P "Done and Done!!")"
        exit $EXIT_PROG
    fi
}

addUserToSudo() {
    if [ $UID -ne "$ROOT_UID" ]; then
        printf "\n\t%s\n\n" "$(color -x 179 "$(blink "Must run this script with root privilege")")"
        exit $NON_ROOT
    else
        usermod -aG "sudo" "$userName"
        # printf "\t\t%s\n\n" "Done and Done!!"
        exit $EXIT_PROG
    fi
}

lockUserAccount() {
    if [ $UID -ne "$ROOT_UID" ]; then
        printf "\n\t%s\n\n" "$(color -x 179 "$(blink "Must run this script with root privilege")")"
        exit $NON_ROOT
    else
        usermod -L "$userName"
        # printf "\t\t%s\n\n" "Done and Done!!"
        exit $EXIT_PROG
    fi
}

unlockUserAccount() {
    if [ $UID -ne "$ROOT_UID" ]; then
        printf "\n\t%s\n\n" "$(color -x 179 "$(blink "Must run this script with root privilege")")"
        exit $NON_ROOT
    else
        usermod -U "$userName"
        # printf "\t\t%s\n\n" "Done and Done!!"
        exit $EXIT_PROG
    fi
}

listUserGroups() {
    if [ $UID -ne "$ROOT_UID" ]; then
        printf "\n\t%s\n\n" "$(color -x 179 "$(blink "Must run this script with root privilege")")"
        exit $NON_ROOT
    else
        groups "$userName"
        exit $EXIT_PROG
    fi
}

removeUserFromSudoGroup() {
    if [ $UID -ne "$ROOT_UID" ]; then
        printf "\n\t%s\n\n" "$(color -x 179 "$(blink "Must run this script with root privilege")")"
        exit $NON_ROOT
    else
        gpasswd -d "$userName" "sudo"
        # printf "\t\t%s\n\n" "Done and Done!!"
        exit $EXIT_PROG
    fi
}

removeUserFromGroup() {
    if [ $UID -ne "$ROOT_UID" ]; then
        printf "\n\t%s\n\n" "$(color -x 179 "$(blink "Must run this script with root privilege")")"
        exit $NON_ROOT
    else
        gpasswd -d "$userName" "$groupName"
        # printf "\t\t%s\n\n" "Done and Done!!"
        exit $EXIT_PROG
    fi
}

trap "gracefulExit" INT TERM QUIT PWR

while getopts ':?l:u:a:L:r:A:R:' OPTION; do
    case ${OPTION} in
    a)
        # Add user to sudo group

        if [ ! -e "$2" ]; then
            userName="$(cat </etc/passwd | awk -F : '{print $1}' | grep -E "\b($2)\b")"
            if [ -n "$userName" ]; then
                addUserToSudo "$userName"
            else
                printf "\n\t%s\n\n" "$(color -o "Username ${2^^} does not exist!")"
                exit $EXIT_UNKNOWN_USER
            fi
        else
            printf "\nMust enter a valid username \n\n"
            exit $EXIT_UNKNOWN_USER
        fi

        ;;

    A)
        # Add user to existing group

        if [ $# -eq 3 ]; then
            userName="$(cat </etc/passwd | awk -F : '{print $1}' | grep -E "\b($2)\b")"
            groupName="$(cat </etc/group | awk -F : '{print $1}' | grep -E "\b($3)\b")"
            if [ -n "$userName" ]; then
                if [ -n "$groupName" ]; then
                    addUserToGroup "$userName" "$groupName"
                else
                    printf "\n\t%s\n\n" "$(color -o "Group ${3^^} does not exist!")"
                    exit $EXIT_UNKNOWN_GROUP
                fi
            else
                printf "\n\t%s\n\n" "$(color -o "Username ${2^^} does not exist!")"
                exit $EXIT_UNKNOWN_USER
            fi
        fi

        ;;

    l)
        # Lock user account

        if [ ! -e "$2" ]; then
            userName="$(cat </etc/passwd | awk -F : '{print $1}' | grep -E "\b($2)\b")"
            if [ -n "$userName" ]; then
                lockUserAccount "$userName"
            else
                printf "\n\t%s\n\n" "$(color -o "Username ${2^^} does not exist!")"
                exit $EXIT_UNKNOWN_USER
            fi
        else
            printf "\nMust enter a valid username \n\n"
            exit $EXIT_UNKNOWN_USER
        fi

        ;;

    L)
        # List user's group(s)

        if [ ! -e "$2" ]; then
            userName="$(cat </etc/passwd | awk -F : '{print $1}' | grep -E "\b($2)\b")"
            if [ -n "$userName" ]; then
                listUserGroups "$userName"
            else
                printf "\n\t%s\n\n" "$(color -o "Username ${2^^} does not exist!")"
                exit $EXIT_UNKNOWN_USER
            fi
        else
            printf "\nMust enter a valid username \n\n"
            exit $EXIT_UNKNOWN_USER
        fi

        ;;

    r)
        # Remove user from sudo group

        if [ ! -e "$2" ]; then
            userName="$(cat </etc/passwd | awk -F : '{print $1}' | grep -E "\b($2)\b")"
            if [ -n "$userName" ]; then
                removeUserFromSudoGroup "$userName"
            else
                printf "\n\t%s\n\n" "$(color -o "Username ${2^^} does not exist!")"
                exit $EXIT_UNKNOWN_USER
            fi
        else
            printf "\nMust enter a valid username \n\n"
            exit $EXIT_UNKNOWN_USER
        fi

        ;;

    R)
        # Remove user from existing group

        if [ $# -eq 3 ]; then
            userName="$(cat </etc/passwd | awk -F : '{print $1}' | grep -E "\b($2)\b")"
            groupName="$(cat </etc/group | awk -F : '{print $1}' | grep -E "\b($3)\b")"
            if [ -n "$userName" ]; then
                if [ -n "$groupName" ]; then
                    removeUserFromGroup "$userName" "$groupName"
                else
                    printf "\n\t%s\n\n" "$(color -o "Group ${3^^} does not exist!")"
                    exit $EXIT_UNKNOWN_GROUP
                fi
            else
                printf "\n\t%s\n\n" "$(color -o "Username ${2^^} does not exist!")"
                exit $EXIT_UNKNOWN_USER
            fi
        fi

        ;;

    u)
        # Unlock user account

        if [ ! -e "$2" ]; then
            userName="$(cat </etc/passwd | awk -F : '{print $1}' | grep -E "\b($2)\b")"
            if [ -n "$userName" ]; then
                unlockUserAccount "$userName"
            else
                printf "\n\t%s\n\n" "$(color -o "Username ${2^^} does not exist!")"
                exit $EXIT_UNKNOWN_USER
            fi
        else
            printf "\nMust enter a valid username \n\n"
            exit $EXIT_UNKNOWN_USER
        fi

        ;;

    \?)
        synopsis
        ;;
    esac
done
shift "$(($OPTIND - 1))"
