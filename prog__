#!/bin/bash
set -e
# set -u
set -o pipefail
declare -A tasks
DIALOG=${DIALOG=zenity}

clearVars() {
    unset $@ manualvalue monthvalue locatevalue
}

gracefulExit() {
    clearVars
    exit 0
}

generatePassword() {
    color -w '\n\tGenerating password ...\n'
    sleep 2
    apg -a 1 -M Sncl -m 17 -n 1 -E +\<\>\;:\|\\\^\'\",\.\={}*\-[]\`\~\)\(\/
    gracefulExit
}

synopsis() {
    color -w "Synopsis: `color -y "prog <-dmplh?s> [argument]"`\n"
    color -o "Prog `color -w "is a cheesy assistant Bash script that provides tasks to generate a password, shows the current date, display given month, finds the location of a program or script and displays man page description of a program."`\n"
    color -g "Options:"
    color -w "\td: show date\n\tm: [month]: show month - defaults to current month\n\tp: <program_name>: search manual pages\n\tl: <program_name>: find program location\n\th: show usage\n\t?: synopsis\n\ts: generate password\n"
}

help() {
    color -w "\t\t\tWelcome to Prog!"
    echo -e "\t\e[38;5;215mA Multi-tasked Bash script providing various functions."
    echo -e "\e[38;5;224m------------------------------------------------------------------------"
    echo -e "\e[38;5;193mUsage: prog <option> [argument]"
    color -g "Options:"
    color -w "\td: show date\n\tm: [month]: show month - defaults to current month\n\tp: <program_name>: search manual pages\n\tl: <program_name>: find program location\n\th: show usage\n\t?: synopsis\n\ts: generate password\n"
}

showMonth() {
    if [[ ${monthvalue} =~ (january|february|march|april|may|june|july|august|september|october|november|december) ]];
    then
        ncal -bm ${monthvalue}
    fi
}

showDate() {
    ncal -bw
}

showManualPageFor() {
    apropos ${manualvalue}
}

findProgramLocation() {
    whereis ${locatevalue}
}

defaultMonth() {
    ncal -bm `date +'%B'`
    gracefulExit
}

info() {
    # printf '%s\n' "${MSG}"
    MSG="\tWelcome to Prog!\nA Bash script that performs 4 seperate user tasks.\n\n@Author:      Rick Walker\n@Version:     0.0.1\n."
    $DIALOG --info \
    --title "Prog" \
    --width 217 \
    --height 110 \
    --text "${MSG}" \
    --icon-name=emblem-shared
    gracefulExit
}

trap "gracefulExit" INT TERM QUIT PWR STOP KILL

while getopts ':dhm:p:l:s' OPTION; do
    case "$OPTION" in
        h)
            help
            gracefulExit
        ;;
        
        \?)
            synopsis
            gracefulExit
        ;;
        
        :)
            if [[ ${OPTARG} == "m" ]];
            then
                tasks["monthdefault"]=`color -w "Run default month"`
                continue
            else
                tasks["argumenterror"]=`color -w "\tOption ${OPTARG} requires an argument."`
                continue
            fi
        ;;
        
        p)
            if [[ $OPTARG =~ (\-[a-z]) ]];
            then
                tasks["maunualargumenterror"]=`color -w "Opton -m received an invalid argument: ${OPTARG}\n"`
                continue
            elif [[ $str == $OPTARG ]];
            then
                tasks["manualerror"]=`color -r "Option -l needs an argument\n"`
                continue
            else
                tasks["manual"]="${OPTARG}"
            fi
        ;;
        
        l)
            if [[ $OPTARG =~ (\-[a-z]) ]];
            then
                tasks["locationargumenterror"]=`color -w "Option -l received an invalid argument: ${OPTARG}\n"`
                continue
            elif [[ $str == $OPTARG ]];
            then
                tasks["locationerror"]=`color -w "Option -l needs an argument\n"`
                continue
            else
                tasks["locate"]="${OPTARG}"
            fi
        ;;
        
        d)
            tasks["date"]=`color -w "get current date"`
            continue
        ;;
        
        m)
            if [[ $OPTARG =~ (\-[a-z]) ]];
            then
                tasks["montherror"]="`color -w "Option -m received an invalid argument: ${OPTARG}\n"`"
                continue
            else
                tasks["month"]="${OPTARG}"
            fi
        ;;
        
        s)
            if [[ $OPTARG =~ (\-[a-z]) ]];
            then
                tasks["passworderror"]="`color -w "Option -m received an invalid argument: ${OPTARG}\n"`"
                continue
            else
                tasks["password"]=`color -w "Generate password"`
            fi
            
    esac
done
shift "$(($OPTIND -1))"

if [[ ${#tasks[@]} -gt 0 ]];
then
    for K in ${!tasks[@]}
    do
        if [[ ${K} == "manual" ]];
        then
            manualvalue=${tasks[$K]}
            showManualPageFor
            unset -v 'tasks[$K]'
            if [[ ${#tasks[@]} -gt 0 ]];
            then
                continue
            fi
        elif [[ "${K}" == "date" ]];
        then
            showDate
            unset -v 'tasks[$K]'
            if [[ ${#tasks[@]} -gt 0 ]];
            then
                continue
            fi
        elif [[ ${K} == "locate" ]];
        then
            locatevalue=${tasks[$K]}
            findProgramLocation
            unset -v 'tasks[$K]'
            if [[ ${#tasks[@]} -gt 0 ]];
            then
                continue
            fi
        elif [[ ${K} == "month" ]];
        then
            monthvalue=${tasks[$K]}
            showMonth
            unset -v 'tasks[$K]'
            if [[ ${#tasks[@]} -gt 0 ]];
            then
                continue
            fi
        elif [[ ${K} == "monthdefault" ]];
        then
            defaultMonth
            unset -v 'tasks[$K]'
            if [[ ${#tasks[@]} -gt 0 ]];
            then
                continue
            fi
        elif [[ ${K} == "password" ]];
        then
            generatePassword
            unset -v 'tasks[$K]'
            if [[ ${#tasks[@]} -gt 0 ]];
            then
                continue
            fi
        fi
    done

    if [[ ${#tasks[@]} -gt 0 ]];
    then
        for T in ${!tasks[@]}
        do
            case ${T,,} in
                argumenterror)
                    blink `color -o "This option requires an argument"`
                ;;

                manualerror)
                    blink `color -o "Option -p error occurred"`
                ;;

                maunualargumenterror)
                    blink `color -o "Invalid argument supplied to option -p"`
                ;;

                locationargumenterror)
                    blink `color -o "Invalid argument supplied to option -l"`
                ;;

                passworderror)
                    blink `color -o "Invalid argument supplied to option -s"`
                ;;
            esac
            color -w "Enter prog -h or prog -? for more help"
        done
    fi
elif [[ $# -eq 1 ]] && [[ $1 == "info" ]];then info
fi