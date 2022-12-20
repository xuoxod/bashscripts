#!/bin/bash

clearVars() {
 unset $@ $3
}

missing() {
 red "Error: " `white "Missing parameter"`
 usage
}

usage() {
 echo -e "\033[1;92mUsage: \033[0m" `echo -e '\033[1;96mxcolor <"Quoted  Text"> <Intensity> <Forecolor>\033[0m'`
 xcolor "For detailed usage, call xcolor usage" 1 97
 gracefulExit
}

gracefulExit() {
 clearVars
 exit 0
}

trap "gracefulExit" INT TERM PWR QUIT

if [ $# -eq 1 ] && [ ${1} == "usage" ]
then
    xcolor "           xcolor Usage Detail" 1 92
    xcolor ' xcolor <"Quoted Text"> <Intensity> <Color>' 0 97
    xcolor ' xcolor <"String List"> <Integer> <Integer>' 0 97
    printf "\n"
    xcolor ' Intensity: Bold 0=false, 1=true' 0 97
    printf "\n"
    xcolor ' Color Range: n0 through n7' 0 97
    xcolor ' Regular Colors: 30 - 37' 0 97
    xcolor ' High Intensity Colors: 90 - 97' 0 97
    printf "\n"
    xcolor '          black = n0' 0 90
    xcolor '            red = n1' 0 91
    xcolor '          green = n2' 0 92
    xcolor '         yellow = n3' 0 93
    xcolor '           blue = n4' 0 94
    xcolor '         purple = n5' 0 95
    xcolor '           cyan = n6' 0 96
    xcolor '          white = n7' 0 97
    printf "\n"
elif [[ $# -lt 3 ]];
then
    red "Error: " `white "Missing one or more arguments"`
    usage
elif [[ $# -gt 3 ]];
then
    red "Error: " `white "Wrong number of arguments"`
    usage
elif [[ ${1} == $str ]];
then
    red "Error: " `white "Text argument is null or empty"`
    usage
else
    echo -e "\033[$2;$3m${1}\033[0m"
fi
