 #!/bin/bash

graceful_exit() {
 exit 0
}

missing() {
 echo -e "\e[1;34m Missing parameter \e[0m\n"
 graceful_exit
}

trap "graceful_exit" INT TERM QUIT PWR

if [ $# -lt 1 ] && [ $1 != $str ];
then
    missing
else
    result=""
    for p in $@
    do
        result="${result}${p} "
    done
        echo -e "\e[1;34m${result}\e[0m"
fi


