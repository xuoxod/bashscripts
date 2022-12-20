 #!/bin/bash

 clear_vars() {
     unset result 
 }

graceful_exit() {
 clear_vars
 exit 0
}

missing() {
 echo -e "\e[1;35mMissing parameter \e[0m\n"
 graceful_exit
}

trap "graceful_exit" INT TERM QUIT PWR

if [ $# -lt 1 ];
then
    missing
else
    result=""
    for p in $@
    do
        result="${result}${p} "
    done
        echo -e "\e[1;31m${result}\e[0m"
        graceful_exit
fi
