#    Find network interfaces

# The netface formula

# This will output all working network interfaces except the loopback.
ip -4 addr show | awk -F : '{print $2}' | grep -E "[a-z0-9][^\b(lo)\b]{2}" | awk '{gsub(/[ \t\n\r]/,"");print}'

# Tweaked to include ingnoring any docker interfaces
ip -4 addr show | awk -F : '{print $2}' | grep -E "[a-z0-9][^\b(lo)\b\b(docker*)\b]{2}"

# Tweaked a little more to remove any spacing character
ip -4 addr show | awk -F : '{print $2}' | grep -E "[a-z0-9][^\b(lo)\b\b(docker*)\b]{2}" | awk '{gsub(/[ \t\n\r]/,"");print}'

# Dependant on netface script value, output the ipv6
ip -6 addr show "$(netface)" | grep -E "inet6 (([a-zA-Z0-9])::?)*" | awk '{print $2}' | awk -F / '{print $1}'

for I in $(ip -4 addr show | awk -F : '{print $2}' | grep -E "[a-z0-9A-Z][^\b(lo)\b]{2}"); do
    printf "$I\n"
    sleep 1
done
-------------------------------
#     Copy directories

scp -r -P 30778 -i ~/.ssh/id-from-xuoux-to-xuaux-ed25519 ./.user-helpers ./.user-scripts ./user-env ./.reference rick@192.168.1.158:/home/rick/private/projects/desktop/docker/proj1

-------------------------------

#!/bin/bash

#Defining variables
age=25
is_voter=true

#Using the ternary operator
[ "$age" -ge 18 ] && [ "$is_voter" == true ] && echo "You are an adult and can vote."

-------------------------------

for I in $(ip -4 addr show | awk -F : '{print $2}' | grep -E "[a-z0-9][^\b(lo)\b]{2}" | awk '{gsub(/[ \t\n\r]/,"");print}'); do
    [ "$I" != "docker0" ] && interface="$I"
    ip -4 addr show "${interface}" | grep -E "inet (([0-9])\.){4}*" | awk '{print $2}' | awk -F "/" '{print $1}'
done

-------------------------------
netfaces=$(
    ip -4 addr show | awk -F : '{print $2}' | grep -E "[a-z0-9][^\b(lo)\b]{2}" | awk '{gsub(/[ \t\n\r]/,"");print}'
)

for I in $(netfaces); do
    [ I != "docker*" ] && interface="$I"
    ip -6 addr show "$interface"
done

for I in $(ip -4 addr show | awk -F : '{print $2}' | grep -E "[a-z0-9][^\b(lo)\b]{2}" | awk '{gsub(/[ \t\n\r]/,"");print}'); do
    [ $I != "docker*" ] && interface="$I"
    ip -6 addr show "$interface"
done

-------------------------------
ip -6 addr show wlp2s0 | cut -d ':' -f2 | cut -d ' ' -f2
-------------------------------
for I in $(anetfaces); do
    ip -4 addr show "$I"
    printf "\n\n"
    ip -6 addr show "$I"
    printf "\n\n"
    ifconfig "$I"
    printf "\n\n\n----------------------------------------------------------------------------------------------------------\n"
done

for I in $(netfaces); do
    ip -4 addr show "$I"
    printf "\n\n"
    ip -6 addr show "$I"
    printf "\n\n"
    ifconfig "$I"
    printf "\n\n\n----------------------------------------------------------------------------------------------------------\n"
done

for I in $(netface); do
    ip -4 addr show "$I"
    printf "\n\n"
    ip -6 addr show "$I"
    printf "\n\n"
    ifconfig "$I"
    printf "\n\n\n----------------------------------------------------------------------------------------------------------\n"
done

-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
-------------------------------
