#! /usr/bin/bash

for I in $(ip -4 addr show | awk -F : '{print $2}' | grep -E "[a-z0-9][^\b(lo)\b\b(docker*)\b]{2}" | awk '{gsub(/[ \t\n\r]/,"");print}'); do
    netface="$I"
    ip -4 addr show "${netface}" | grep -E "inet (([0-9])\.){4}*" | awk '{print $2}' | awk -F "/" '{print $1}'
done
