#!/usr/bin/env bash

blink() {
    text=$(echo -e "\e[38;5;254m${1^}\e[m")
    /usr/bin/echo -e "\e[28;5;24m${text}\e[m\n"
}
