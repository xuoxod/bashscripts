#! /usr/bin/bash

black() {
    printf "\e[97m\e[38;5;234m%s\n", "$text"
}

blue() {
    printf "\e[38;5;224m\e[38;5;39m%s\n", "$text"
}

cyan() {
    printf "\e[38;5;224m\e[38;5;87m%s\n" "$text"
}

green() {
    printf "\e[38;5;224m\e[38;5;119m%s\n" "$text"
}

magenta() {
    printf "\e[38;5;224m\e[38;5;200m%s\n" "$text"
}

orange() {
    printf "\e[38;5;224m\e[38;5;208m%s\n" "$text"
}

pink() {
    printf "\e[38;5;224m\e[38;5;211m%s\n" "$text"
}

purple() {
    printf "\e[38;5;224m\e[38;5;129m%s\n" "$text"
}

red() {
    printf "\e[38;5;224m\e[38;5;196m%s\n" "$text"
}

white() {
    printf "\e[38;5;224m\e[38;5;224m%s\n" "$text"
}

yellow() {
    printf "\e[38;5;224m\e[38;5;226m%s\n" "$text"
}

custom() {
    printf "\e[38;5;224m\e[38;5;%dm%s\n" "$icolor" "$text"
}

blink() {
    printf "\e[28;5;24m%s\e[m\n" "$text"
}

util-export() {
    export -f custom
    export -f black
    export -f blue
    export -f cyan
    export -f green
    export -f magenta
    export -f orange
    export -f pink
    export -f purple
    export -f red
    export -f white
    export -f yellow
    export -f blink
}
