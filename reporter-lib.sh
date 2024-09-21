#!/usr/bin/env bash

report() {
    fileName="$1"
    if [ ! -e "./$fileName-report.txt" ]; then
        touch "./$fileName-report.txt"
    fi
    results="$2"
    printf "$results\n" >>"./$fileName-report.txt"
}
