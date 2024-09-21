#!/usr/bin/env bash

INTDEC_PATTERN="^([0-9]{1,3})(\.[0-9]{1,2})?$"
INTEGER_PATTERN="^[0-9]{1,3}$"
PATH_PATTERN='^((/)?([a-zA-Z]+)(/[a-zA-Z]+/?)?$|/)'
PATH_PATTERN_II='^(\/|\.|(\.\/))?[a-zA-Z-]+$'
WORD_PATTERN='^[a-zA-Z]+$'
NUMBER_PATTERN='^[0-9]+$'
ALPHA_NUM_PATTERN='^([0-9]+|[A-Za-z]+)$'
IP4_PATTERN='^([1-9]{1,3}\.)([1-9][0-9]{1,2}[1-9]{1}))'
