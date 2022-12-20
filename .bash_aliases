#!/usr/bin/bash

alias l='ls -hst'
alias ll='ls -lh'
alias la='ls -hAlts'
alias myip4='whatsmyip4address'
alias myip6='whatsmyip6address'
alias myips='whatsmyip4address && whatsmyip6address'
alias pcr='for N in {1..255};do color -x $N "Color value is $N!";done'
alias nano='nano -l'
alias dim='xdpyinfo | grep dimensions | sed -r "s/^[^0-9]*([0-9]+x[0-9]+).*$/\1/"'
alias dimen='xdpyinfo | grep dimensions'
alias dimi='xdpyinfo'
