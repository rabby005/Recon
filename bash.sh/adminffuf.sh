#!/bin/bash 

target=$1
#common-wordlist
#ffuf -c -w ~/wordlists/Critical-wordlist -u $1/FUZZ
ffuf -c -w ~/wordlists/common.txt -u $1/FUZZ
