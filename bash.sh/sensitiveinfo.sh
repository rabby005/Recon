#!/bin/bash 

target=$1
ffuf -c -w ~/wordlists/Critical-wordlist -u $1/FUZZ -mc 200,302,301,403,401,500 2>/dev/null

