#!/bin/bash 

target=$1

subfinder -d $1 | httpx -silent | nuclei -c 200 -t log.yaml  -v
