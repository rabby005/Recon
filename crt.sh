#!/bin/bash

if [ "$1" == "-h" ] || [ "$1" == "--help" ] || [[ $# -eq 0 ]]
  then
    me=`basename "$0"`
    echo "Find subdomains in certificate transparency log."
    echo -e "Usage:\n\t./${me} [domain]"
    echo -e "Example:\n\t./${me} example.com"
    exit 1
fi


curl https://crt.sh/\?q\=%25.$1 2>&1 | grep -i '<TD>' | grep -iv '<TD></TD>' | grep -iv '<TD><A' | grep -iPo '(?<=TD>).*?(?=<)' | sort | uniq
