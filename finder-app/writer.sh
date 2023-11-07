#!/bin/bash
# Author: Jan Feemers

set -e

help(){
    echo "writer.sh /path/to/dir/ TEXT"
    echo "The first argument is a path to a file"
    echo "The second argument is a text string which will be writen to this file."
}

# check amount of input arguments
if [ "$#" -ne 2 ]; then
    echo "ERROR: Two arguments needed" >&2
    echo ""
    help
    exit 1
fi

writefile="$1"
writestr="$2"

writedir=$(dirname "${writefile}")
if [ $? -ne 0 ]; then
    echo "ERROR: Not a valid path name" >&2
    echo ""
    help
    exit 1
fi

mkdir -p $writedir
if [ $? -ne 0 ]; then
    echo "ERROR: Could not create a file path" >&2
    echo ""
    help
    exit 1
fi

echo "$writestr" > $writefile
if [ $? -ne 0 ]; then
    echo "ERROR: Could not create athe file path" >&2
    echo ""
    help
    exit 1
fi
