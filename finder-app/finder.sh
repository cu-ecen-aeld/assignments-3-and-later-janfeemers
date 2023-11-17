#!/bin/sh
# finds hits in a file dir
# Author: Jan Feemers

set -e

help(){
    echo "finder.sh /path/to/dir/ TEXT"
    echo "The first argument is a path to a directory on the filesystem"
    echo "The second argument is a text string which will be searched within these files."
}

# check amount of input arguments
if [ "$#" -ne 2 ]; then
    echo "ERROR: Two arguments needed" >&2
    echo ""
    help
    exit 1
fi

filesdir="$1"
searchstr="$2"

# check if path exits
if ! [ -d "$filesdir" ]; then
    echo "ERROR: The seccond argument must be a path" >&2
    echo ""
    help
    exit 1
fi

#The number of files are X and the number of matching lines are Y
hit_files=$(grep -rl "$searchstr" $filesdir/* | wc -l)
hits=$(grep -r "$searchstr" $filesdir/* | wc -l)

echo "The number of files are $hit_files and the number of matching lines are $hits"
