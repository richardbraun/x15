#!/bin/sh

# This script is meant to be run by the build system.

set -e

compile="$1"
output_file="$2"

shift 2

tmpfile1=$(mktemp)
tmpfile2=$(mktemp)

cleanup()
{
    rm -f $tmpfile1 $tmpfile2
}

trap cleanup EXIT

process()
{
    target=$1

    shift

    for dep in $@; do
        echo $target $dep
    done
}

# Define _KERN_INIT_H so that the INIT_XXX macros aren't expanded.
$compile -E -D_KERN_INIT_H "$@" \
     | sed -e 's/#.*$//' \
     | tr '\n' ' ' \
     | tr -s ' ' \
     | sed -E -e 's/INIT_OP_DEP\(([a-zA-Z0-9_]*), 1 \)/\1/g' \
     | grep -P -o 'INIT_OP_DEFINE\(.*?\)' \
     | sed -e 's/^INIT_OP_DEFINE(//' \
     | sed -e 's/).*$//' \
     | tr -d , \
| while read line; do
    process $line
done > $tmpfile1

if [ -z "$(cat $tmpfile1)" ]; then
    return 1
fi

# XXX Avoid using pipes because of the lack of a standard -o pipefail variant.
tsort < $tmpfile1 > $tmpfile2
tac < $tmpfile2 > "$output_file"
