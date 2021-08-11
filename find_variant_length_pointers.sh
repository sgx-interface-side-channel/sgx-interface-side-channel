#!/bin/bash

set -e

if [ "$#" -ne 1 ] || [ ! -f ${1} ] ; then
    echo "Input error or File not exist!"
    echo "usage: < EDL file dir (e.g. '/home/Enclave.edl')>" >&2
    exit 1
fi
# TODO:use parameter index rather than the parameter name
edl_path=${1}

sensitive=$(cat $edl_path | awk '{if ($1=="trusted") 
    {if ($2=="{") {start=NR;stop=99999999}}
} NR>start {if ($1=="};"){ if(NR<=stop){stop=NR}}} NR>start {if (NR<stop) {print}}' | awk -F '(' '/\[*out*\]/ {print} /\[*user_check*\]/ {print}');

declare -a func
index=0 
for line in $sensitive
do
    if grep -q "("<<<$line; then
        echo $line | awk -F '(' '{printf $1 " "}'
    fi
    if grep -q "*"<<<$line; then
        echo $line | awk -F '*' '{printf $2}' | awk -F ')' '{printf $1 " "}'
        echo 
    fi
    arr[$index]=$i
    let "index+=1"
done
