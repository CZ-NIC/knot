#!/bin/bash

IN="./scanner.rl"
OUT="./scanner.c"

pushd ../src/zscanner/

ragel -T0 -s -o $OUT $IN
sed '/#line/d' $OUT > $OUT.t0
rm $OUT

ragel -G2 -s -o $OUT $IN
sed '/#line/d' $OUT > $OUT.g2
rm $OUT

popd
