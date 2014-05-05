#!/bin/bash

IN="./scanner.rl"
OUT="./scanner.c"

pushd ../src/zscanner/

ragel -T0 -s -o $OUT $IN
sed '/#line/d' $OUT > $OUT.t0
rm $OUT

# Remove unused constants because of clang 3.4 warnings
sed -e '/static\ const\ int\ zone_scanner_en_/d' -e '/zone_scanner_first_final/d' $OUT.t0 > ./tmp
mv -f ./tmp $OUT.t0

ragel -G2 -s -o $OUT $IN
sed '/#line/d' $OUT > $OUT.g2
rm $OUT

popd
