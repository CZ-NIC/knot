#!/bin/bash

### ZSCANNER ###

IN="./scanner.rl"
OUT_T0="./scanner.c.t0"
OUT_G2="./scanner.c.g2"

pushd ../src/zscanner/

# Generate slower/small zone parser.
ragel -T0 -s -o $OUT_T0 $IN

# Remove redundant comments and unused constants (clang warnings).
sed -i '/#line/d' $OUT_T0
sed -i '/static\ const\ int\ zone_scanner_/d' $OUT_T0

# Remove trailing white spaces.
sed -i 's/\s*$//g' $OUT_T0

# Generate fast/huge zone parser.
ragel -G2 -s -o $OUT_G2 $IN

# Remove redundant comments and unused constants (clang warnings).
sed -i '/#line/d' $OUT_G2
sed -i '/static\ const\ int\ zone_scanner_/d' $OUT_G2

# Remove trailing white spaces.
sed -i 's/\s*$//g' $OUT_G2

popd

### YPARSER ###

IN_Y="./ypbody.rl"
OUT_Y="./ypbody.c"

pushd ../src/libknot/yparser/

# Generate yparser.
ragel -T0 -s -o $OUT_Y $IN_Y

# Remove redundant comments and unused constants (clang warnings).
sed -i '/#line/d' $OUT_Y
sed -i '/static\ const\ int\ yparser_/d' $OUT_Y

# Remove trailing white spaces.
sed -i 's/\s*$//g' $OUT_Y

popd
