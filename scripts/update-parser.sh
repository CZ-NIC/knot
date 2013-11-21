#!/bin/bash

pushd ../src/zscanner/

ragel -T0 -s -o ./scanner.c ./scanner.rl
sed '/#line/d' ./scanner.c > ./scanner.c.t0

ragel -G2 -s -o ./scanner.c ./scanner.rl
sed '/#line/d' ./scanner.c > ./scanner.c.g2

popd
