#!/bin/sh
COMMON_PARAMS="--prefix=/tmp/root --with-conf-mapsize=2 --with-sanitizer"
MS_PARAMS="--enable-async-query --with-module-delay --enable-throttle-dnstap-logs --with-module-dnstap --without-module-azuredb --without-module-azurednssec --enable-testing"
./configure $COMMON_PARAMS CC=clang $MS_PARAMS 'CFLAGS=-O0 -ggdb3 -pipe -fno-omit-frame-pointer'
