SHELL=/bin/bash

default: test

kru: kru-generic.c kru-avx2.c kru.inc.c kru-tests.c kru-decay.inc.c
	gcc -O3 -Wall -I../../../ $(CFLAGS) kru-tests.c kru-avx2.c ../../../contrib/openbsd/siphash.c -ldnssec -lm -o "$@"

test: kru
	time ./kru
