SHELL=/bin/bash

default: test

kru: kru-generic.c kru-avx2.c kru.inc.c kru-tests.c
	gcc -O3 -Wall -I../../../ $(CFLAGS) -DKRU_IMPL_ss16bit kru-tests.c kru-generic.c kru-avx2.c ../../../contrib/openbsd/siphash.c -ldnssec -o "$@"

test: kru
	time ./kru
