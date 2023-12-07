
default: test_min32bit

kru_%: kru_%.c kru.c kru-tests.c
	gcc -O3 -Wall -I../../../ $(CFLAGS) -DKRU_IMPL_$* kru-tests.c ../../../contrib/openbsd/siphash.c -ldnssec -o "$@"

test_%: kru_%
	./kru_$*
