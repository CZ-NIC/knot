CC      ::= cc
BASEDIR ::= $(shell realpath ../../src)
SOURCES ::= showkey.c $(BASEDIR)/contrib/base64.c
CFLAGS  ::= -Wall -Wextra -O0 -ggdb3 -I$(BASEDIR)
LDFLAGS ::= -Wl,-rpath,$(BASEDIR)/.libs -L$(BASEDIR)/.libs -lknot

all: showkey

showkey: $(SOURCES)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)

clean:
	rm -f showkey

.PHONY: all clean
