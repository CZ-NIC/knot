BASE = ../src
CFLAGS += -std=gnu99 -g -I.. -I$(BASE) -I$(BASE)/libknot -I/usr/local/include 

chkjournal: chkjournal.c $(BASE)/libknotd.la
	libtool --mode=link $(CC) $(CFLAGS) chkjournal.c $(BASE)/libknotd.la -o chkjournal 
chkjournal-i386:
	@echo "!!! Make sure knot is compiled with -fpack-struct=4"
	@grep -q -- "-fpack-struct=4" $(BASE)/Makefile || exit 1
	libtool --mode=link $(CC) $(CFLAGS) -fpack-struct=4 chkjournal.c $(BASE)/libknotd.la -o chkjournal-i386 
chkjournal-amd64:
	@echo "!!! Make sure knot is compiled with -fpack-struct=8"
	@grep -q -- "-fpack-struct=8" $(BASE)/Makefile || exit 1
	libtool --mode=link $(CC) $(CFLAGS) -fpack-struct=8 chkjournal.c $(BASE)/libknotd.la -o chkjournal-amd64 
clean:
	rm chkjournal chkjournal-i386 chkjournal-amd64

