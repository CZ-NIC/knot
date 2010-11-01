all: cf-test

clean:
	rm -f cf-test
	rm -f *.o
	rm -f cf-lex.c
	rm -f cf-parse.output cf-parse.tab.c cf-parse.tab.h

cf-test: cf-lex.o cf-parse.tab.o main.o conf.o
	gcc -o cf-test cf-lex.o cf-parse.tab.o main.o conf.o

%.o: %.c
	gcc -I.. -c $^

cf-parse.tab.h: cf-parse.tab.c

cf-parse.tab.c: cf-parse.y
	bison -bcf-parse -dv -pcf_ cf-parse.y

cf-lex.c: cf-lex.l
	flex -s -B -8 -ocf-lex.c -Pcf_ cf-lex.l
