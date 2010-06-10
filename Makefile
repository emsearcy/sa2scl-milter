CFLAGS=		-g
LDFLAGS=	-lmilter -lpthread

all: milter-regex milter-regex.cat8

milter-regex: milter-regex.o eval.o strlcpy.o y.tab.o
	gcc -o milter-regex milter-regex.o eval.o strlcpy.o y.tab.o $(LDFLAGS)

milter-regex.o: milter-regex.c eval.h
	gcc $(CFLAGS) -c milter-regex.c

eval.o: eval.c eval.h
	gcc $(CFLAGS) -c eval.c

strlcpy.o: strlcpy.c
	gcc $(CFLAGS) -c strlcpy.c
	
y.tab.o: y.tab.c
	gcc $(CFLAGS) -c y.tab.c

y.tab.c: parse.y
	yacc -d parse.y

milter-regex.cat8: milter-regex.8
	nroff -Tascii -mandoc milter-regex.8 > milter-regex.cat8

clean:
	rm -f *.core milter-regex y.tab.* *.o *.cat8
