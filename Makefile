CFLAGS=		-g
LDFLAGS=	-lmilter

all: milter-regex milter-regex.cat8

milter-regex: milter-regex.o strlcpy.o y.tab.o
	gcc -o milter-regex milter-regex.o strlcpy.o $(LDFLAGS)

milter-regex.o: milter-regex.c
	gcc $(CFLAGS) -c milter-regex.c

strlcpy.o: strlcpy.c
	gcc $(CFLAGS) -c strlcpy.c

milter-regex.cat8: milter-regex.8
	nroff -Tascii -mandoc milter-regex.8 > milter-regex.cat8

clean:
	rm -f *.core milter-regex *.o *.cat8
