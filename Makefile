CFLAGS=		-g
LDFLAGS=	-lmilter

.PHONY: all
all: sa2scl-milter

sa2scl-milter: sa2scl-milter.o strlcpy.o
	gcc -o sa2scl-milter sa2scl-milter.o strlcpy.o $(LDFLAGS)

sa2scl-milter.o: sa2scl-milter.c
	gcc $(CFLAGS) -c sa2scl-milter.c

strlcpy.o: strlcpy.c
	gcc $(CFLAGS) -c strlcpy.c

clean:
	rm -f *.core sa2scl-milter *.o
