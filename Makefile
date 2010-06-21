CFLAGS=		-g
LDFLAGS=	-lmilter -pthread

.PHONY: all
all: sa2scl-milter

sa2scl-milter: sa2scl-milter.o strlcpy.o
	gcc -o sa2scl-milter sa2scl-milter.o strlcpy.o $(LDFLAGS)

sa2scl-milter.o: sa2scl-milter.c
	gcc $(CFLAGS) -c sa2scl-milter.c

strlcpy.o: strlcpy.c
	gcc $(CFLAGS) -c strlcpy.c

.PHONY: dist
dist: sa2scl-milter-0.1-src.tar.gz

sa2scl-milter-0.1-src.tar.gz: Makefile sa2scl-milter.c strlcpy.c sa2scl-milter.init sa2scl-milter.spec
	@mkdir -p sa2scl-milter-0.1
	@cp -p Makefile sa2scl-milter.c strlcpy.c sa2scl-milter.init sa2scl-milter.spec sa2scl-milter-0.1
	tar -czvf sa2scl-milter-0.1-src.tar.gz sa2scl-milter-0.1
	@rm -Rf sa2scl-milter-0.1

.PHONY: clean
clean:
	rm -f *.core sa2scl-milter *.o *.tar.gz

.PHONY: install
install:
	install -d $(sbindir)
	install -m 0755 -p sa2scl-milter $(sbindir)
