CC=clang
#CC=gcc
CFLAGS=-std=c99 -pedantic -Wall

ALL=srsr

all: $(ALL)

srsr: Makefile srsr.c
	$(CC) $(CFLAGS) -o $@ *.c
	sudo chown root:root $@
	sudo chmod +s $@

clean:
	rm -f $(ALL)
