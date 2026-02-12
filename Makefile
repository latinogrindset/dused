CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS_LIB = -shared -fPIC -ldl

all: dused libdused.so

dused: dused.c
	$(CC) $(CFLAGS) -o $@ $<

libdused.so: libdused.c
	$(CC) $(CFLAGS) $(LDFLAGS_LIB) -o $@ $< -lpthread

clean:
	rm -f dused libdused.so

.PHONY: all clean
