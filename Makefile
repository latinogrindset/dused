CC = gcc
CFLAGS = -Wall -Wextra -O2

all: dused

dused: dused.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f dused

.PHONY: all clean
