CC=gcc
MBED_PATH=/usr/local
CFLAGS=-I$(MBED_PATH)/include -Wall
LIBS=-L$(MBED_PATH)/lib -lmbedtls -lmbedcrypto -lmbedx509 -lm

SRC=$(wildcard *.c)
TARGETS=$(patsubst %.c, %, $(SRC))

all: $(TARGETS)

%: %.c
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(TARGETS)