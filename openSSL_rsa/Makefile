CC=gcc
CFLAGS=-Wall
LIBS=-lcrypto

# The target executable name
TARGET=rsa

all: $(TARGET)

$(TARGET): rsa.c
	$(CC) $(CFLAGS) -o $(TARGET) rsa.c $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean