CC=g++
CFLAGS=-std=c++11 -Wall
LIBS=-lcryptopp

# The target executable name
TARGET=rsa

all: $(TARGET)

$(TARGET): rsa.cpp
	$(CC) $(CFLAGS) -o $(TARGET) rsa.cpp $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean