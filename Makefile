CXXFLAGS=-Wall -g
LDFLAGS=-lgnutls

all: client server

clean:
	rm -f server client
