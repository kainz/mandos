CXXFLAGS=-Wall -W -g
LDFLAGS=-lgnutls

all: client server

clean:
	rm -f server client
