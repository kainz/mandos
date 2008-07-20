CFLAGS=-Wall -g -std=gnu99
LDFLAGS=-lgnutls

all: plugbasedclient

clean:
	rm -f plugbasedclient
