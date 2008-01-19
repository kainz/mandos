CXXFLAGS=-Wall -W -g
LDFLAGS=-lgnutls

all: client server

clean:
	rm -f server client client_debug

client_debug: client
	mv -f client client.tmp
	$(MAKE) client CXXFLAGS="$(CXXFLAGS) -DDEBUG -DCERT_ROOT=\\\"./\\\""
	mv client client_debug
	mv client.tmp client
