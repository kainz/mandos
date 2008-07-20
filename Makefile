CFLAGS="-Wall -std=gnu99"
LDFLAGS=-lgnutls

all: plugbasedclient

clean:
	rm -f plugbasedclient

client_debug: client
	mv -f client client.tmp
	$(MAKE) client CXXFLAGS="$(CXXFLAGS) -DDEBUG -DCERT_ROOT=\\\"./\\\""
	mv client client_debug
	mv client.tmp client
