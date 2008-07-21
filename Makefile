CFLAGS=-Wall -g -std=gnu99

PROGS=plugbasedclient plugins.d/mandosclient plugins.d/passprompt

objects=$(shell for p in $(PROGS); do echo $${p}.o; done)

all: $(PROGS)

plugbasedclient: plugbasedclient.o
	$(LINK.o) -lgnutls $(COMMON) $^ $(LOADLIBES) $(LDLIBS) -o $@

plugins.d/mandosclient: plugins.d/mandosclient.o
	$(LINK.o) -lgnutls -lavahi-core -lgpgme $(COMMON) $^ $(LOADLIBES) $(LDLIBS) -o $@

plugins.d/passprompt: plugins.d/passprompt.o
	$(LINK.o) $(COMMON) $^ $(LOADLIBES) $(LDLIBS) -o $@

.PHONY : clean
clean:
	-rm -f $(PROGS) $(objects) core
