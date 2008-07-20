CFLAGS=-Wall -g --std=gnu99
LDFLAGS=-lgnutls -lavahi-core -lgpgme

PROGS=mandosclient passprompt

objects=mandosclient.o passprompt.o

all: $(PROGS)

mandosclient: mandosclient.o
	$(LINK.o) -lgnutls -lavahi-core -lgpgme $(COMMON) $^ $(LOADLIBES) $(LDLIBS) -o $@

passprompt: passprompt.o
	$(LINK.o) $(COMMON) $^ $(LOADLIBES) $(LDLIBS) -o $@

.PHONY : clean
clean :
	-rm -f $(PROGS) $(objects) core
