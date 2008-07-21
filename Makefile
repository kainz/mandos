WARN=-O -Wall -Wformat=2 -Winit-self -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wunused-parameter -Wstrict-aliasing=2 -Wextra -Wfloat-equal -Wundef -Wshadow -Wunsafe-loop-optimizations -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings -Wconversion -Wstrict-prototypes -Wold-style-definition -Wpacked -Wnested-externs -Wunreachable-code -Winline -Wvolatile-register-var 
DEBUG=-ggdb3
#COVERAGE=--coverage
LANGUAGE=-std=gnu99

# Do not change these two
LDFLAGS=$(COVERAGE)
CFLAGS=$(WARN) $(COVERAGE) $(DEBUG) $(LANGUAGE)

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
