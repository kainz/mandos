WARN=-O -Wall -Wformat=2 -Winit-self -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wunused-parameter -Wstrict-aliasing=2 -Wextra -Wfloat-equal -Wundef -Wshadow -Wunsafe-loop-optimizations -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings -Wconversion -Wstrict-prototypes -Wold-style-definition -Wpacked -Wnested-externs -Wunreachable-code -Winline -Wvolatile-register-var 
DEBUG=-ggdb3
# For info about _FORTIFY_SOURCE, see
# <http://gcc.gnu.org/ml/gcc-patches/2004-09/msg02055.html>
FORTIFY=-D_FORTIFY_SOURCE=2 # -fstack-protector-all
#COVERAGE=--coverage
OPTIMIZE=-Os
LANGUAGE=-std=gnu99

# Do not change these two
CFLAGS=$(WARN) $(DEBUG) $(FORTIFY) $(COVERAGE) $(OPTIMIZE) $(LANGUAGE)
LDFLAGS=$(COVERAGE)

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
