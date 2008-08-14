WARN=-O -Wall -Wformat=2 -Winit-self -Wmissing-include-dirs \
	-Wswitch-default -Wswitch-enum -Wunused-parameter \
	-Wstrict-aliasing=2 -Wextra -Wfloat-equal -Wundef -Wshadow \
	-Wunsafe-loop-optimizations -Wpointer-arith \
	-Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings \
	-Wconversion -Wstrict-prototypes -Wold-style-definition \
	-Wpacked -Wnested-externs -Wunreachable-code -Winline \
	-Wvolatile-register-var
DEBUG=-ggdb3
# For info about _FORTIFY_SOURCE, see
# <http://gcc.gnu.org/ml/gcc-patches/2004-09/msg02055.html>
FORTIFY=-D_FORTIFY_SOURCE=2 # -fstack-protector-all
#COVERAGE=--coverage
#OPTIMIZE=-Os
LANGUAGE=-std=gnu99

# Do not change these two
CFLAGS=$(WARN) $(DEBUG) $(FORTIFY) $(COVERAGE) $(OPTIMIZE) $(LANGUAGE)
LDFLAGS=$(COVERAGE)

DOCBOOKTOMAN=xsltproc --nonet \
	--param man.charmap.use.subset		0 \
	--param make.year.ranges		1 \
	--param make.single.year.ranges		1 \
	--param man.output.quietly		1 \
	--param man.authors.section.enabled	0

PLUGINS=plugins.d/password-prompt plugins.d/password-request
PROGS=mandos-client $(PLUGINS)
DOCS=mandos.8 mandos-client.8mandos mandos-keygen.8 \
	plugins.d/password-request.8mandos \
	plugins.d/password-prompt.8mandos mandos.conf.5 \
	 mandos-clients.conf.5

objects=$(shell for p in $(PROGS); do echo $${p}.o; done)

all: $(PROGS)

doc: $(DOCS)

%.5: %.xml
	cd $(dir $^); $(DOCBOOKTOMAN) $(notdir $^)

%.8: %.xml
	cd $(dir $^); $(DOCBOOKTOMAN) $(notdir $^)

%.8mandos: %.xml
	cd $(dir $^); $(DOCBOOKTOMAN) $(notdir $^)

mandos-client: mandos-client.o
	$(LINK.o) -lgnutls $(COMMON) $^ $(LOADLIBES) $(LDLIBS) -o $@

plugins.d/password-request: plugins.d/password-request.o
	$(LINK.o) -lgnutls -lavahi-core -lgpgme $(COMMON) $^ \
		$(LOADLIBES) $(LDLIBS) -o $@

plugins.d/password-prompt: plugins.d/password-prompt.o
	$(LINK.o) $(COMMON) $^ $(LOADLIBES) $(LDLIBS) -o $@

.PHONY : all clean distclean run-client run-server install \
	install-server install-client uninstall uninstall-server \
	uninstall-client purge purge-server purge-client

clean:
	-rm --force $(PROGS) $(objects) $(DOCS) core

distclean: clean
mostlyclean: clean
maintainer-clean: clean
	-rm --force --recursive keydir

check:
	./mandos --check

run-client: all
	-mkdir keydir
	-./mandos-keygen --dir keydir
	./mandos-client --plugin-dir=plugins.d \
		--options-for=password-request:--keydir=keydir

run-server:
	./mandos --debug --configdir=.

install: install-server install-client

install-server: doc
	mkdir --mode=0755 --parents /etc/mandos
	install --mode=0755 mandos /usr/sbin/mandos
	install --mode=0644 --target-directory=/etc/mandos mandos.conf
	install --mode=0640 --target-directory=/etc/mandos \
		clients.conf
	gzip --best --to-stdout mandos.8 \
		> /usr/share/man/man8/mandos.8.gz
	gzip --best --to-stdout mandos.conf.5 \
		> /usr/share/man/man5/mandos.conf.5.gz
	gzip --best --to-stdout mandos-clients.conf.5 \
		> /usr/share/man/man5/mandos-clients.conf.5.gz

install-client: all doc /usr/share/initramfs-tools/hooks/.
	mkdir --mode=0755 --parents /usr/lib/mandos /etc/mandos
	-mkdir --mode=0700 /usr/lib/mandos/plugins.d
	chmod u=rwx,g=,o= /usr/lib/mandos/plugins.d
	install --mode=0755 --target-directory=/usr/lib/mandos \
		mandos-client
	install --mode=0755 --target-directory=/usr/sbin mandos-keygen
	install --mode=0755 \
		--target-directory=/usr/lib/mandos/plugins.d \
		plugins.d/password-prompt
	install --mode=4755 \
		--target-directory=/usr/lib/mandos/plugins.d \
		plugins.d/password-request
	install initramfs-tools-hook \
		/usr/share/initramfs-tools/hooks/mandos
	install initramfs-tools-hook-conf \
		/usr/share/initramfs-tools/conf-hooks.d/mandos
	gzip --best --to-stdout mandos-keygen.8 \
		> /usr/share/man/man8/mandos-keygen.8.gz
	gzip --best --to-stdout mandos-client.8mandos \
		> /usr/share/man/man8/mandos-client.8mandos.gz
	gzip --best --to-stdout plugins.d/password-prompt.8mandos \
		> /usr/share/man/man8/password-prompt.8mandos.gz
	gzip --best --to-stdout plugins.d/password-request.8mandos \
		> /usr/share/man/man8/password-request.8mandos.gz
	-/usr/sbin/mandos-keygen
	update-initramfs -k all -u

uninstall: uninstall-server uninstall-client

uninstall-server: /usr/sbin/mandos
	-rm --force /usr/sbin/mandos /usr/share/man/man8/mandos.8.gz \
		/usr/share/man/man5/mandos.conf.5.gz \
		/usr/share/man/man5/mandos-clients.conf.5.gz
	-rmdir /etc/mandos

uninstall-client:
# Refuse to uninstall client if /etc/crypttab is configured to use it
	! grep --regexp='^ *[^ #].*keyscript=/usr/lib/mandos/mandos-client' \
		/etc/crypttab
	-rm --force /usr/sbin/mandos-keygen \
		/usr/lib/mandos/mandos-client \
		/usr/lib/mandos/plugins.d/password-prompt \
		/usr/lib/mandos/plugins.d/password-request \
		/usr/share/initramfs-tools/hooks/mandos \
		/usr/share/initramfs-tools/conf-hooks.d/mandos \
		/usr/share/man/man8/mandos-client.8mandos.gz \
		/usr/share/man/man8/mandos-keygen.8.gz \
		/usr/share/man/man8/password-prompt.8mandos.gz \
		/usr/share/man/man8/password-request.8mandos.gz
	-rmdir /usr/lib/mandos/plugins.d /usr/lib/mandos \
		/etc/mandos/plugins.d /etc/mandos

purge: purge-server purge-client

purge-server: uninstall-server
	-rm --force /etc/mandos/mandos.conf /etc/mandos/clients.conf
	-rmdir /etc/mandos

purge-client: uninstall-client
	-rm --force /etc/mandos/seckey.txt /etc/mandos/pubkey.txt
	-rmdir /etc/mandos /etc/mandos/plugins.d
