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
OPTIMIZE=-Os
LANGUAGE=-std=gnu99
# PREFIX=/usr/local
PREFIX=$(DESTDIR)/usr
# CONFDIR=/usr/local/lib/mandos
CONFDIR=$(DESTDIR)/etc/mandos
# MANDIR=/usr/local/man
MANDIR=$(DESTDIR)/usr/share/man

GNUTLS_CFLAGS=$(shell libgnutls-config --cflags)
GNUTLS_LIBS=$(shell libgnutls-config --libs)
AVAHI_CFLAGS=$(shell pkg-config --cflags-only-I avahi-core)
AVAHI_LIBS=$(shell pkg-config --libs avahi-core)
GPGME_CFLAGS=$(shell gpgme-config --cflags)
GPGME_LIBS=$(shell gpgme-config --libs)

# Do not change these two
CFLAGS=$(WARN) $(DEBUG) $(FORTIFY) $(COVERAGE) $(OPTIMIZE) \
	$(LANGUAGE) $(GNUTLS_CFLAGS) $(AVAHI_CFLAGS) $(GPGME_CFLAGS)
LDFLAGS=$(COVERAGE)

# Commands to format a DocBook refentry document into a manual page
DOCBOOKTOMAN=cd $(dir $<); xsltproc --nonet --xinclude \
	--param man.charmap.use.subset		0 \
	--param make.year.ranges		1 \
	--param make.single.year.ranges		1 \
	--param man.output.quietly		1 \
	--param man.authors.section.enabled	0 \
	 /usr/share/xml/docbook/stylesheet/nwalsh/manpages/docbook.xsl \
	$(notdir $<); \
	$(MANPOST) $(notdir $@)
# DocBook-to-man post-processing to fix a \n escape bug
MANPOST=sed --in-place --expression='s,\\\\en,\\en,g;s,\\n,\\en,g'

PLUGINS=plugins.d/password-prompt plugins.d/password-request
PROGS=plugin-runner $(PLUGINS)
DOCS=mandos.8 plugin-runner.8mandos mandos-keygen.8 \
	plugins.d/password-request.8mandos \
	plugins.d/password-prompt.8mandos mandos.conf.5 \
	mandos-clients.conf.5

objects=$(addsuffix .o,$(PROGS))

all: $(PROGS)

doc: $(DOCS)

%.5: %.xml legalnotice.xml
	$(DOCBOOKTOMAN)

%.8: %.xml legalnotice.xml
	$(DOCBOOKTOMAN)

%.8mandos: %.xml legalnotice.xml
	$(DOCBOOKTOMAN)

mandos.8: mandos.xml mandos-options.xml overview.xml legalnotice.xml
	$(DOCBOOKTOMAN)

mandos-keygen.8: mandos-keygen.xml overview.xml legalnotice.xml
	$(DOCBOOKTOMAN)

mandos.conf.5: mandos.conf.xml mandos-options.xml legalnotice.xml
	$(DOCBOOKTOMAN)

plugin-runner.8mandos: plugin-runner.xml overview.xml legalnotice.xml
	$(DOCBOOKTOMAN)

plugins.d/password-request.8mandos: plugins.d/password-request.xml \
					mandos-options.xml \
					overview.xml legalnotice.xml
	$(DOCBOOKTOMAN)

plugins.d/password-request: plugins.d/password-request.o
	$(LINK.o) $(GNUTLS_LIBS) $(AVAHI_LIBS) $(GPGME_LIBS) \
		$(COMMON) $^ $(LOADLIBES) $(LDLIBS) -o $@

.PHONY : all doc clean distclean run-client run-server install \
	install-server install-client uninstall uninstall-server \
	uninstall-client purge purge-server purge-client

clean:
	-rm --force $(PROGS) $(objects) $(DOCS) core

distclean: clean
mostlyclean: clean
maintainer-clean: clean
	-rm --force --recursive keydir confdir

check:
	./mandos --check

# Run the client with a local config and key
run-client: all keydir/seckey.txt keydir/pubkey.txt \
	keydir/secring.gpg keydir/pubring.gpg
	./plugin-runner --plugin-dir=plugins.d \
		--config-file=plugin-runner.conf \
		--options-for=password-request:--seckey=keydir/seckey.txt,--pubkey=keydir/pubkey.txt

# Used by run-client
keydir/secring.gpg: keydir/seckey.txt
	gpg --homedir $(dir $<) --import $^
keydir/pubring.gpg: keydir/pubkey.txt
	gpg --homedir $(dir $<) --import $^
keydir/seckey.txt keydir/pubkey.txt: mandos-keygen
	install --directory keydir
	./mandos-keygen --dir keydir --force

# Run the server with a local config
run-server: confdir/mandos.conf confdir/clients.conf
	./mandos --debug --configdir=confdir

# Used by run-server
confdir/mandos.conf: mandos.conf
	install --directory confdir
	install $^ $@
confdir/clients.conf: clients.conf keydir/seckey.txt
	install --directory confdir
	install clients.conf $@
# Add a client password
	./mandos-keygen --dir keydir --password >> $@

install: install-server install-client

install-server: doc
	install --directory --parents $(CONFDIR) $(MANDIR)/man5 \
		$(MANDIR)/man8
	install --mode=0755 mandos $(PREFIX)/sbin/mandos
	install --mode=0644 --target-directory=$(CONFDIR) mandos.conf
	install --mode=0640 --target-directory=$(CONFDIR) \
		clients.conf
	gzip --best --to-stdout mandos.8 \
		> $(MANDIR)/man8/mandos.8.gz
	gzip --best --to-stdout mandos.conf.5 \
		> $(MANDIR)/man5/mandos.conf.5.gz
	gzip --best --to-stdout mandos-clients.conf.5 \
		> $(MANDIR)/man5/mandos-clients.conf.5.gz

install-client: all doc /usr/share/initramfs-tools/hooks/.
	install --directory --parents $(PREFIX)/lib/mandos \
		$(CONFDIR) $(MANDIR)/man8
	install --directory --mode=0700 $(PREFIX)/lib/mandos/plugins.d
	chmod u=rwx,g=,o= $(PREFIX)/lib/mandos/plugins.d
	install --mode=0755 --target-directory=$(PREFIX)/lib/mandos \
		plugin-runner
	install --mode=0755 --target-directory=$(PREFIX)/sbin \
		mandos-keygen
	install --mode=0755 \
		--target-directory=$(PREFIX)/lib/mandos/plugins.d \
		plugins.d/password-prompt
	install --mode=4755 \
		--target-directory=$(PREFIX)/lib/mandos/plugins.d \
		plugins.d/password-request
	install initramfs-tools-hook \
		/usr/share/initramfs-tools/hooks/mandos
	install initramfs-tools-hook-conf \
		/usr/share/initramfs-tools/conf-hooks.d/mandos
	install initramfs-tools-script \
		/usr/share/initramfs-tools/scripts/local-top/mandos
	gzip --best --to-stdout mandos-keygen.8 \
		> $(MANDIR)/man8/mandos-keygen.8.gz
	gzip --best --to-stdout plugin-runner.8mandos \
		> $(MANDIR)/man8/plugin-runner.8mandos.gz
	gzip --best --to-stdout plugins.d/password-prompt.8mandos \
		> $(MANDIR)/man8/password-prompt.8mandos.gz
	gzip --best --to-stdout plugins.d/password-request.8mandos \
		> $(MANDIR)/man8/password-request.8mandos.gz
	-$(PREFIX)/sbin/mandos-keygen
	update-initramfs -k all -u

uninstall: uninstall-server uninstall-client

uninstall-server: $(PREFIX)/sbin/mandos
	-rm --force $(PREFIX)/sbin/mandos \
		$(MANDIR)/man8/mandos.8.gz \
		$(MANDIR)/man5/mandos.conf.5.gz \
		$(MANDIR)/man5/mandos-clients.conf.5.gz
	-rmdir $(CONFDIR)

uninstall-client:
# Refuse to uninstall client if /etc/crypttab is explicitly configured
# to use it.
	! grep --regexp='^ *[^ #].*keyscript=[^,=]*/mandos/' \
		/etc/crypttab
	-rm --force $(PREFIX)/sbin/mandos-keygen \
		$(PREFIX)/lib/mandos/plugin-runner \
		$(PREFIX)/lib/mandos/plugins.d/password-prompt \
		$(PREFIX)/lib/mandos/plugins.d/password-request \
		/usr/share/initramfs-tools/hooks/mandos \
		/usr/share/initramfs-tools/conf-hooks.d/mandos \
		$(MANDIR)/man8/plugin-runner.8mandos.gz \
		$(MANDIR)/man8/mandos-keygen.8.gz \
		$(MANDIR)/man8/password-prompt.8mandos.gz \
		$(MANDIR)/man8/password-request.8mandos.gz
	-rmdir $(PREFIX)/lib/mandos/plugins.d $(CONFDIR)/plugins.d \
		 $(PREFIX)/lib/mandos $(CONFDIR)
	update-initramfs -k all -u

purge: purge-server purge-client

purge-server: uninstall-server
	-rm --force $(CONFDIR)/mandos.conf $(CONFDIR)/clients.conf
	-rmdir $(CONFDIR)

purge-client: uninstall-client
	-rm --force $(CONFDIR)/seckey.txt $(CONFDIR)/pubkey.txt
	-rmdir $(CONFDIR) $(CONFDIR)/plugins.d
