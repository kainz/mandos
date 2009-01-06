WARN=-O -Wall -Wformat=2 -Winit-self -Wmissing-include-dirs \
	-Wswitch-default -Wswitch-enum -Wunused-parameter \
	-Wstrict-aliasing=2 -Wextra -Wfloat-equal -Wundef -Wshadow \
	-Wunsafe-loop-optimizations -Wpointer-arith \
	-Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings \
	-Wconversion -Wstrict-prototypes -Wold-style-definition \
	-Wpacked -Wnested-externs -Winline -Wvolatile-register-var
#	-Wunreachable-code 
#DEBUG=-ggdb3
# For info about _FORTIFY_SOURCE, see
# <http://gcc.gnu.org/ml/gcc-patches/2004-09/msg02055.html>
FORTIFY=-D_FORTIFY_SOURCE=2 -fstack-protector-all -fPIE -pie
LINK_FORTIFY=-z relro -pie
#COVERAGE=--coverage
OPTIMIZE=-Os
LANGUAGE=-std=gnu99
htmldir=man
version=1.0.3
SED=sed

## Use these settings for a traditional /usr/local install
# PREFIX=$(DESTDIR)/usr/local
# CONFDIR=$(DESTDIR)/etc/mandos
# KEYDIR=$(DESTDIR)/etc/mandos/keys
# MANDIR=$(PREFIX)/man
# INITRAMFSTOOLS=$(DESTDIR)/etc/initramfs-tools
##

## These settings are for a package-type install
PREFIX=$(DESTDIR)/usr
CONFDIR=$(DESTDIR)/etc/mandos
KEYDIR=$(DESTDIR)/etc/keys/mandos
MANDIR=$(PREFIX)/share/man
INITRAMFSTOOLS=$(DESTDIR)/usr/share/initramfs-tools
##

GNUTLS_CFLAGS=$(shell libgnutls-config --cflags)
GNUTLS_LIBS=$(shell libgnutls-config --libs)
AVAHI_CFLAGS=$(shell pkg-config --cflags-only-I avahi-core)
AVAHI_LIBS=$(shell pkg-config --libs avahi-core)
GPGME_CFLAGS=$(shell gpgme-config --cflags)
GPGME_LIBS=$(shell gpgme-config --libs)

# Do not change these two
CFLAGS=$(WARN) $(DEBUG) $(FORTIFY) $(COVERAGE) $(OPTIMIZE) \
	$(LANGUAGE) $(GNUTLS_CFLAGS) $(AVAHI_CFLAGS) $(GPGME_CFLAGS) \
	-DVERSION='"$(version)"'
LDFLAGS=$(COVERAGE) $(foreach flag,$(LINK_FORTIFY),-Xlinker $(flag))

# Commands to format a DocBook <refentry> document into a manual page
DOCBOOKTOMAN=cd $(dir $<); xsltproc --nonet --xinclude \
	--param man.charmap.use.subset		0 \
	--param make.year.ranges		1 \
	--param make.single.year.ranges		1 \
	--param man.output.quietly		1 \
	--param man.authors.section.enabled	0 \
	 /usr/share/xml/docbook/stylesheet/nwalsh/manpages/docbook.xsl \
	$(notdir $<); \
	$(MANPOST) $(notdir $@)
# DocBook-to-man post-processing to fix a '\n' escape bug
MANPOST=$(SED) --in-place --expression='s,\\\\en,\\en,g;s,\\n,\\en,g'

DOCBOOKTOHTML=xsltproc --nonet --xinclude \
	--param make.year.ranges		1 \
	--param make.single.year.ranges		1 \
	--param man.output.quietly		1 \
	--param man.authors.section.enabled	0 \
	--param citerefentry.link		1 \
	--output $@ \
	/usr/share/xml/docbook/stylesheet/nwalsh/xhtml/docbook.xsl \
	$<; $(HTMLPOST) $@
# Fix citerefentry links
HTMLPOST=$(SED) --in-place \
	--expression='s/\(<a class="citerefentry" href="\)\("><span class="citerefentry"><span class="refentrytitle">\)\([^<]*\)\(<\/span>(\)\([^)]*\)\()<\/span><\/a>\)/\1\3.\5\2\3\4\5\6/g'

PLUGINS=plugins.d/password-prompt plugins.d/mandos-client \
	plugins.d/usplash plugins.d/splashy plugins.d/askpass-fifo
CPROGS=plugin-runner $(PLUGINS)
PROGS=mandos mandos-keygen mandos-list $(CPROGS)
DOCS=mandos.8 plugin-runner.8mandos mandos-keygen.8 \
	plugins.d/mandos-client.8mandos \
	plugins.d/password-prompt.8mandos mandos.conf.5 \
	plugins.d/usplash.8mandos plugins.d/splashy.8mandos \
	plugins.d/askpass-fifo.8mandos mandos-clients.conf.5

htmldocs=$(addsuffix .xhtml,$(DOCS))

objects=$(addsuffix .o,$(CPROGS))

all: $(PROGS) mandos.lsm

doc: $(DOCS)

html: $(htmldocs)

%.5: %.xml common.ent legalnotice.xml
	$(DOCBOOKTOMAN)
%.5.xhtml: %.xml common.ent legalnotice.xml
	$(DOCBOOKTOHTML)

%.8: %.xml common.ent legalnotice.xml
	$(DOCBOOKTOMAN)
%.8.xhtml: %.xml common.ent legalnotice.xml
	$(DOCBOOKTOHTML)

%.8mandos: %.xml common.ent legalnotice.xml
	$(DOCBOOKTOMAN)
%.8mandos.xhtml: %.xml common.ent legalnotice.xml
	$(DOCBOOKTOHTML)

mandos.8: mandos.xml common.ent mandos-options.xml overview.xml \
		legalnotice.xml
	$(DOCBOOKTOMAN)
mandos.8.xhtml: mandos.xml common.ent mandos-options.xml \
		overview.xml legalnotice.xml
	$(DOCBOOKTOHTML)

mandos-keygen.8: mandos-keygen.xml common.ent overview.xml \
		legalnotice.xml
	$(DOCBOOKTOMAN)
mandos-keygen.8.xhtml: mandos-keygen.xml common.ent overview.xml \
		 legalnotice.xml
	$(DOCBOOKTOHTML)

mandos.conf.5: mandos.conf.xml common.ent mandos-options.xml \
		legalnotice.xml
	$(DOCBOOKTOMAN)
mandos.conf.5.xhtml: mandos.conf.xml common.ent mandos-options.xml \
		legalnotice.xml
	$(DOCBOOKTOHTML)

plugin-runner.8mandos: plugin-runner.xml common.ent overview.xml \
		legalnotice.xml
	$(DOCBOOKTOMAN)
plugin-runner.8mandos.xhtml: plugin-runner.xml common.ent \
		overview.xml legalnotice.xml
	$(DOCBOOKTOHTML)

plugins.d/mandos-client.8mandos: plugins.d/mandos-client.xml \
					common.ent \
					mandos-options.xml \
					overview.xml legalnotice.xml
	$(DOCBOOKTOMAN)
plugins.d/mandos-client.8mandos.xhtml: plugins.d/mandos-client.xml \
					common.ent \
					mandos-options.xml \
					overview.xml legalnotice.xml
	$(DOCBOOKTOHTML)

# Update all these files with version number $(version)
common.ent: Makefile
	$(SED) --in-place \
		--expression='s/^\(<ENTITY VERSION "\)[^"]*">$$/\1$(version)"/' \
		$@

mandos: Makefile
	$(SED) --in-place \
		--expression='s/^\(version = "\)[^"]*"$$/\1$(version)"/' \
		$@

mandos-keygen: Makefile
	$(SED) --in-place \
		--expression='s/^\(VERSION="\)[^"]*"$$/\1$(version)"/' \
		$@

mandos-list: Makefile
	$(SED) --in-place \
		--expression='s/^\(version = "\)[^"]*"$$/\1$(version)"/' \
		$@

mandos.lsm: Makefile
	$(SED) --in-place \
		--expression='s/^\(Version:\).*/\1\t$(version)/' \
		$@
	$(SED) --in-place \
		--expression='s/^\(Entered-date:\).*/\1\t$(shell date --rfc-3339=date --reference=Makefile)/' \
		$@

plugins.d/mandos-client: plugins.d/mandos-client.o
	$(LINK.o) $(GNUTLS_LIBS) $(AVAHI_LIBS) $(GPGME_LIBS) \
		$(COMMON) $^ $(LOADLIBES) $(LDLIBS) -o $@

.PHONY : all doc html clean distclean run-client run-server install \
	install-server install-client uninstall uninstall-server \
	uninstall-client purge purge-server purge-client

clean:
	-rm --force $(CPROGS) $(objects) $(htmldocs) $(DOCS) core

distclean: clean
mostlyclean: clean
maintainer-clean: clean
	-rm --force --recursive keydir confdir

check:	all
	./mandos --check

# Run the client with a local config and key
run-client: all keydir/seckey.txt keydir/pubkey.txt
	./plugin-runner --plugin-dir=plugins.d \
		--config-file=plugin-runner.conf \
		--options-for=mandos-client:--seckey=keydir/seckey.txt,--pubkey=keydir/pubkey.txt

# Used by run-client
keydir/seckey.txt keydir/pubkey.txt: mandos-keygen
	install --directory keydir
	./mandos-keygen --dir keydir --force

# Run the server with a local config
run-server: confdir/mandos.conf confdir/clients.conf
	./mandos --debug --configdir=confdir

# Used by run-server
confdir/mandos.conf: mandos.conf
	install --directory confdir
	install --mode=u=rw,go=r $^ $@
confdir/clients.conf: clients.conf keydir/seckey.txt
	install --directory confdir
	install --mode=u=rw $< $@
# Add a client password
	./mandos-keygen --dir keydir --password >> $@

install: install-server install-client-nokey

install-html: html
	install --directory $(htmldir)
	install --mode=u=rw,go=r --target-directory=$(htmldir) \
		$(htmldocs)

install-server: doc
	install --directory $(CONFDIR)
	install --mode=u=rwx,go=rx mandos $(PREFIX)/sbin/mandos
	install --mode=u=rw,go=r --target-directory=$(CONFDIR) \
		mandos.conf
	install --mode=u=rw --target-directory=$(CONFDIR) \
		clients.conf
	install --mode=u=rwx,go=rx init.d-mandos \
		$(DESTDIR)/etc/init.d/mandos
	install --mode=u=rw,go=r default-mandos \
		$(DESTDIR)/etc/default/mandos
	if [ -z $(DESTDIR) ]; then \
		update-rc.d mandos defaults 25 15;\
	fi
	gzip --best --to-stdout mandos.8 \
		> $(MANDIR)/man8/mandos.8.gz
	gzip --best --to-stdout mandos.conf.5 \
		> $(MANDIR)/man5/mandos.conf.5.gz
	gzip --best --to-stdout mandos-clients.conf.5 \
		> $(MANDIR)/man5/mandos-clients.conf.5.gz

install-client-nokey: all doc
	install --directory $(PREFIX)/lib/mandos $(CONFDIR)
	install --directory --mode=u=rwx $(KEYDIR) \
		$(PREFIX)/lib/mandos/plugins.d
	if [ "$(CONFDIR)" != "$(PREFIX)/lib/mandos" ]; then \
		install --mode=u=rwx \
			--directory "$(CONFDIR)/plugins.d"; \
	fi
	install --mode=u=rwx,go=rx \
		--target-directory=$(PREFIX)/lib/mandos plugin-runner
	install --mode=u=rwx,go=rx --target-directory=$(PREFIX)/sbin \
		mandos-keygen
	install --mode=u=rwx,go=rx \
		--target-directory=$(PREFIX)/lib/mandos/plugins.d \
		plugins.d/password-prompt
	install --mode=u=rwxs,go=rx \
		--target-directory=$(PREFIX)/lib/mandos/plugins.d \
		plugins.d/mandos-client
	install --mode=u=rwxs,go=rx \
		--target-directory=$(PREFIX)/lib/mandos/plugins.d \
		plugins.d/usplash
	install --mode=u=rwxs,go=rx \
		--target-directory=$(PREFIX)/lib/mandos/plugins.d \
		plugins.d/splashy
	install --mode=u=rwxs,go=rx \
		--target-directory=$(PREFIX)/lib/mandos/plugins.d \
		plugins.d/askpass-fifo
	install initramfs-tools-hook \
		$(INITRAMFSTOOLS)/hooks/mandos
	install --mode=u=rw,go=r initramfs-tools-hook-conf \
		$(INITRAMFSTOOLS)/conf-hooks.d/mandos
	install initramfs-tools-script \
		$(INITRAMFSTOOLS)/scripts/local-top/mandos
	install --mode=u=rw,go=r plugin-runner.conf $(CONFDIR)
	gzip --best --to-stdout mandos-keygen.8 \
		> $(MANDIR)/man8/mandos-keygen.8.gz
	gzip --best --to-stdout plugin-runner.8mandos \
		> $(MANDIR)/man8/plugin-runner.8mandos.gz
	gzip --best --to-stdout plugins.d/password-prompt.8mandos \
		> $(MANDIR)/man8/password-prompt.8mandos.gz
	gzip --best --to-stdout plugins.d/mandos-client.8mandos \
		> $(MANDIR)/man8/mandos-client.8mandos.gz
	gzip --best --to-stdout plugins.d/usplash.8mandos \
		> $(MANDIR)/man8/usplash.8mandos.gz
	gzip --best --to-stdout plugins.d/splashy.8mandos \
		> $(MANDIR)/man8/splashy.8mandos.gz
	gzip --best --to-stdout plugins.d/askpass-fifo.8mandos \
		> $(MANDIR)/man8/askpass-fifo.8mandos.gz

install-client: install-client-nokey
# Post-installation stuff
	-$(PREFIX)/sbin/mandos-keygen --dir "$(KEYDIR)"
	update-initramfs -k all -u
	echo "Now run mandos-keygen --password --dir $(KEYDIR)"

uninstall: uninstall-server uninstall-client

uninstall-server:
	-rm --force $(PREFIX)/sbin/mandos \
		$(MANDIR)/man8/mandos.8.gz \
		$(MANDIR)/man5/mandos.conf.5.gz \
		$(MANDIR)/man5/mandos-clients.conf.5.gz
	update-rc.d -f mandos remove
	-rmdir $(CONFDIR)

uninstall-client:
# Refuse to uninstall client if /etc/crypttab is explicitly configured
# to use it.
	! grep --regexp='^ *[^ #].*keyscript=[^,=]*/mandos/' \
		$(DESTDIR)/etc/crypttab
	-rm --force $(PREFIX)/sbin/mandos-keygen \
		$(PREFIX)/lib/mandos/plugin-runner \
		$(PREFIX)/lib/mandos/plugins.d/password-prompt \
		$(PREFIX)/lib/mandos/plugins.d/mandos-client \
		$(PREFIX)/lib/mandos/plugins.d/usplash \
		$(PREFIX)/lib/mandos/plugins.d/splashy \
		$(PREFIX)/lib/mandos/plugins.d/askpass-fifo \
		$(INITRAMFSTOOLS)/hooks/mandos \
		$(INITRAMFSTOOLS)/conf-hooks.d/mandos \
		$(INITRAMFSTOOLS)/scripts/local-top/mandos \
		$(MANDIR)/man8/plugin-runner.8mandos.gz \
		$(MANDIR)/man8/mandos-keygen.8.gz \
		$(MANDIR)/man8/password-prompt.8mandos.gz \
		$(MANDIR)/man8/usplash.8mandos.gz \
		$(MANDIR)/man8/splashy.8mandos.gz \
		$(MANDIR)/man8/askpass-fifo.8mandos.gz \
		$(MANDIR)/man8/mandos-client.8mandos.gz
	-rmdir $(PREFIX)/lib/mandos/plugins.d $(CONFDIR)/plugins.d \
		 $(PREFIX)/lib/mandos $(CONFDIR) $(KEYDIR)
	update-initramfs -k all -u

purge: purge-server purge-client

purge-server: uninstall-server
	-rm --force $(CONFDIR)/mandos.conf $(CONFDIR)/clients.conf \
		$(DESTDIR)/etc/default/mandos \
		$(DESTDIR)/etc/init.d/mandos \
		$(DESTDIR)/var/run/mandos.pid
	-rmdir $(CONFDIR)

purge-client: uninstall-client
	-shred --remove $(KEYDIR)/seckey.txt
	-rm --force $(CONFDIR)/plugin-runner.conf \
		$(KEYDIR)/pubkey.txt $(KEYDIR)/seckey.txt
	-rmdir $(KEYDIR) $(CONFDIR)/plugins.d $(CONFDIR)
