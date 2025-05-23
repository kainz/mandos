WARN:=-O -Wall -Wextra -Wdouble-promotion -Wformat=2 -Winit-self \
	-Wmissing-include-dirs -Wswitch-default -Wswitch-enum \
	-Wunused -Wuninitialized -Wstrict-overflow=5 \
	-Wsuggest-attribute=pure -Wsuggest-attribute=const \
	-Wsuggest-attribute=noreturn -Wfloat-equal -Wundef -Wshadow \
	-Wunsafe-loop-optimizations -Wpointer-arith \
	-Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings \
	-Wconversion -Wlogical-op -Waggregate-return \
	-Wstrict-prototypes -Wold-style-definition \
	-Wmissing-format-attribute -Wnormalized=nfc -Wpacked \
	-Wredundant-decls -Wnested-externs -Winline -Wvla \
	-Wvolatile-register-var -Woverlength-strings

#DEBUG:=-ggdb3 -fsanitize=address $(SANITIZE)
## Check which sanitizing options can be used
#SANITIZE:=$(foreach option,$(ALL_SANITIZE_OPTIONS),$(shell \
#	echo 'int main(){}' | $(CC) --language=c $(option) \
#	/dev/stdin -o /dev/null >/dev/null 2>&1 && echo $(option)))
# <https://developerblog.redhat.com/2014/10/16/gcc-undefined-behavior-sanitizer-ubsan/>
ALL_SANITIZE_OPTIONS:=-fsanitize=leak -fsanitize=undefined \
        -fsanitize=shift -fsanitize=integer-divide-by-zero \
        -fsanitize=unreachable -fsanitize=vla-bound -fsanitize=null \
        -fsanitize=return -fsanitize=signed-integer-overflow \
        -fsanitize=bounds -fsanitize=alignment \
        -fsanitize=object-size -fsanitize=float-divide-by-zero \
        -fsanitize=float-cast-overflow -fsanitize=nonnull-attribute \
        -fsanitize=returns-nonnull-attribute -fsanitize=bool \
        -fsanitize=enum -fsanitize-address-use-after-scope

# For info about _FORTIFY_SOURCE, see feature_test_macros(7)
# and <https://gcc.gnu.org/ml/gcc-patches/2004-09/msg02055.html>.
FORTIFY:=-fstack-protector-all -fPIC
CPPFLAGS+=-D_FORTIFY_SOURCE=3
LINK_FORTIFY_LD:=-z relro -z now
LINK_FORTIFY:=

# If BROKEN_PIE is set, do not build with -pie
ifndef BROKEN_PIE
FORTIFY += -fPIE
LINK_FORTIFY += -pie
endif
#COVERAGE=--coverage
OPTIMIZE:=-Os -fno-strict-aliasing
LANGUAGE:=-std=gnu11
CPPFLAGS+=-D_FILE_OFFSET_BITS=64 -D_TIME_BITS=64
htmldir:=man
version:=1.8.18
SED:=sed
PKG_CONFIG?=pkg-config

USER:=$(firstword $(subst :, ,$(shell getent passwd _mandos \
	|| getent passwd nobody || echo 65534)))
GROUP:=$(firstword $(subst :, ,$(shell getent group _mandos \
	|| getent group nogroup || echo 65534)))

LINUXVERSION:=$(shell uname --kernel-release)

## Use these settings for a traditional /usr/local install
# PREFIX:=$(DESTDIR)/usr/local
# BINDIR:=$(PREFIX)/sbin
# CONFDIR:=$(DESTDIR)/etc/mandos
# KEYDIR:=$(DESTDIR)/etc/mandos/keys
# MANDIR:=$(PREFIX)/man
# INITRAMFSTOOLS:=$(DESTDIR)/etc/initramfs-tools
# DRACUTMODULE:=$(DESTDIR)/usr/lib/dracut/modules.d/90mandos
# STATEDIR:=$(DESTDIR)/var/lib/mandos
# LIBDIR:=$(PREFIX)/lib
# DBUSPOLICYDIR:=$(DESTDIR)/etc/dbus-1/system.d
##

## These settings are for a package-type install
PREFIX:=$(DESTDIR)/usr
BINDIR:=$(PREFIX)/sbin
CONFDIR:=$(DESTDIR)/etc/mandos
KEYDIR:=$(DESTDIR)/etc/keys/mandos
MANDIR:=$(PREFIX)/share/man
INITRAMFSTOOLS:=$(DESTDIR)/usr/share/initramfs-tools
DRACUTMODULE:=$(DESTDIR)/usr/lib/dracut/modules.d/90mandos
STATEDIR:=$(DESTDIR)/var/lib/mandos
LIBDIR:=$(shell \
	for d in \
	"/usr/lib/`dpkg-architecture \
			-qDEB_HOST_MULTIARCH 2>/dev/null`" \
	"`rpm --eval='%{_libdir}' 2>/dev/null`" /usr/lib; do \
		if [ -d "$$d" -a "$$d" = "$${d%/}" ]; then \
			echo "$(DESTDIR)$$d"; \
			break; \
		fi; \
	done)
DBUSPOLICYDIR:=$(DESTDIR)/usr/share/dbus-1/system.d
##

SYSTEMD:=$(DESTDIR)$(shell $(PKG_CONFIG) systemd \
			--variable=systemdsystemunitdir)
TMPFILES:=$(DESTDIR)$(shell $(PKG_CONFIG) systemd \
			--variable=tmpfilesdir)
SYSUSERS:=$(DESTDIR)$(shell $(PKG_CONFIG) systemd \
			--variable=sysusersdir)

GNUTLS_CFLAGS:=$(shell $(PKG_CONFIG) --cflags-only-I gnutls)
GNUTLS_LIBS:=$(shell $(PKG_CONFIG) --libs gnutls)
AVAHI_CFLAGS:=$(shell $(PKG_CONFIG) --cflags-only-I avahi-core)
AVAHI_LIBS:=$(shell $(PKG_CONFIG) --libs avahi-core)
GPGME_CFLAGS:=$(shell $(PKG_CONFIG) --cflags-only-I gpgme 2>/dev/null \
	|| gpgme-config --cflags; getconf LFS_CFLAGS)
GPGME_LIBS:=$(shell $(PKG_CONFIG) --libs gpgme 2>/dev/null \
	|| gpgme-config --libs; getconf LFS_LIBS; \
	getconf LFS_LDFLAGS)
LIBNL3_CFLAGS:=$(shell $(PKG_CONFIG) --cflags-only-I libnl-route-3.0)
LIBNL3_LIBS:=$(shell $(PKG_CONFIG) --libs libnl-route-3.0)
GLIB_CFLAGS:=$(shell $(PKG_CONFIG) --cflags glib-2.0)
GLIB_LIBS:=$(shell $(PKG_CONFIG) --libs glib-2.0)

# Do not change these two
CFLAGS+=$(WARN) $(DEBUG) $(FORTIFY) $(COVERAGE) $(OPTIMIZE) \
	$(LANGUAGE) -DVERSION='"$(version)"'
LDFLAGS+=-Xlinker --as-needed $(COVERAGE) $(LINK_FORTIFY) $(strip \
	) $(foreach flag,$(LINK_FORTIFY_LD),-Xlinker $(flag))

# Commands to format a DocBook <refentry> document into a manual page
DOCBOOKTOMAN=$(strip cd $(dir $<); xsltproc --nonet --xinclude \
	--param man.charmap.use.subset		0 \
	--param make.year.ranges		1 \
	--param make.single.year.ranges		1 \
	--param man.output.quietly		1 \
	--param man.authors.section.enabled	0 \
	/usr/share/xml/docbook/stylesheet/nwalsh/manpages/docbook.xsl \
	$(notdir $<); \
	if locale --all 2>/dev/null | grep --regexp='^en_US\.utf8$$' \
	&& command -v man >/dev/null; then LANG=en_US.UTF-8 \
	MANWIDTH=80 man --warnings --encoding=UTF-8 --local-file \
	$(notdir $@); fi >/dev/null)

DOCBOOKTOHTML=$(strip xsltproc --nonet --xinclude \
	--param make.year.ranges		1 \
	--param make.single.year.ranges		1 \
	--param man.output.quietly		1 \
	--param man.authors.section.enabled	0 \
	--param citerefentry.link		1 \
	--output $@ \
	/usr/share/xml/docbook/stylesheet/nwalsh/xhtml/docbook.xsl \
	$<; $(HTMLPOST) $@)
# Fix citerefentry links
HTMLPOST:=$(SED) --in-place \
	--expression='s/\(<a class="citerefentry" href="\)\("><span class="citerefentry"><span class="refentrytitle">\)\([^<]*\)\(<\/span>(\)\([^)]*\)\()<\/span><\/a>\)/\1\3.\5\2\3\4\5\6/g'

PLUGINS:=plugins.d/password-prompt plugins.d/mandos-client \
	plugins.d/usplash plugins.d/splashy plugins.d/askpass-fifo \
	plugins.d/plymouth
PLUGIN_HELPERS:=plugin-helpers/mandos-client-iprouteadddel
CPROGS:=plugin-runner dracut-module/password-agent $(PLUGINS) \
	$(PLUGIN_HELPERS)
PROGS:=mandos mandos-keygen mandos-ctl mandos-monitor $(CPROGS)
DOCS:=mandos.8 mandos-keygen.8 mandos-monitor.8 mandos-ctl.8 \
	mandos.conf.5 mandos-clients.conf.5 plugin-runner.8mandos \
	dracut-module/password-agent.8mandos \
	plugins.d/mandos-client.8mandos \
	plugins.d/password-prompt.8mandos plugins.d/usplash.8mandos \
	plugins.d/splashy.8mandos plugins.d/askpass-fifo.8mandos \
	plugins.d/plymouth.8mandos intro.8mandos

htmldocs:=$(addsuffix .xhtml,$(DOCS))

objects:=$(addsuffix .o,$(CPROGS))

.PHONY: all
all: $(PROGS) mandos.lsm

.PHONY: doc
doc: $(DOCS)

.PHONY: html
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

intro.8mandos: intro.xml common.ent legalnotice.xml
	$(DOCBOOKTOMAN)
intro.8mandos.xhtml: intro.xml common.ent legalnotice.xml
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

mandos-monitor.8: mandos-monitor.xml common.ent overview.xml \
		legalnotice.xml
	$(DOCBOOKTOMAN)
mandos-monitor.8.xhtml: mandos-monitor.xml common.ent overview.xml \
		 legalnotice.xml
	$(DOCBOOKTOHTML)

mandos-ctl.8: mandos-ctl.xml common.ent overview.xml \
		legalnotice.xml
	$(DOCBOOKTOMAN)
mandos-ctl.8.xhtml: mandos-ctl.xml common.ent overview.xml \
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

dracut-module/password-agent.8mandos: \
		dracut-module/password-agent.xml common.ent \
		overview.xml legalnotice.xml
	$(DOCBOOKTOMAN)
dracut-module/password-agent.8mandos.xhtml: \
		dracut-module/password-agent.xml common.ent \
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
	$(strip $(SED) --in-place \
		--expression='s/^\(<!ENTITY version "\)[^"]*">$$/\1$(version)">/' \
		$@)

mandos: Makefile
	$(strip $(SED) --in-place \
		--expression='s/^\(version = "\)[^"]*"$$/\1$(version)"/' \
		$@)

mandos-keygen: Makefile
	$(strip $(SED) --in-place \
		--expression='s/^\(VERSION="\)[^"]*"$$/\1$(version)"/' \
		$@)

mandos-ctl: Makefile
	$(strip $(SED) --in-place \
		--expression='s/^\(version = "\)[^"]*"$$/\1$(version)"/' \
		$@)

mandos-monitor: Makefile
	$(strip $(SED) --in-place \
		--expression='s/^\(version = "\)[^"]*"$$/\1$(version)"/' \
		$@)

mandos.lsm: Makefile
	$(strip $(SED) --in-place \
		--expression='s/^\(Version:\).*/\1\t$(version)/' \
		$@)
	$(strip $(SED) --in-place \
		--expression='s/^\(Entered-date:\).*/\1\t$(shell date --rfc-3339=date --reference=Makefile)/' \
		$@)
	$(strip $(SED) --in-place \
		--expression='s/\(mandos_\)[0-9.]\+\(\.orig\.tar\.gz\)/\1$(version)\2/' \
		$@)

# Does the linker support the --no-warn-execstack option?
ifeq ($(shell echo 'int main(){}'|$(CC) --language=c /dev/stdin -o /dev/null -Xlinker --no-warn-execstack >/dev/null 2>&1 && echo yes),yes)
# These programs use nested functions, which uses an executable stack
plugin-runner: LDFLAGS += -Xlinker --no-warn-execstack
dracut-module/password-agent: LDFLAGS += -Xlinker --no-warn-execstack
plugins.d/password-prompt: LDFLAGS += -Xlinker --no-warn-execstack
plugins.d/mandos-client: LDFLAGS += -Xlinker --no-warn-execstack
plugins.d/plymouth: LDFLAGS += -Xlinker --no-warn-execstack
endif

# Need to add the GnuTLS, Avahi and GPGME libraries
plugins.d/mandos-client: CFLAGS += $(GNUTLS_CFLAGS) $(strip \
	) $(AVAHI_CFLAGS) $(GPGME_CFLAGS)
plugins.d/mandos-client: LDLIBS += $(GNUTLS_LIBS) $(strip \
	) $(AVAHI_LIBS) $(GPGME_LIBS)

# Need to add the libnl-route library
plugin-helpers/mandos-client-iprouteadddel: CFLAGS += $(LIBNL3_CFLAGS)
plugin-helpers/mandos-client-iprouteadddel: LDLIBS += $(LIBNL3_LIBS)

# Need to add the GLib and pthread libraries
dracut-module/password-agent: CFLAGS += $(GLIB_CFLAGS)
# Note: -lpthread is unnecessary with the GNU C library 2.34 or later
dracut-module/password-agent: LDLIBS += $(GLIB_LIBS) -lpthread

.PHONY: clean
clean:
	-rm --force $(CPROGS) $(objects) $(htmldocs) $(DOCS) core

.PHONY: distclean
distclean: clean
.PHONY: mostlyclean
mostlyclean: clean
.PHONY: maintainer-clean
maintainer-clean: clean
	-rm --force --recursive keydir confdir statedir

.PHONY: check
check: all
	./mandos --check
	./mandos-ctl --check
	./mandos-keygen --version
	./plugin-runner --version
	./plugin-helpers/mandos-client-iprouteadddel --version
	./dracut-module/password-agent --test

# Run the client with a local config and key
.PHONY: run-client
run-client: all keydir/seckey.txt keydir/pubkey.txt \
			keydir/tls-privkey.pem keydir/tls-pubkey.pem
	@echo '######################################################'
	@echo '# The following error messages are harmless and can  #'
	@echo '#  be safely ignored:                                #'
	@echo '## From plugin-runner:                               #'
	@echo '# setgid: Operation not permitted                    #'
	@echo '# setuid: Operation not permitted                    #'
	@echo '## From askpass-fifo:                                #'
	@echo '# mkfifo: Permission denied                          #'
	@echo '## From mandos-client:                               #'
	@echo '# Failed to raise privileges: Operation not permi... #'
	@echo '# Warning: network hook "*" exited with status *     #'
	@echo '# ioctl SIOCSIFFLAGS +IFF_UP: Operation not permi... #'
	@echo '# Failed to bring up interface "*": Operation not... #'
	@echo '#                                                    #'
	@echo '# (The messages are caused by not running as root,   #'
	@echo '# but you should NOT run "make run-client" as root   #'
	@echo '# unless you also unpacked and compiled Mandos as    #'
	@echo '# root, which is also NOT recommended.)              #'
	@echo '######################################################'
# We set GNOME_KEYRING_CONTROL to block pam_gnome_keyring
	./plugin-runner --plugin-dir=plugins.d \
		--plugin-helper-dir=plugin-helpers \
		--config-file=plugin-runner.conf \
		--options-for=mandos-client:--seckey=keydir/seckey.txt,--pubkey=keydir/pubkey.txt,--tls-privkey=keydir/tls-privkey.pem,--tls-pubkey=keydir/tls-pubkey.pem,--network-hook-dir=network-hooks.d \
		--env-for=mandos-client:GNOME_KEYRING_CONTROL= \
		$(CLIENTARGS)

# Used by run-client
keydir/seckey.txt keydir/pubkey.txt keydir/tls-privkey.pem keydir/tls-pubkey.pem: mandos-keygen
	install --directory keydir
	./mandos-keygen --dir keydir --force
	if ! [ -e keydir/tls-privkey.pem ]; then \
		install --mode=u=rw /dev/null keydir/tls-privkey.pem; \
	fi
	if ! [ -e keydir/tls-pubkey.pem ]; then \
		install --mode=u=rw /dev/null keydir/tls-pubkey.pem; \
	fi

# Run the server with a local config
.PHONY: run-server
run-server: confdir/mandos.conf confdir/clients.conf statedir
	./mandos --debug --no-dbus --configdir=confdir \
		--statedir=statedir $(SERVERARGS)

# Used by run-server
confdir/mandos.conf: mandos.conf
	install -D --mode=u=rw,go=r $^ $@
confdir/clients.conf: clients.conf keydir/seckey.txt keydir/tls-pubkey.pem
	install -D --mode=u=rw $< $@
# Add a client password
	./mandos-keygen --dir keydir --password --no-ssh >> $@
statedir:
	install --directory statedir

.PHONY: install
install: install-server install-client-nokey

.PHONY: install-html
install-html: html
	install -D --mode=u=rw,go=r --target-directory=$(htmldir) \
		$(htmldocs)

.PHONY: install-server
install-server: doc
	if install --directory --mode=u=rwx --owner=$(USER) \
		--group=$(GROUP) $(STATEDIR); then \
		:; \
	elif install --directory --mode=u=rwx $(STATEDIR); then \
		chown -- $(USER):$(GROUP) $(STATEDIR) || :; \
	fi
	if [ "$(TMPFILES)" != "$(DESTDIR)" ]; then \
		install -D --mode=u=rw,go=r tmpfiles.d-mandos.conf \
			$(TMPFILES)/mandos.conf; \
	fi
	if [ "$(SYSUSERS)" != "$(DESTDIR)" ]; then \
		install -D --mode=u=rw,go=r sysusers.d-mandos.conf \
			$(SYSUSERS)/mandos.conf; \
	fi
	install --directory $(BINDIR)
	install --mode=u=rwx,go=rx --target-directory=$(BINDIR) mandos
	install --mode=u=rwx,go=rx --target-directory=$(BINDIR) \
		mandos-ctl
	install --mode=u=rwx,go=rx --target-directory=$(BINDIR) \
		mandos-monitor
	install --directory $(CONFDIR)
	install --mode=u=rw,go=r --target-directory=$(CONFDIR) \
		mandos.conf
	install --mode=u=rw --target-directory=$(CONFDIR) \
		clients.conf
	install -D --mode=u=rw,go=r dbus-mandos.conf \
		$(DBUSPOLICYDIR)/mandos.conf
	install -D --mode=u=rwx,go=rx init.d-mandos \
		$(DESTDIR)/etc/init.d/mandos
	if [ "$(SYSTEMD)" != "$(DESTDIR)" ]; then \
		install -D --mode=u=rw,go=r mandos.service \
			$(SYSTEMD); \
	fi
	install -D --mode=u=rw,go=r default-mandos \
		$(DESTDIR)/etc/default/mandos
	if [ -z $(DESTDIR) ]; then \
		update-rc.d mandos defaults 25 15;\
	fi
	install --directory $(MANDIR)/man8 $(MANDIR)/man5
	gzip --best --to-stdout mandos.8 \
		> $(MANDIR)/man8/mandos.8.gz
	gzip --best --to-stdout mandos-monitor.8 \
		> $(MANDIR)/man8/mandos-monitor.8.gz
	gzip --best --to-stdout mandos-ctl.8 \
		> $(MANDIR)/man8/mandos-ctl.8.gz
	gzip --best --to-stdout mandos.conf.5 \
		> $(MANDIR)/man5/mandos.conf.5.gz
	gzip --best --to-stdout mandos-clients.conf.5 \
		> $(MANDIR)/man5/mandos-clients.conf.5.gz
	gzip --best --to-stdout intro.8mandos \
		> $(MANDIR)/man8/intro.8mandos.gz

.PHONY: install-client-nokey
install-client-nokey: all doc
	install --directory --mode=u=rwx $(KEYDIR) \
		$(LIBDIR)/mandos/plugins.d \
		$(LIBDIR)/mandos/plugin-helpers
	if [ "$(SYSUSERS)" != "$(DESTDIR)" ]; then \
		install -D --mode=u=rw,go=r sysusers.d-mandos.conf \
			$(SYSUSERS)/mandos-client.conf; \
	fi
	if [ "$(CONFDIR)" != "$(LIBDIR)/mandos" ]; then \
		install --directory \
			--mode=u=rwx "$(CONFDIR)/plugins.d" \
			"$(CONFDIR)/plugin-helpers"; \
	fi
	install --directory --mode=u=rwx,go=rx \
		"$(CONFDIR)/network-hooks.d"
	install --mode=u=rwx,go=rx \
		--target-directory=$(LIBDIR)/mandos plugin-runner
	install --mode=u=rwx,go=rx \
		--target-directory=$(LIBDIR)/mandos \
		mandos-to-cryptroot-unlock
	install --directory $(BINDIR)
	install --mode=u=rwx,go=rx --target-directory=$(BINDIR) \
		mandos-keygen
	install --mode=u=rwx,go=rx \
		--target-directory=$(LIBDIR)/mandos/plugins.d \
		plugins.d/password-prompt
	install --mode=u=rwxs,go=rx \
		--target-directory=$(LIBDIR)/mandos/plugins.d \
		plugins.d/mandos-client
	install --mode=u=rwxs,go=rx \
		--target-directory=$(LIBDIR)/mandos/plugins.d \
		plugins.d/usplash
	install --mode=u=rwxs,go=rx \
		--target-directory=$(LIBDIR)/mandos/plugins.d \
		plugins.d/splashy
	install --mode=u=rwxs,go=rx \
		--target-directory=$(LIBDIR)/mandos/plugins.d \
		plugins.d/askpass-fifo
	install --mode=u=rwxs,go=rx \
		--target-directory=$(LIBDIR)/mandos/plugins.d \
		plugins.d/plymouth
	install --mode=u=rwx,go=rx \
		--target-directory=$(LIBDIR)/mandos/plugin-helpers \
		plugin-helpers/mandos-client-iprouteadddel
	install -D initramfs-tools-hook \
		$(INITRAMFSTOOLS)/hooks/mandos
	install -D --mode=u=rw,go=r initramfs-tools-conf \
		$(INITRAMFSTOOLS)/conf.d/mandos-conf
	install -D --mode=u=rw,go=r initramfs-tools-conf-hook \
		$(INITRAMFSTOOLS)/conf-hooks.d/zz-mandos
	install -D initramfs-tools-script \
		$(INITRAMFSTOOLS)/scripts/init-premount/mandos
	install -D initramfs-tools-script-stop \
		$(INITRAMFSTOOLS)/scripts/local-premount/mandos
	install -D --mode=u=rw,go=r \
		--target-directory=$(DRACUTMODULE) \
		dracut-module/ask-password-mandos.path \
		dracut-module/ask-password-mandos.service
	install --mode=u=rwxs,go=rx \
		--target-directory=$(DRACUTMODULE) \
		dracut-module/module-setup.sh \
		dracut-module/cmdline-mandos.sh \
		dracut-module/password-agent
	install --mode=u=rw,go=r plugin-runner.conf $(CONFDIR)
	install --directory $(MANDIR)/man8
	gzip --best --to-stdout mandos-keygen.8 \
		> $(MANDIR)/man8/mandos-keygen.8.gz
	gzip --best --to-stdout plugin-runner.8mandos \
		> $(MANDIR)/man8/plugin-runner.8mandos.gz
	gzip --best --to-stdout plugins.d/mandos-client.8mandos \
		> $(MANDIR)/man8/mandos-client.8mandos.gz
	gzip --best --to-stdout plugins.d/password-prompt.8mandos \
		> $(MANDIR)/man8/password-prompt.8mandos.gz
	gzip --best --to-stdout plugins.d/usplash.8mandos \
		> $(MANDIR)/man8/usplash.8mandos.gz
	gzip --best --to-stdout plugins.d/splashy.8mandos \
		> $(MANDIR)/man8/splashy.8mandos.gz
	gzip --best --to-stdout plugins.d/askpass-fifo.8mandos \
		> $(MANDIR)/man8/askpass-fifo.8mandos.gz
	gzip --best --to-stdout plugins.d/plymouth.8mandos \
		> $(MANDIR)/man8/plymouth.8mandos.gz
	gzip --best --to-stdout dracut-module/password-agent.8mandos \
		> $(MANDIR)/man8/password-agent.8mandos.gz

.PHONY: install-client
install-client: install-client-nokey
# Post-installation stuff
	-$(BINDIR)/mandos-keygen --dir "$(KEYDIR)"
	if command -v update-initramfs >/dev/null; then \
	    update-initramfs -k all -u; \
	elif command -v dracut >/dev/null; then \
	    for initrd in $(DESTDIR)/boot/initr*-$(LINUXVERSION); do \
		if [ -w "$$initrd" ]; then \
		    chmod go-r "$$initrd"; \
		    dracut --force "$$initrd"; \
		fi; \
	    done; \
	fi
	echo "Now run mandos-keygen --password --dir $(KEYDIR)"

.PHONY: uninstall
uninstall: uninstall-server uninstall-client

.PHONY: uninstall-server
uninstall-server:
	-rm --force $(BINDIR)/mandos \
		$(BINDIR)/mandos-ctl \
		$(BINDIR)/mandos-monitor \
		$(MANDIR)/man8/mandos.8.gz \
		$(MANDIR)/man8/mandos-monitor.8.gz \
		$(MANDIR)/man8/mandos-ctl.8.gz \
		$(MANDIR)/man5/mandos.conf.5.gz \
		$(MANDIR)/man5/mandos-clients.conf.5.gz
	update-rc.d -f mandos remove
	-rmdir $(CONFDIR)

.PHONY: uninstall-client
uninstall-client:
# Refuse to uninstall client if /etc/crypttab is explicitly configured
# to use it.
	! grep --regexp='^ *[^ #].*keyscript=[^,=]*/mandos/' \
		$(DESTDIR)/etc/crypttab
	-rm --force $(BINDIR)/mandos-keygen \
		$(LIBDIR)/mandos/plugin-runner \
		$(LIBDIR)/mandos/plugins.d/password-prompt \
		$(LIBDIR)/mandos/plugins.d/mandos-client \
		$(LIBDIR)/mandos/plugins.d/usplash \
		$(LIBDIR)/mandos/plugins.d/splashy \
		$(LIBDIR)/mandos/plugins.d/askpass-fifo \
		$(LIBDIR)/mandos/plugins.d/plymouth \
		$(INITRAMFSTOOLS)/hooks/mandos \
		$(INITRAMFSTOOLS)/conf-hooks.d/mandos \
		$(INITRAMFSTOOLS)/scripts/init-premount/mandos \
		$(INITRAMFSTOOLS)/scripts/local-premount/mandos \
		$(DRACUTMODULE)/ask-password-mandos.path \
		$(DRACUTMODULE)/ask-password-mandos.service \
		$(DRACUTMODULE)/module-setup.sh \
		$(DRACUTMODULE)/cmdline-mandos.sh \
		$(DRACUTMODULE)/password-agent \
		$(MANDIR)/man8/mandos-keygen.8.gz \
		$(MANDIR)/man8/plugin-runner.8mandos.gz \
		$(MANDIR)/man8/mandos-client.8mandos.gz
		$(MANDIR)/man8/password-prompt.8mandos.gz \
		$(MANDIR)/man8/usplash.8mandos.gz \
		$(MANDIR)/man8/splashy.8mandos.gz \
		$(MANDIR)/man8/askpass-fifo.8mandos.gz \
		$(MANDIR)/man8/plymouth.8mandos.gz \
		$(MANDIR)/man8/password-agent.8mandos.gz \
	-rmdir $(LIBDIR)/mandos/plugins.d $(CONFDIR)/plugins.d \
		 $(LIBDIR)/mandos $(CONFDIR) $(KEYDIR) $(DRACUTMODULE)
	if command -v update-initramfs >/dev/null; then \
	    update-initramfs -k all -u; \
	elif command -v dracut >/dev/null; then \
	    for initrd in $(DESTDIR)/boot/initr*-$(LINUXVERSION); do \
		test -w "$$initrd" && dracut --force "$$initrd"; \
	    done; \
	fi

.PHONY: purge
purge: purge-server purge-client

.PHONY: purge-server
purge-server: uninstall-server
	-rm --force $(CONFDIR)/mandos.conf $(CONFDIR)/clients.conf \
		$(DESTDIR)/etc/dbus-1/system.d/mandos.conf
		$(DESTDIR)/etc/default/mandos \
		$(DESTDIR)/etc/init.d/mandos \
		$(DESTDIR)/run/mandos.pid \
		$(DESTDIR)/var/run/mandos.pid
	if [ "$(SYSTEMD)" != "$(DESTDIR)" -a -d "$(SYSTEMD)" ]; then \
		-rm --force -- $(SYSTEMD)/mandos.service; \
	fi
	-rmdir $(CONFDIR)

.PHONY: purge-client
purge-client: uninstall-client
	-shred --remove $(KEYDIR)/seckey.txt $(KEYDIR)/tls-privkey.pem
	-rm --force $(CONFDIR)/plugin-runner.conf \
		$(KEYDIR)/pubkey.txt $(KEYDIR)/seckey.txt \
		$(KEYDIR)/tls-pubkey.txt $(KEYDIR)/tls-privkey.txt
	-rmdir $(KEYDIR) $(CONFDIR)/plugins.d $(CONFDIR)
