#!/bin/sh
#
# This file should be present in the root file system directory
# /usr/lib/dracut/modules.d/90mandos.  When dracut creates the
# initramfs image, dracut will source this file and run the shell
# functions defined in this file: "install", "check", "depends",
# "cmdline", and "installkernel".
# 
# Despite the above #!/bin/sh line and the executable flag, this file
# is not executed; this file is sourced by dracut when creating the
# initramfs image file.

mandos_libdir(){
    for dir in /usr/lib \
	"/usr/lib/`dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null`" \
	"`rpm --eval='%{_libdir}' 2>/dev/null`" /usr/local/lib; do
	if [ -d "$dir"/mandos ]; then
	    echo "$dir"/mandos
	    return
	fi
    done
    # Mandos not found
    return 1
}

mandos_keydir(){
    for dir in /etc/keys/mandos /etc/mandos/keys; do
	if [ -d "$dir" ]; then
	    echo "$dir"
	    return
	fi
    done
    # Mandos key directory not found
    return 1
}

check(){
    if [ "${hostonly:-no}" = "no" ]; then
	dwarning "Mandos: Dracut not in hostonly mode"
	return 1
    fi

    local libdir=`mandos_libdir`
    if [ -z "$libdir" ]; then
	dwarning "Mandos lib directory not found"
	return 1
    fi

    local keydir=`mandos_keydir`
    if [ -z "$keydir" ]; then
	dwarning "Mandos key directory not found"
	return 1
    fi
}

install(){
    chmod go+w,+t "$initdir"/tmp
    local libdir=`mandos_libdir`
    local keydir=`mandos_keydir`
    set `{ getent passwd _mandos \
	|| getent passwd nobody \
	|| echo ::65534:65534:::; } \
	| cut --delimiter=: --fields=3,4 --only-delimited \
	--output-delimiter=" "`
    local mandos_user="$1"
    local mandos_group="$2"
    inst "${libdir}" /lib/mandos
    if dracut_module_included "systemd"; then
	plugindir=/lib/mandos
	inst "${libdir}/plugins.d/mandos-client" \
	     "${plugindir}/mandos-client"
	chmod u-s "${initdir}/${plugindir}/mandos-client"
	inst "${moddir}/ask-password-mandos.service" \
	     "${systemdsystemunitdir}/ask-password-mandos.service"
	if [ ${mandos_user} != 65534 ]; then
	    sed --in-place \
		--expression="s,^ExecStart=/lib/mandos/password-agent ,&--user=${mandos_user} ," \
		"${initdir}/${systemdsystemunitdir}/ask-password-mandos.service"
	fi
	if [ ${mandos_group} != 65534 ]; then
	    sed --in-place \
		--expression="s,^ExecStart=/lib/mandos/password-agent ,&--group=${mandos_group} ," \
		"${initdir}/${systemdsystemunitdir}/ask-password-mandos.service"
	fi
    else
	inst_hook cmdline 20 "$moddir"/cmdline-mandos.sh
	plugindir=/lib/mandos/plugins.d
	inst "${libdir}/plugin-runner" /lib/mandos/plugin-runner
	inst /etc/mandos/plugin-runner.conf
	sed --in-place \
	    --expression='1i--options-for=mandos-client:--pubkey=/etc/mandos/keys/pubkey.txt,--seckey=/etc/mandos/keys/seckey.txt,--tls-pubkey=/etc/mandos/keys/tls-pubkey.pem,--tls-privkey=/etc/mandos/keys/tls-privkey.pem' \
	    "${initdir}/etc/mandos/plugin-runner.conf"
	if [ ${mandos_user} != 65534 ]; then
	    sed --in-place --expression="1i--userid=${mandos_user}" \
		"${initdir}/etc/mandos/plugin-runner.conf"
	fi
	if [ ${mandos_group} != 65534 ]; then
	    sed --in-place \
		--expression="1i--groupid=${mandos_group}" \
		"${initdir}/etc/mandos/plugin-runner.conf"
	fi
	inst "${libdir}/plugins.d" "$plugindir"
	chown ${mandos_user}:${mandos_group} "${initdir}/${plugindir}"
	# Copy the packaged plugins
	for file in "$libdir"/plugins.d/*; do
	    base="`basename \"$file\"`"
	    # Is this plugin overridden?
	    if [ -e "/etc/mandos/plugins.d/$base" ]; then
		continue
	    fi
	    case "$base" in
		*~|.*|\#*\#|*.dpkg-old|*.dpkg-bak|*.dpkg-new|*.dpkg-divert)
		    : ;;
		"*") dwarning "Mandos client plugin directory is empty." >&2 ;;
		askpass-fifo) : ;; # Ignore packaged for dracut
		*) inst "${file}" "${plugindir}/${base}" ;;
	    esac
	done
	# Copy any user-supplied plugins
	for file in /etc/mandos/plugins.d/*; do
	    base="`basename \"$file\"`"
	    case "$base" in
		*~|.*|\#*\#|*.dpkg-old|*.dpkg-bak|*.dpkg-new|*.dpkg-divert)
		    : ;;
		"*") : ;;
		*) inst "$file" "${plugindir}/${base}" ;;
	    esac
	done
	# Copy any user-supplied plugin helpers
	for file in /etc/mandos/plugin-helpers/*; do
	    base="`basename \"$file\"`"
	    case "$base" in
		*~|.*|\#*\#|*.dpkg-old|*.dpkg-bak|*.dpkg-new|*.dpkg-divert)
		    : ;;
		"*") : ;;
		*) inst "$file" "/lib/mandos/plugin-helpers/$base";;
	    esac
	done
    fi
    # Copy network hooks
    for hook in /etc/mandos/network-hooks.d/*; do
	basename=`basename "$hook"`
	case "$basename" in
	    "*") continue ;;
	    *[!A-Za-z0-9_.-]*) continue ;;
	    *) test -d "$hook" || inst "$hook" "/lib/mandos/network-hooks.d/$basename" ;;
	esac
	if [ -x "$hook" ]; then
	    # Copy any files needed by the network hook
	    MANDOSNETHOOKDIR=/etc/mandos/network-hooks.d MODE=files \
		VERBOSITY=0 "$hook" files | while read file target; do
		if [ ! -e "${file}" ]; then
		    dwarning "WARNING: file ${file} not found, requested by Mandos network hook '${basename}'" >&2
		fi
		if [ -z "${target}" ]; then
		    inst "$file"
		else
		    inst "$file" "$target"
		fi
	    done
	fi
    done
    # Copy the packaged plugin helpers
    for file in "$libdir"/plugin-helpers/*; do
	base="`basename \"$file\"`"
	# Is this plugin overridden?
	if [ -e "/etc/mandos/plugin-helpers/$base" ]; then
	    continue
	fi
	case "$base" in
	    *~|.*|\#*\#|*.dpkg-old|*.dpkg-bak|*.dpkg-new|*.dpkg-divert)
		: ;;
	    "*") : ;;
	    *) inst "$file" "/lib/mandos/plugin-helpers/$base";;
	esac
    done
    local gpg=/usr/bin/gpg
    if [ -e /usr/bin/gpgconf ]; then
	inst /usr/bin/gpgconf
	gpg="`/usr/bin/gpgconf|sed --quiet --expression='s/^gpg:[^:]*://p'`"
	gpgagent="`/usr/bin/gpgconf|sed --quiet --expression='s/^gpg-agent:[^:]*://p'`"
	# Newer versions of GnuPG 2 requires the gpg-agent binary
	if [ -e "$gpgagent" ]; then
	    inst "$gpgagent"
	fi
    fi
    inst "$gpg"
    if dracut_module_included "systemd"; then
	inst "${moddir}/password-agent" /lib/mandos/password-agent
	inst "${moddir}/ask-password-mandos.path" \
	     "${systemdsystemunitdir}/ask-password-mandos.path"
	ln_r "${systemdsystemunitdir}/ask-password-mandos.path" \
	     "${systemdsystemunitdir}/sysinit.target.wants/ask-password-mandos.path"
    fi
    # Key files
    for file in "$keydir"/*; do
	if [ -d "$file" ]; then
	    continue
	fi
	case "$file" in
	    *~|.*|\#*\#|*.dpkg-old|*.dpkg-bak|*.dpkg-new|*.dpkg-divert)
		: ;;
	    "*") : ;;
	    *)
		inst "$file" "/etc/mandos/keys/`basename \"$file\"`"
		chown ${mandos_user}:${mandos_group} \
		      "${initdir}/etc/mandos/keys/`basename \"$file\"`"
		if [ `basename "$file"` = dhparams.pem ]; then
		    # Use Diffie-Hellman parameters file
		    if dracut_module_included "systemd"; then
			sed --in-place \
			    --expression='/^ExecStart/s/$/ --dh-params=\/etc\/mandos\/keys\/dhparams.pem/' \
			    "${initdir}/${systemdsystemunitdir}/ask-password-mandos.service"
		    else
			sed --in-place \
			    --expression="1i--options-for=mandos-client:--dh-params=/etc/mandos/keys/dhparams.pem" \
			    "${initdir}/etc/mandos/plugin-runner.conf"
		    fi
		fi
		;;
	esac
    done
}

installkernel(){
    instmods =drivers/net
    hostonly='' instmods ipv6
    # Copy any kernel modules needed by network hooks
    for hook in /etc/mandos/network-hooks.d/*; do
	basename=`basename "$hook"`
	case "$basename" in
	    "*") continue ;;
	    *[!A-Za-z0-9_.-]*) continue ;;
	esac
	if [ -x "$hook" ]; then
	    # Copy and load any modules needed by the network hook
	    MANDOSNETHOOKDIR=/etc/mandos/network-hooks.d MODE=modules \
		VERBOSITY=0 "$hook" modules | while read module; do
		if [ -z "${target}" ]; then
		    instmods "$module"
		fi
	    done
	fi
    done
}

depends(){
    echo crypt
}

cmdline(){
    :
}
