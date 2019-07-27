#!/bin/sh
#
# This file should be present in the root file system directory
# /usr/lib/dracut/modules.d/90mandos.  When dracut creates the
# initramfs image, dracut will run the "module-setup.sh" file in the
# same directory, which (when *not* using the "systemd" dracut module)
# will copy this file ("cmdline-mandos.sh") into the initramfs as
# "/lib/dracut/hooks/cmdline/20-cmdline-mandos.sh".
# 
# Despite the above #!/bin/sh line and the executable flag, this file
# is not executed; this file is sourced by the /init script in the
# initramfs image created by dracut.

if getargbool 1 mandos && [ -e /lib/dracut-crypt-lib.sh ]; then
    cat >> /lib/dracut-crypt-lib.sh <<- "EOF"
	ask_for_password(){
	    local cmd; local prompt; local tries=3
	    local ply_cmd; local ply_prompt; local ply_tries=3
	    local tty_cmd; local tty_prompt; local tty_tries=3
	    local ret
	
	    while [ $# -gt 0 ]; do
		case "$1" in
		    --cmd) ply_cmd="$2"; tty_cmd="$2"; shift;;
		    --ply-cmd) ply_cmd="$2"; shift;;
		    --tty-cmd) tty_cmd="$2"; shift;;
		    --prompt) ply_prompt="$2"; tty_prompt="$2"; shift;;
		    --ply-prompt) ply_prompt="$2"; shift;;
		    --tty-prompt) tty_prompt="$2"; shift;;
		    --tries) ply_tries="$2"; tty_tries="$2"; shift;;
		    --ply-tries) ply_tries="$2"; shift;;
		    --tty-tries) tty_tries="$2"; shift;;
		    --tty-echo-off) tty_echo_off=yes;;
		    -*) :;;
		esac
		shift
	    done
	    if [ -z "$ply_cmd" ]; then
		ply_cmd="$tty_cmd"
	    fi
	    # Extract device and luksname from $ply_cmd
	    set -- $ply_cmd
	    shift
	    for arg in "$@"; do
		case "$arg" in
		    -*) :;;
		    *)
			if [ -z "$device" ]; then
			    device="$arg"
			else
			    luksname="$arg"
			    break
			fi
			;;
		esac
	    done
	    { flock -s 9;
	      if [ -z "$ply_prompt" ]; then
		  if [ -z "$tty_prompt" ]; then
		      CRYPTTAB_SOURCE="$device" cryptsource="$device" CRYPTTAB_NAME="$luksname" crypttarget="$luksname" /lib/mandos/plugin-runner --config-file=/etc/mandos/plugin-runner.conf | $ply_cmd
		  else
		      CRYPTTAB_SOURCE="$device" cryptsource="$device" CRYPTTAB_NAME="$luksname" crypttarget="$luksname" /lib/mandos/plugin-runner --options-for=password-prompt:--prompt="${tty_prompt}" --config-file=/etc/mandos/plugin-runner.conf | $ply_cmd
		  fi
	      else
		  if [ -z "$tty_prompt" ]; then
		      CRYPTTAB_SOURCE="$device" cryptsource="$device" CRYPTTAB_NAME="$luksname" crypttarget="$luksname" /lib/mandos/plugin-runner --options-for=plymouth:--prompt="${ply_prompt}" --config-file=/etc/mandos/plugin-runner.conf | $ply_cmd
		  else
		      CRYPTTAB_SOURCE="$device" cryptsource="$device" CRYPTTAB_NAME="$luksname" crypttarget="$luksname" /lib/mandos/plugin-runner --options-for=password-prompt:--prompt="${tty_prompt}" --options-for=plymouth:--prompt="${ply_prompt}" --config-file=/etc/mandos/plugin-runner.conf | $ply_cmd
		  fi
	      fi
	    } 9>/.console_lock
	}
	EOF
fi
