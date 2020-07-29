#!/bin/sh
#
# Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
#
# Knot DNS utility script
#
# This script collects selected system and Knot DNS configuration
# data and prints them out to the standard output. If the output
# is sent through a secure channel to the Knot DNS development team,
# the data can serve as a basis for the Knot DNS performace troubleshooting.
#
# Usage:  ./kinquire.sh <Knot DNS configuration file>
#         ./kinquire.sh <Knot DNS configuration DB directory>
#         ./kinquire.sh <control socket of a running knotd daemon>
#
# Note: the script is currently mostly GNU/Linux specific
#


KU_SCRIPT_VERSION="Knot DNS utility script, version 0.1"

PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin

WHICH=${WHICH:-$(which which || echo /usr/bin/which)}
if [ ! -x "$WHICH" ]; then
	echo "Command \"which\" not found." >&2
	exit 98
fi

KNOTD=${KNOTD:-$(which knotd)}
KNOTC=${KNOTC:-$(which knotc || echo \#knotc)}
KNOTPID=${KNOTPID:-$(pgrep knotd |head -n 1)}
KNOTCONF=

PATH=/bin:/usr/bin:/sbin:/usr/sbin

AWK=${AWK:-$(which awk || echo \#awk)}
CAT=${CAT:-$(which cat || echo \#cat)}
DATE=${DATE:-$(which date || echo \#date)}
ETHTOOL=${ETHTOOL:-$(which ethtool || echo \#ethtool)}
FILE=${FILE:-$(which file || echo \#file)}
FREE=${FREE:-$(which free || echo \#free)}
GREP=${GREP:-$(which grep || echo \#grep)}
HOSTNAME=${HOSTNAME:-$(which hostname || echo \#hostname)}
HOSTNAMECTL=${HOSTNAMECTL:-$(which hostnamectl || \#hostnamectl)}
ID=${ID:-$(which id || echo \#id)}
IFCONFIG=${IFCONFIG:-$(which ifconfig || echo \#ifconfig)}
IP=${IP:-$(which ip || echo \#ip)}
LDD=${LDD:-$(which ldd || echo \#ldd)}
LS=${LS:-$(which ls || echo \#ls)}
LSCPU=${LSCPU:-$(which lscpu || echo \#lscpu)}
PRLIMIT=${PRLIMIT:-$(which prlimit || echo \#prlimit)}
SED=${SED:-$(which sed || echo \#sed)}
STRINGS=${STRINGS:-$(which strings || echo \#strings)}
SYSCTL=${SYSCTL:-$(which sysctl || echo \#sysctl)}
UNAME=${UNAME:-$(which uname || echo \#uname)}

CPUINFO=/proc/cpuinfo
MEMINFO=/proc/meminfo
IRQINFO=/proc/interrupts
SIRQINFO=/proc/softirqs

LSB_VERSION=/etc/lsb-release
DISTRO_VERSION=/etc/os-release
DEBIAN_VERSION=/etc/debian_version
GENTOO_VERSION=/etc/gentoo-release
ALPINE_VERSION=/etc/alpine-release
CENTOS_VERSION=/etc/centos-release
REDHAT_VERSION=/etc/redhat-release
RH_SYSTEM_VERSION=/etc/system-release

ku_separator() echo -----------------------------------------------------------------------------------------
ku_hd_separator() echo ========================================================

ku_log_failure() {
	ku_separator
	printf "FAILURE:   %s\n" "$*"
	ku_separator
	echo
}

ku_execute() {
	ku_separator
	printf "COMMAND:   %s\n" "$*"
	ku_separator
	eval "$@" 2>&1
}

ku_get_params() {
	if [ -f "$1" ]; then
		KNOTCONF="$KNOTCONF -c $1"
	elif [ -d "$1" ]; then
		KNOTCONF="$KNOTCONF -C $1"
	elif [ -S "$1" ]; then
		KNOTCONF="$KNOTCONF -s $1"
	else
		echo "$KU_SCRIPT_VERSION"					>&2
		echo "Usage:  $0 <Knot DNS configuration file>"			>&2
		echo "        $0 <Knot DNS configuration DB directory>"		>&2
		echo "        $0 <control socket of a running knotd daemon>"	>&2
		exit 99
	fi
}

ku_net_devs_info() {
	if [ -x "$IFCONFIG" ]; then
		ku_execute $IFCONFIG -a
		DEVICES=$($IFCONFIG -a |$SED '/^ /d;/^$/d;s/: .*$//;/^lo$/d')
	elif [ -x "$IP" ]; then
		ku_execute $IP -s addr
		DEVICES=$($IP link show |$SED '/^ /d;s/^[^:]*: //;s/: .*$//;/^lo$/d')
	else
		ku_log_failure "No ifconfig/ip found."
		return
	fi

	if [ ! -x "$ETHTOOL" ]; then
		ku_log_failure "No ethtool utility found."
		return
	fi

	for DEV in $DEVICES; do
		ku_execute $ETHTOOL $DEV
		ku_execute $ETHTOOL -i $DEV
		ku_execute $ETHTOOL -l $DEV
		ku_execute $ETHTOOL -a $DEV
		ku_execute $ETHTOOL -g $DEV
		ku_execute $ETHTOOL -k $DEV
		ku_execute $ETHTOOL -c $DEV
		ku_execute $ETHTOOL -n $DEV rx-flow-hash udp4
		ku_execute $ETHTOOL -n $DEV rx-flow-hash udp6
	done
}

ku_knotd_binary_info() {
	if [ ! -f "$KNOTD" ]; then
		ku_log_failure "No knotd binary found."
		return
	fi

	ku_execute $LS -ld --full-time "$KNOTD"
	ku_execute $FILE "$KNOTD"
	ku_execute "$STRINGS $KNOTD |$GREP -e ^GCC -e ^clang\ version"
	ku_execute "$STRINGS $KNOTD |$AWK -c /^\ \ Knot\ DNS\ /,/^\[^\ \]/ |$SED \\\$d"

	[ ! -x "$LDD" ] && return

	ku_execute $LDD -v "$KNOTD"
	ku_execute $LS -ld  --full-time $($LDD "$KNOTD" |$SED -E '/linux-vdso.so.1/d;s@^.*=> @@;s@^[ \t]*@@;s@ \(0x.*$@@')
	ku_execute $LS -ldL --full-time $($LDD "$KNOTD" |$SED -E '/linux-vdso.so.1/d;s@^.*=> @@;s@^[ \t]*@@;s@ \(0x.*$@@')
}

ku_print_header() {
	ku_hd_separator
	echo "  $KU_SCRIPT_VERSION"
	echo
	echo "  hostname:\t$($HOSTNAME)"
	echo "  date:\t\t$($DATE)"
	echo "  run as root:\t$([ $($ID -u) -eq 0 ] && echo yes || echo no)"
	ku_hd_separator
	echo
}

ku_print_data() {

    # General OS info
	ku_execute $UNAME -a
	[ -x "$HOSTNAMECTL" ] && ku_execute $HOSTNAMECTL
	[ -r "$LSB_VERSION" ] && ku_execute $CAT $LSB_VERSION
	[ -r "$DISTRO_VERSION" ] && ku_execute $CAT $DISTRO_VERSION
	[ -r "$DEBIAN_VERSION" ] && ku_execute $CAT $DEBIAN_VERSION
	[ -r "$GENTOO_VERSION" ] && ku_execute $CAT $GENTOO_VERSION
	[ -r "$ALPINE_VERSION" ] && ku_execute $CAT $ALPINE_VERSION
	[ -r "$CENTOS_VERSION" ] && ku_execute $CAT $CENTOS_VERSION
	[ -r "$REDHAT_VERSION" ] && ku_execute $CAT $REDHAT_VERSION
	[ -r "$RH_SYSTEM_VERSION" ] && ku_execute $CAT $RH_SYSTEM_VERSION

    # Some hardware details
	if [ -x "$LSCPU" ]; then
		ku_execute $LSCPU
	else
		ku_execute $CAT $CPUINFO
	fi
	ku_execute $FREE -h
	ku_execute $CAT $MEMINFO
	ku_execute $CAT $IRQINFO
	ku_execute $CAT $SIRQINFO

    # Some OS details
	# Not yet.
	# ku_execute $SYSCTL -a
	ku_net_devs_info

    # Some knotd binary details
	ku_knotd_binary_info

    # Some knotd configuration details
	if [ ${KNOTPID}X != X ]; then
	 	ku_execute $PRLIMIT -p $KNOTPID
		ku_execute $KNOTC $KNOTCONF conf-read server.listen
		ku_execute $KNOTC $KNOTCONF conf-read server.listen-xdp
		ku_execute $KNOTC $KNOTCONF conf-read server.udp-workers
		ku_execute $KNOTC $KNOTCONF conf-read server.tcp-workers
		ku_execute $KNOTC $KNOTCONF conf-read server.background-workers
		ku_execute $KNOTC $KNOTCONF conf-read server.tcp-max-clients
		ku_execute $KNOTC $KNOTCONF conf-read database
		ku_execute $KNOTC $KNOTCONF conf-read stats server

		ku_execute $KNOTC $KNOTCONF status version
		ku_execute $KNOTC $KNOTCONF status workers
		ku_execute $KNOTC $KNOTCONF status configure
	else
		ku_log_failure "Running knotd process not found."
	fi

	ku_separator
}

############
#  "main()"

ku_get_params "$@"
ku_print_header 2>&1
ku_print_data 2>&1


