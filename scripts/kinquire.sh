#!/bin/sh
#
# Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
#
# Knot DNS utility script
#
# This script collects selected system and Knot DNS configuration
# data and prints them out to the standard output. If the output
# is sent through a secure channel to the Knot DNS development team,
# the data can serve as a basis for the Knot DNS performance troubleshooting.
#
# Usage:  ./kinquire.sh <Knot DNS configuration file>
#         ./kinquire.sh <Knot DNS configuration DB directory>
#         ./kinquire.sh <control socket of a running knotd daemon>
#
# Note: the script is currently mostly GNU/Linux specific
#

KU_SCRIPT_VERSION="Knot DNS utility script, version 0.3a"

PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin

ku_which() {
	local RET=$(command -v "$@")
	if [ -f "$RET" -a -x "$RET" ]; then
		echo "$RET"
		return 0
	else
		return 1
	fi
}

KNOTD=${KNOTD:-$(ku_which knotd)}
KNOTC=${KNOTC:-$(ku_which knotc || echo \#knotc)}
# KNOTPID=${KNOTPID:-$(ps -A |awk '$NF~"knotd" {print $1; exit}')}
KNOTPID=${KNOTPID:-$(pgrep knotd |head -n 1)}
# General knotc options can be set in KNOTCONF environment variable.

PATH=/bin:/usr/bin:/sbin:/usr/sbin

CAT=$(ku_which cat || echo \#cat)
DATE=$(ku_which date || echo \#date)
ETHTOOL=$(ku_which ethtool || echo \#ethtool)
FILE=$(ku_which file || echo \#file)
FREE=$(ku_which free || echo \#free)
GREP=$(ku_which grep || echo \#grep)
HOSTNAME=$(ku_which hostname || echo \#hostname)
HOSTNAMECTL=$(ku_which hostnamectl || echo \#hostnamectl)
ID=$(ku_which id || echo \#id)
IFCONFIG=$(ku_which ifconfig || echo \#ifconfig)
IP=$(ku_which ip || echo \#ip)
LDD=$(ku_which ldd || echo \#ldd)
LS=$(ku_which ls || echo \#ls)
LSCPU=$(ku_which lscpu || echo \#lscpu)
LSPCI=$(ku_which lspci || echo \#lspci)
PRLIMIT=$(ku_which prlimit || echo \#prlimit)
PS=$(ku_which ps || echo \#ps)
SED=$(ku_which sed || echo \#sed)
STRINGS=$(ku_which strings || echo \#strings)
SYSCTL=$(ku_which sysctl || echo \#sysctl)
UNAME=$(ku_which uname || echo \#uname)

CPUINFO=/proc/cpuinfo
MEMINFO=/proc/meminfo
IRQINFO=/proc/interrupts
SIRQINFO=/proc/softirqs
BONDINFO=/proc/net/bonding

LSB_VERSION=/etc/lsb-release
DISTRO_VERSION=/etc/os-release
DEBIAN_VERSION=/etc/debian_version
GENTOO_VERSION=/etc/gentoo-release
ALPINE_VERSION=/etc/alpine-release
CENTOS_VERSION=/etc/centos-release
REDHAT_VERSION=/etc/redhat-release
RH_SYSTEM_VERSION=/etc/system-release

ku_separator() {
	echo -----------------------------------------------------------------------------------------
}

ku_hd_separator() {
	echo ========================================================
}

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

ku_print_header() {
	ku_hd_separator
	echo "  $KU_SCRIPT_VERSION"
	echo
	echo "  hostname:     $($HOSTNAME)"
	echo "  date:         $($DATE)"
	echo "  run as root:  $([ $($ID -u) -eq 0 ] && echo yes || echo no)"
	ku_hd_separator
	echo
}

ku_net_devs_info() {
	if [ -x "$IFCONFIG" ]; then
		ku_execute $IFCONFIG -a
		DEVICES=$($IFCONFIG -a |$SED -E '/^ /d;/^$/d;s/:? .*$//;/^lo(:.*)?$/d')
	elif [ -x "$IP" ]; then
		ku_execute $IP -s addr
		DEVICES=$($IP link show |$SED -E '/^ /d;s/^[^:]*: //;s/(: |@).*$//;/^lo(:.*)?$/d')
	else
		ku_log_failure "No ifconfig/ip found."
		return
	fi

	ku_execute $CAT $IRQINFO
	ku_execute $CAT $SIRQINFO

	if [ ! -x "$ETHTOOL" ]; then
		ku_log_failure "No ethtool utility found."
		return
	fi

	local DEV_START="############################"

	for DEV in $DEVICES; do
		ku_execute echo "$DEV_START  " $DEV "  $DEV_START"
		ku_execute $ETHTOOL $DEV
		ku_execute $ETHTOOL -i $DEV
		ku_execute $ETHTOOL -l $DEV
		ku_execute $ETHTOOL -a $DEV
		ku_execute $ETHTOOL -g $DEV
		ku_execute $ETHTOOL -k $DEV
		ku_execute $ETHTOOL -c $DEV
		ku_execute $ETHTOOL -n $DEV rx-flow-hash udp4
		ku_execute $ETHTOOL -n $DEV rx-flow-hash udp6
		ku_execute $ETHTOOL -S $DEV
		[[ $DEV = bond* ]] && ku_execute $CAT $BONDINFO/$DEV
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

	[ ! -x "$LDD" ] && return

	ku_execute $LDD -v "$KNOTD"
	ku_execute $LS -ld  --full-time $($LDD "$KNOTD" |$SED -E '/linux-vdso.so.1/d;s@^.*=> @@;s@^[ \t]*@@;s@ \(0x.*$@@')
	ku_execute $LS -ldL --full-time $($LDD "$KNOTD" |$SED -E '/linux-vdso.so.1/d;s@^.*=> @@;s@^[ \t]*@@;s@ \(0x.*$@@')
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

    # Some OS details
	# Not yet.
	# ku_execute $SYSCTL -a

    # Some knotd binary details
	ku_knotd_binary_info

    # Some knotd configuration details
	if [ ${KNOTPID}X != X -a -x "$KNOTC" ]; then
		ku_execute $PS uww -p ${KNOTPID}
		ku_execute $PS vww -p ${KNOTPID}
		[ -x "${PRLIMIT}" ] && ku_execute $PRLIMIT -p $KNOTPID
		ku_execute $KNOTC $KNOTCONF conf-read server
		ku_execute $KNOTC $KNOTCONF conf-read template
		ku_execute $KNOTC $KNOTCONF conf-read database
		ku_execute $KNOTC $KNOTCONF stats server

		ku_execute $KNOTC $KNOTCONF status version
		ku_execute $KNOTC $KNOTCONF status workers
		ku_execute $KNOTC $KNOTCONF status configure
	else
		ku_log_failure "Running knotd process not found."
	fi

    # Network adapters details
	[ -x $LSPCI ] && ku_execute "$LSPCI |$GREP -i Ethernet"
	ku_net_devs_info

	ku_separator
}

############
#  "main()"

ku_get_params "$@"
ku_print_header 2>&1
ku_print_data 2>&1

