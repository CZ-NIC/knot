#!/usr/bin/env bash

# This package is needed on Debian derived ditributions: libglib2.0-bin

cb() {
	case "$1" in
	zone_ksk_submission)
		echo "Ready KSK for zone=${2} keytag=${3} keyid=${4}"
		;;
	zone_updated)
		echo "Updated zone=${2} to serial=${3}"
		;;
	zone_dnssec_invalid)
		echo "Invalid DNSSEC for zone=${2}"
		;;
	started)
		echo "Server started"
		;;
	stopped)
		echo "Server stopped"
		;;
	esac
}

awk="awk"

# If awk is mawk, turn off input buffering.
if ($awk -Wv 2>&1 | grep -q "mawk") && \
   ($awk -W interactive > /dev/null 2>&1); then
	awk=${awk}" -W interactive"
fi

gdbus monitor --system --dest cz.nic.knotd --object-path /cz/nic/knotd \
	| $awk '/^\/cz\/nic\/knotd/ {
		gsub("cz.nic.knotd.events.", "", $2);
		tmp="";
		for(i=3;i<=NF;++i) {
			if( $i ~ /[\),]$/ ) tmp=tmp$i;
		}
		gsub(/(^\()|(\)$)|\47/, "", tmp);
		items=split(tmp, args, ",");
		printf "%s ", $2;
		for(i=1;i<=items;i++) printf "%s ", args[i];
		print "";
		fflush(stdout); }' \
	| while read line; do \
		cb ${line[@]}; \
	done
